package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	hermesv1 "github.com/paperclipinc/hermes-operator/api/v1"
)

func TestBuildNetworkPolicy_DenyAllBase(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "agents"}}
	np := BuildNetworkPolicy(inst)
	assert.Equal(t, "demo", np.Name)
	assert.Equal(t, "agents", np.Namespace)
	assert.Contains(t, np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
	assert.Contains(t, np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
	assert.Equal(t, "demo", np.Spec.PodSelector.MatchLabels["app.kubernetes.io/instance"])
	assert.Equal(t, "hermes-agent", np.Spec.PodSelector.MatchLabels["app.kubernetes.io/name"])
}

func TestBuildNetworkPolicy_SameNamespaceIngress(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "agents"}}
	np := BuildNetworkPolicy(inst)
	require := false
	for _, rule := range np.Spec.Ingress {
		for _, from := range rule.From {
			if from.NamespaceSelector != nil &&
				from.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "agents" {
				require = true
			}
		}
	}
	assert.True(t, require, "expected ingress rule from same namespace")
}

func TestBuildNetworkPolicy_DefaultDNSEgress(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{ObjectMeta: metav1.ObjectMeta{Name: "demo"}}
	np := BuildNetworkPolicy(inst)
	foundUDP53, foundTCP443 := false, false
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.Ports {
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP && p.Port != nil && p.Port.IntValue() == 53 {
				foundUDP53 = true
			}
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolTCP && p.Port != nil && p.Port.IntValue() == 443 {
				foundTCP443 = true
			}
		}
	}
	assert.True(t, foundUDP53, "default-allow DNS UDP/53")
	assert.True(t, foundTCP443, "default-allow HTTPS TCP/443")
}

func TestBuildNetworkPolicy_AllowDNSDisabled(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: hermesv1.HermesInstanceSpec{
			Security: hermesv1.SecuritySpec{
				NetworkPolicy: hermesv1.NetworkPolicySpec{AllowDNS: Ptr(false)},
			},
		},
	}
	np := BuildNetworkPolicy(inst)
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.Ports {
			if p.Port != nil && p.Port.IntValue() == 53 {
				t.Fatalf("expected no DNS rule when AllowDNS=false")
			}
		}
	}
}

func TestBuildNetworkPolicy_AllowedIngressNamespacesAndCIDRs(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "agents"},
		Spec: hermesv1.HermesInstanceSpec{
			Security: hermesv1.SecuritySpec{
				NetworkPolicy: hermesv1.NetworkPolicySpec{
					AllowedIngressNamespaces: []string{"prometheus"},
					AllowedIngressCIDRs:      []string{"10.0.0.0/8"},
				},
			},
		},
	}
	np := BuildNetworkPolicy(inst)
	var sawNS, sawCIDR bool
	for _, rule := range np.Spec.Ingress {
		for _, from := range rule.From {
			if from.NamespaceSelector != nil &&
				from.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "prometheus" {
				sawNS = true
			}
			if from.IPBlock != nil && from.IPBlock.CIDR == "10.0.0.0/8" {
				sawCIDR = true
			}
		}
	}
	assert.True(t, sawNS, "expected ingress rule for namespace prometheus")
	assert.True(t, sawCIDR, "expected ingress rule for CIDR 10.0.0.0/8")
}

func TestBuildNetworkPolicy_AdditionalEgress(t *testing.T) {
	t.Parallel()
	extra := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "203.0.113.0/24"}}},
	}
	inst := &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: hermesv1.HermesInstanceSpec{
			Security: hermesv1.SecuritySpec{
				NetworkPolicy: hermesv1.NetworkPolicySpec{AdditionalEgress: []networkingv1.NetworkPolicyEgressRule{extra}},
			},
		},
	}
	np := BuildNetworkPolicy(inst)
	var sawExtra bool
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "203.0.113.0/24" {
				sawExtra = true
			}
		}
	}
	assert.True(t, sawExtra)
}

func TestNetworkPolicyName(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{ObjectMeta: metav1.ObjectMeta{Name: "demo"}}
	assert.Equal(t, "demo", NetworkPolicyName(inst))
	_ = metav1.ObjectMeta{}
}

func TestExtraEgressRules_TelegramAndDiscord(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "agents"},
		Spec: hermesv1.HermesInstanceSpec{
			Gateways: hermesv1.GatewaysSpec{
				Telegram: hermesv1.TelegramGatewaySpec{Enabled: Ptr(true)},
				Discord:  hermesv1.DiscordGatewaySpec{Enabled: Ptr(true)},
			},
		},
	}
	rules := ExtraEgressRules(inst)
	hasTCP443 := false
	for _, r := range rules {
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolTCP && p.Port != nil && p.Port.IntVal == 443 {
				hasTCP443 = true
			}
		}
	}
	assert.True(t, hasTCP443, "at least one rule opens TCP/443 for gateway endpoints")
}

func TestExtraEgressRules_HonchoSibling(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "agents"},
		Spec: hermesv1.HermesInstanceSpec{
			ProfileStore: hermesv1.ProfileStoreSpec{
				Honcho: hermesv1.HonchoSpec{Enabled: Ptr(true)},
			},
		},
	}
	rules := ExtraEgressRules(inst)
	foundHoncho := false
	for _, r := range rules {
		for _, peer := range r.To {
			if peer.PodSelector != nil && peer.PodSelector.MatchLabels["app.kubernetes.io/instance"] == "demo-honcho" {
				foundHoncho = true
			}
		}
	}
	assert.True(t, foundHoncho, "egress to honcho sibling pod selector present")
}

func TestBuildHonchoNetworkPolicy_IngressOnlyFromHermes(t *testing.T) {
	t.Parallel()
	inst := &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "agents"},
		Spec: hermesv1.HermesInstanceSpec{
			ProfileStore: hermesv1.ProfileStoreSpec{
				Honcho: hermesv1.HonchoSpec{Enabled: Ptr(true)},
			},
		},
	}
	np := BuildHonchoNetworkPolicy(inst)
	assert.Equal(t, "demo-honcho", np.Name)
	assert.Equal(t, "honcho", np.Spec.PodSelector.MatchLabels["app.kubernetes.io/name"])

	require := np.Spec.Ingress
	assert.Len(t, require, 1)
	from := require[0].From
	assert.Len(t, from, 1)
	assert.Equal(t, "hermes-agent", from[0].PodSelector.MatchLabels["app.kubernetes.io/name"])
	assert.Equal(t, "demo", from[0].PodSelector.MatchLabels["app.kubernetes.io/instance"])

	assert.Empty(t, np.Spec.Egress)
	assert.Contains(t, np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
}

func TestBuildNetworkPolicy_TailscaleEgress(t *testing.T) {
	t.Parallel()
	np := BuildNetworkPolicy(tailscaleInstance())

	var sawUDP3478, sawUDP41641 bool
	for _, e := range np.Spec.Egress {
		for _, p := range e.Ports {
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP && p.Port != nil {
				switch p.Port.IntValue() {
				case 3478:
					sawUDP3478 = true
				case 41641:
					sawUDP41641 = true
				}
			}
		}
	}
	assert.True(t, sawUDP3478, "expected STUN UDP/3478 egress")
	assert.True(t, sawUDP41641, "expected Tailscale UDP/41641 egress")

	// Disabled: no UDP tailscale rules.
	npOff := BuildNetworkPolicy(minimalInstance())
	for _, e := range npOff.Spec.Egress {
		for _, p := range e.Ports {
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP && p.Port != nil {
				assert.NotEqual(t, 3478, p.Port.IntValue())
				assert.NotEqual(t, 41641, p.Port.IntValue())
			}
		}
	}
}

func apiServerEgressRules(np *networkingv1.NetworkPolicy) []networkingv1.NetworkPolicyEgressRule {
	var out []networkingv1.NetworkPolicyEgressRule
	for _, e := range np.Spec.Egress {
		if len(e.To) > 0 && e.To[0].IPBlock != nil && len(e.Ports) == 1 {
			out = append(out, e)
		}
	}
	return out
}

func TestBuildNetworkPolicy_APIServerEgressWhenSelfConfigure(t *testing.T) {
	t.Parallel()
	inst := minimalInstance()
	inst.Spec.SelfConfigure.Enabled = Ptr(true)
	eps := []APIServerEndpoint{
		{IP: "10.0.1.71", Port: 6443},
		{IP: "10.0.1.70", Port: 6443},
		{IP: "10.0.1.70", Port: 6443}, // duplicate collapses
		{IP: "fd00::1", Port: 443},
		{IP: "not-an-ip", Port: 6443}, // skipped
		{IP: "10.0.1.72", Port: 0},    // skipped
	}
	np := BuildNetworkPolicyWithAPIServer(inst, eps)
	rules := apiServerEgressRules(np)
	if assert.Len(t, rules, 2, "one rule per distinct port, sorted") {
		assert.Equal(t, 443, rules[0].Ports[0].Port.IntValue())
		assert.Equal(t, corev1.ProtocolTCP, *rules[0].Ports[0].Protocol)
		assert.Equal(t, "fd00::1/128", rules[0].To[0].IPBlock.CIDR)

		assert.Equal(t, 6443, rules[1].Ports[0].Port.IntValue())
		assert.Len(t, rules[1].To, 2)
		assert.Equal(t, "10.0.1.70/32", rules[1].To[0].IPBlock.CIDR)
		assert.Equal(t, "10.0.1.71/32", rules[1].To[1].IPBlock.CIDR)
	}
	// Deterministic across calls regardless of input order.
	again := BuildNetworkPolicyWithAPIServer(inst, []APIServerEndpoint{eps[3], eps[0], eps[1]})
	assert.Equal(t, np.Spec.Egress, again.Spec.Egress)
}

func TestBuildNetworkPolicy_NoAPIServerEgressWithoutSelfConfigure(t *testing.T) {
	t.Parallel()
	inst := minimalInstance()
	eps := []APIServerEndpoint{{IP: "10.0.1.70", Port: 6443}}
	assert.Empty(t, apiServerEgressRules(BuildNetworkPolicyWithAPIServer(inst, eps)),
		"selfConfigure off: the agent has no business talking to the API server")

	inst.Spec.SelfConfigure.Enabled = Ptr(true)
	assert.Empty(t, apiServerEgressRules(BuildNetworkPolicyWithAPIServer(inst, nil)),
		"no endpoints resolved: emit nothing rather than a bogus rule")
	assert.Equal(t, BuildNetworkPolicy(inst).Spec, BuildNetworkPolicyWithAPIServer(inst, nil).Spec)
}
