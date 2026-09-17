/*
Copyright 2026 Paperclip.inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hermesv1 "github.com/paperclipinc/hermes-operator/api/v1"
)

// forbiddenReader is what an operator sees when its ClusterRole predates the
// endpointslices rule: every read is Forbidden.
type forbiddenReader struct{}

func (forbiddenReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return apierrors.NewForbidden(schema.GroupResource{Group: "discovery.k8s.io", Resource: "endpointslices"}, "", nil)
}

func (forbiddenReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return apierrors.NewForbidden(schema.GroupResource{Group: "discovery.k8s.io", Resource: "endpointslices"}, "", nil)
}

func apiEgressScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	sch := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(sch))
	require.NoError(t, hermesv1.AddToScheme(sch))
	return sch
}

func selfConfiguringInstance() *hermesv1.HermesInstance {
	return &hermesv1.HermesInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "sc", Namespace: "agents", UID: "uid-sc"},
		Spec: hermesv1.HermesInstanceSpec{
			Image:         hermesv1.ImageSpec{Repository: "r", Tag: "t"},
			SelfConfigure: hermesv1.SelfConfigureSpec{Enabled: Ptr(true)},
		},
	}
}

func ipBlockRules(np *networkingv1.NetworkPolicy) []networkingv1.NetworkPolicyEgressRule {
	var out []networkingv1.NetworkPolicyEgressRule
	for _, e := range np.Spec.Egress {
		if len(e.To) > 0 && e.To[0].IPBlock != nil {
			out = append(out, e)
		}
	}
	return out
}

// The scenario seen on a k3s cluster running a new operator image under the
// old chart: no RBAC for endpointslices. The reconcile must finish, still
// write the NetworkPolicy (without the API server rule), and warn.
func TestReconcileNetworkPolicy_ForbiddenEndpointSlicesWarnsAndContinues(t *testing.T) {
	sch := apiEgressScheme(t)
	inst := selfConfiguringInstance()
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(inst).Build()
	rec := record.NewFakeRecorder(10)
	r := &HermesInstanceReconciler{Client: cl, Scheme: sch, Recorder: rec, APIReader: forbiddenReader{}}

	require.NoError(t, r.reconcileNetworkPolicy(context.Background(), inst))

	np := &networkingv1.NetworkPolicy{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: "sc", Namespace: "agents"}, np))
	assert.Empty(t, ipBlockRules(np), "no API server rule when endpoints are unreadable")

	select {
	case ev := <-rec.Events:
		assert.Contains(t, ev, "Warning")
		assert.Contains(t, ev, EventReasonAPIServerEgressUnresolved)
		assert.Contains(t, ev, "additionalEgress")
	default:
		t.Fatal("expected a Warning event")
	}
}

func TestReconcileNetworkPolicy_AddsAPIServerRuleFromEndpointSlice(t *testing.T) {
	sch := apiEgressScheme(t)
	inst := selfConfiguringInstance()
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubernetes", Namespace: "default",
			Labels: map[string]string{discoveryv1.LabelServiceName: "kubernetes"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.70"}, Conditions: discoveryv1.EndpointConditions{Ready: Ptr(true)}}},
		Ports:       []discoveryv1.EndpointPort{{Name: Ptr("https"), Port: Ptr(int32(6443))}},
	}
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(inst, slice).Build()
	rec := record.NewFakeRecorder(10)
	r := &HermesInstanceReconciler{Client: cl, Scheme: sch, Recorder: rec, APIReader: cl}

	require.NoError(t, r.reconcileNetworkPolicy(context.Background(), inst))

	np := &networkingv1.NetworkPolicy{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: "sc", Namespace: "agents"}, np))
	rules := ipBlockRules(np)
	require.Len(t, rules, 1)
	assert.Equal(t, "10.0.1.70/32", rules[0].To[0].IPBlock.CIDR)
	assert.Equal(t, 6443, rules[0].Ports[0].Port.IntValue())
	assert.Empty(t, rec.Events, "no warning when the lookup succeeds")
}

func TestReconcileNetworkPolicy_NoLookupWhenSelfConfigureOff(t *testing.T) {
	sch := apiEgressScheme(t)
	inst := selfConfiguringInstance()
	inst.Spec.SelfConfigure.Enabled = Ptr(false)
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(inst).Build()
	rec := record.NewFakeRecorder(10)
	r := &HermesInstanceReconciler{Client: cl, Scheme: sch, Recorder: rec, APIReader: forbiddenReader{}}

	require.NoError(t, r.reconcileNetworkPolicy(context.Background(), inst))
	assert.Empty(t, rec.Events, "selfConfigure off: endpoints are never read, so nothing to warn about")
}
