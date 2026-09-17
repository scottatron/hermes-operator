package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	hermesv1 "github.com/paperclipinc/hermes-operator/api/v1"
	"github.com/paperclipinc/hermes-operator/internal/resources"
)

var _ = Describe("HermesInstance reconciler: sidecar securityContext", func() {
	const (
		instName = "sidecar-sc-it"
		ns       = "default"
	)

	AfterEach(func() {
		ctx := context.Background()
		_ = k8sClient.Delete(ctx, &hermesv1.HermesInstance{ObjectMeta: metav1.ObjectMeta{Name: instName, Namespace: ns}})
		_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: instName, Namespace: ns}})
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: instName + "-config", Namespace: ns}})
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: instName + "-workspace", Namespace: ns}})
	})

	It("carries spec.sidecars[].securityContext into the persisted StatefulSet", func() {
		ctx := context.Background()
		inst := &hermesv1.HermesInstance{
			ObjectMeta: metav1.ObjectMeta{Name: instName, Namespace: ns},
			Spec: hermesv1.HermesInstanceSpec{
				Image: hermesv1.ImageSpec{Repository: "ghcr.io/paperclipinc/hermes-agent", Tag: "v1.0.0"},
				Sidecars: []corev1.Container{{
					Name:  "workspace",
					Image: "example.com/workspace:1",
					SecurityContext: &corev1.SecurityContext{
						Privileged:               resources.Ptr(false),
						AllowPrivilegeEscalation: resources.Ptr(true),
						Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}},
					},
				}},
			},
		}
		Expect(k8sClient.Create(ctx, inst)).To(Succeed())

		var stored hermesv1.HermesInstance
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: instName, Namespace: ns}, &stored)).To(Succeed())
		Expect(stored.Spec.Sidecars).To(HaveLen(1))
		Expect(stored.Spec.Sidecars[0].SecurityContext).NotTo(BeNil(), "CR must persist the sidecar securityContext")

		Eventually(func(g Gomega) {
			var sts appsv1.StatefulSet
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: instName, Namespace: ns}, &sts)).To(Succeed())
			var found *corev1.Container
			for i := range sts.Spec.Template.Spec.Containers {
				if sts.Spec.Template.Spec.Containers[i].Name == "workspace" {
					found = &sts.Spec.Template.Spec.Containers[i]
				}
			}
			g.Expect(found).NotTo(BeNil())
			g.Expect(found.SecurityContext).NotTo(BeNil(), "sidecar securityContext must reach the StatefulSet")
			g.Expect(found.SecurityContext.Capabilities).NotTo(BeNil())
			g.Expect(found.SecurityContext.Capabilities.Add).To(ConsistOf(corev1.Capability("SYS_ADMIN")))
		}, "30s", "250ms").Should(Succeed())
	})
})
