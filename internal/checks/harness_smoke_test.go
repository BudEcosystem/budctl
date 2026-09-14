package checks

import (
	"testing"

	"github.com/BudEcosystem/budctl/internal/adapters"
)

// These prove the harness can drive a check to BOTH outcomes. A harness that
// can only produce passes would make every test below meaningless.

func TestImageFsBlocksWhenShort(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(200), ImageFsAvailable: gib(20)})
	assertStatus(t, run(t, f, "nodes.imagefs"), "BLOCK")
}

func TestImageFsPassesWithHeadroom(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(400), ImageFsAvailable: gib(120)})
	assertStatus(t, run(t, f, "nodes.imagefs"), "PASS")
}

// The kubelet proxy can be denied by RBAC. That must read as "not verified",
// never as a pass — the whole point of D5.
func TestImageFsSkipsWhenStatsUnreadable(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"))
	assertSkipHasReason(t, run(t, f, "nodes.imagefs"))
}

func TestTolerationsBlockWhenEveryNodeTainted(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", tainted), node("n2", tainted))
	assertStatus(t, run(t, f, "nodes.tolerations"), "BLOCK")
}

func TestArchitectureBlocksOnArm64(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2", arm64))
	assertStatus(t, run(t, f, "nodes.architecture"), "BLOCK")
}

// The OpenShift branch must not be judged by IngressClass, and the vanilla
// branch must not be judged by ClusterOperator. Getting this backwards would
// report a healthy cluster as broken on one distribution and vice versa.
func TestIngressOpenShiftUsesOperatorNotIngressClass(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", clusterOperator("ingress", true)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.ocp.example.com", 2))
	assertStatus(t, run(t, f, "components.ingress"), "PASS")
}

func TestIngressOpenShiftBlocksWhenOperatorDegraded(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", clusterOperator("ingress", false))
	assertStatus(t, run(t, f, "components.ingress"), "BLOCK")
}

func TestIngressVanillaBlocksWithNoIngressClass(t *testing.T) {
	assertStatus(t, run(t, vanilla(), "components.ingress"), "BLOCK")
}

func TestMetricsServerBlocksWhenUnavailable(t *testing.T) {
	f := vanilla().with("apiservices.apiregistration.k8s.io", "",
		apiService("v1beta1.metrics.k8s.io", false))
	assertStatus(t, run(t, f, "components.metrics-server"), "BLOCK")
}

func TestMetricsServerPassesWhenAvailable(t *testing.T) {
	f := vanilla().with("apiservices.apiregistration.k8s.io", "",
		apiService("v1beta1.metrics.k8s.io", true))
	assertStatus(t, run(t, f, "components.metrics-server"), "PASS")
}

// A GPU node whose device plugin has stopped still reports capacity. Reading
// capacity instead of allocatable would call this fleet healthy.
func TestGPUNodesIgnoresCapacityOnlyAdvertisement(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", gpuCapacityOnly("4")))
	r := run(t, f, "gpu.nodes")
	if r.Status() == "PASS" {
		t.Fatalf("gpu.nodes passed on a node advertising GPU capacity but no allocatable: %s", r.Summary)
	}
}
