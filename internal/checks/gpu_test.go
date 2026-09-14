package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The gpu group is the one place where a green result is most expensive to get
// wrong: every signal it reads (a label, a capacity number, a RuntimeClass
// object) is produced by something OTHER than a working GPU, so each of them
// keeps reporting health after the thing it stands for has died. These tests
// exist to prove each check can still say no.

// ---------------------------------------------------------------------------
// Builders. Group-prefixed so they cannot collide with a sibling group's file.
// ---------------------------------------------------------------------------

// gpuTestAdvertises is the healthy shape: the plugin registered and the kubelet
// publishes the resource in BOTH allocatable and capacity.
func gpuTestAdvertises(resource, count string) func(adapters.Object) {
	return func(o adapters.Object) {
		st := o["status"].(map[string]any)
		st["allocatable"].(map[string]any)[resource] = count
		st["capacity"].(map[string]any)[resource] = count
	}
}

// gpuTestCapacityOnly is the same failure gpuCapacityOnly models, for the
// vendors the harness has no shorthand for.
func gpuTestCapacityOnly(resource, count string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["status"].(map[string]any)["capacity"].(map[string]any)[resource] = count
	}
}

func gpuTestLabel(key, value string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["metadata"].(map[string]any)["labels"].(map[string]any)[key] = value
	}
}

func gpuTestCordoned(o adapters.Object) {
	o["spec"].(map[string]any)["unschedulable"] = true
}

// gpuTestTaint models the GPU-node taint convention (nvidia.com/gpu=present),
// which is NOT the control-plane taint the harness's `tainted` applies.
func gpuTestTaint(key, value, effect string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["spec"].(map[string]any)["taints"] = []any{
			map[string]any{"key": key, "value": value, "effect": effect},
		}
	}
}

func gpuTestPluginDaemonSet(ns, name, image string, ready, desired int) adapters.Object {
	return adapters.Object{
		"apiVersion": "apps/v1", "kind": "DaemonSet",
		"metadata": map[string]any{"name": name, "namespace": ns, "uid": "uid-" + name},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "plugin", "image": image}},
		}}},
		"status": map[string]any{
			"numberReady": int64(ready), "desiredNumberScheduled": int64(desired),
		},
	}
}

// gpuTestPluginPod is a DaemonSet-owned pod pinned to a node: coverage is a
// per-node fact, and a DaemonSet's own ready COUNT never says which node is
// uncovered.
func gpuTestPluginPod(ns, name, nodeName, owner string, ready bool) adapters.Object {
	cond := "True"
	if !ready {
		cond = "False"
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": ns,
			"ownerReferences": []any{map[string]any{
				"kind": "DaemonSet", "name": owner, "uid": "uid-" + owner,
			}},
		},
		"spec": map[string]any{
			"nodeName":   nodeName,
			"containers": []any{map[string]any{"name": "plugin", "image": "k8s-device-plugin:v0.16.2"}},
		},
		"status": map[string]any{
			"phase":      "Running",
			"conditions": []any{map[string]any{"type": "Ready", "status": cond}},
		},
	}
}

func gpuTestRuntimeClass(name, handler string) adapters.Object {
	return adapters.Object{
		"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
		"metadata": map[string]any{"name": name},
		"handler":  handler,
	}
}

func gpuTestDeployment(ns, name string, available int) adapters.Object {
	return adapters.Object{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "hami:v2.4.0"}},
		}}},
		"status": map[string]any{"availableReplicas": int64(available)},
	}
}

// gpuTestText flattens everything the operator would read, so an assertion can
// say "this result must NAME the uncovered node" rather than pinning a field.
func gpuTestText(r engine.Result) string {
	parts := []string{r.Summary, r.Remedy, r.DoesNotProve}
	parts = append(parts, r.Detail...)
	for _, e := range r.Evidence {
		parts = append(parts, e.What, e.Output)
	}
	return strings.Join(parts, "\n")
}

func gpuTestAssertMentions(t *testing.T, r engine.Result, want ...string) {
	t.Helper()
	hay := strings.ToLower(gpuTestText(r))
	for _, w := range want {
		if !strings.Contains(hay, strings.ToLower(w)) {
			t.Fatalf("%s [%s]: expected the result to mention %q\n--- result ---\n%s",
				r.ID, r.Status(), w, gpuTestText(r))
		}
	}
}

func gpuTestAssertSilentOn(t *testing.T, r engine.Result, unwanted ...string) {
	t.Helper()
	hay := strings.ToLower(gpuTestText(r))
	for _, w := range unwanted {
		if strings.Contains(hay, strings.ToLower(w)) {
			t.Fatalf("%s [%s]: result must NOT mention %q\n--- result ---\n%s",
				r.ID, r.Status(), w, gpuTestText(r))
		}
	}
}

// ---------------------------------------------------------------------------
// Probe plumbing. The harness leaves Ctx.Probes nil, which is the --no-probe
// path; gpu.operator-functional's whole value is the three stages it separates,
// and asserting only its skip would leave all three untested.
// ---------------------------------------------------------------------------

func gpuTestCtx(t *testing.T, f *fakeCluster, withProbes bool, setup func(*k8sfake.Clientset)) *engine.Ctx {
	t.Helper()
	profile, err := intake.LoadProfile()
	if err != nil {
		t.Fatalf("embedded profile: %v", err)
	}
	cs := k8sfake.NewSimpleClientset()
	if setup != nil {
		setup(cs)
	}
	k := adapters.NewFakeKube(cs, nil, nil, nil,
		func(_ context.Context, node string) adapters.NodeStats {
			if s, ok := f.stats[node]; ok {
				return s
			}
			return adapters.NodeStats{Node: node, Err: "no stats seeded"}
		})
	k.SetAPIGroups(f.apiGroups)
	for key, objs := range f.objects {
		fq, ns := splitKey(key)
		k.Seed(fq, ns, objs)
	}
	c := engine.NewCtx()
	c.Kube = k
	c.Net = adapters.NewNet(time.Second)
	c.OCI = adapters.NewOCI(c.Net)
	c.Helm = adapters.NewHelm()
	c.Answers = f.answers
	c.Profile = profile
	c.Opts = f.opts
	c.Platform = f.platform
	if withProbes {
		c.Probes = probes.NewRunner(k, "budctl-gpu-unit", "unit", false)
	}
	return c
}

func gpuTestRunWithProbes(t *testing.T, f *fakeCluster, timeout time.Duration, setup func(*k8sfake.Clientset)) engine.Result {
	t.Helper()
	ch := engine.Lookup("gpu.operator-functional")
	if ch == nil {
		t.Fatal("no such check: gpu.operator-functional")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return ch.Run(ctx, gpuTestCtx(t, f, true, setup))
}

// gpuTestPodReactor makes the fake API server answer for the probe pod: its
// status is what separates "never scheduled" from "never started" from "ran and
// found nothing", and the container's log carries the device assertion.
func gpuTestPodReactor(nodeName, logs string, status corev1.PodStatus) func(*k8sfake.Clientset) {
	return func(cs *k8sfake.Clientset) {
		cs.PrependReactor("get", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() == "log" {
				return true, &runtime.Unknown{Raw: []byte(logs)}, nil
			}
			p := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "budctl-gpu-probe", Namespace: a.GetNamespace()},
			}
			p.Spec.NodeName = nodeName
			p.Status = status
			return true, p, nil
		})
	}
}

func gpuTestWaiting(phase, reason, message string) corev1.PodStatus {
	return corev1.PodStatus{
		Phase: corev1.PodPhase(phase),
		ContainerStatuses: []corev1.ContainerStatus{{
			Name:  "probe",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: message}},
		}},
	}
}

func gpuTestTerminated(phase, reason string, exit int32) corev1.PodStatus {
	return corev1.PodStatus{
		Phase: corev1.PodPhase(phase),
		ContainerStatuses: []corev1.ContainerStatus{{
			Name: "probe",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				Reason: reason, ExitCode: exit,
			}},
		}},
	}
}

// gpuTestIDs is the whole group. Used by the CPU-only test, which must cover
// every id: a check that quietly reports nothing on a CPU cluster and a check
// that says "there are no GPUs here" look identical unless the skip is asserted.
var gpuTestIDs = []string{
	"gpu.nodes", "gpu.device-plugin", "gpu.runtime-class",
	"gpu.operator-functional", "gpu.sharing", "gpu.capacity",
}

// ---------------------------------------------------------------------------
// The whole group on a CPU-only cluster
// ---------------------------------------------------------------------------

func TestGPUGroupSkipsWithReasonOnCPUOnlyCluster(t *testing.T) {
	for _, id := range gpuTestIDs {
		t.Run(id, func(t *testing.T) {
			f := vanilla().with("nodes", "", node("cpu-1"), node("cpu-2"))
			assertSkipHasReason(t, run(t, f, id))
		})
	}
}

// A CPU-only fleet is a legitimate Bud install, so the reason must say so
// rather than reading as an apology for an unfinished check.
func TestGPUSkipReasonNamesCPUOnlyAsSupported(t *testing.T) {
	f := vanilla().with("nodes", "", node("cpu-1"))
	r := run(t, f, "gpu.nodes")
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "CPU-only cluster, which Bud supports")
}

// The dangerous case: the operator stated GPU serving and the cluster has none.
// The group still skips — there is no accelerator to judge — but a bare
// "no GPU nodes" there reads as a clean bill of health for a cluster on which
// every GPU deployment will sit Pending forever.
func TestGPUSkipReasonNamesTheContradictionWhenIntakeSaysGPU(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("cpu-1")).
		withAnswers(func(a *intake.Answers) { a.GPU = true })
	r := run(t, f, "gpu.device-plugin")
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "the intake states GPU serving", "would stay Pending")
}

// With probes enabled the functional check must still skip on a CPU fleet, and
// for the fleet reason — not for the probe-disabled one.
func TestGPUOperatorFunctionalSkipsOnCPUOnlyFleetEvenWithProbesEnabled(t *testing.T) {
	f := vanilla().with("nodes", "", node("cpu-1"))
	r := gpuTestRunWithProbes(t, f, 5*time.Second, nil)
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "no node advertises nvidia.com/gpu")
}

// ---------------------------------------------------------------------------
// gpu.nodes — detection semantics
// ---------------------------------------------------------------------------

// The single most important claim in the group: allocatable is the only signal
// that means a GPU can be handed to a pod.
func TestGPUNodesCountsAllocatableAndNotCapacityOnly(t *testing.T) {
	healthy := run(t, vanilla().with("nodes", "", node("gpu-1", withGPU("4"))), "gpu.nodes")
	assertStatus(t, healthy, "INFO")
	gpuTestAssertMentions(t, healthy, "4 nvidia.com/gpu on 1 node", "detected by allocatable")

	// Same node, plugin dead: capacity still says 4. The totals line must say 0,
	// because 0 is the number of GPUs this fleet can actually schedule.
	dead := run(t, vanilla().with("nodes", "", node("gpu-1", gpuCapacityOnly("4"))), "gpu.nodes")
	assertStatus(t, dead, "INFO")
	gpuTestAssertMentions(t, dead,
		"0 nvidia.com/gpu on 1 node",
		"allocatable 0, capacity 4 (detected by capacity only)",
		"gpu.device-plugin reports what that costs")
	gpuTestAssertSilentOn(t, dead, "4 nvidia.com/gpu on 1 node")
}

// Driver never loaded: nothing is advertised at all, in allocatable OR in
// capacity. Only the hardware labels remain, and missing this case would let
// budctl skip the whole group on a cluster full of idle GPUs.
func TestGPUNodesDetectsHardwareLabelWhenNothingIsAdvertised(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gpu-1", gpuTestLabel("nvidia.com/gpu.present", "true")))
	r := run(t, f, "gpu.nodes")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "detected by hardware label only", "advertises no allocatable nvidia.com/gpu")
}

// A NotReady or cordoned node's advertised GPUs are not usable. Counting them
// is how a fleet looks big enough right up to the first deployment.
func TestGPUNodesSeparatesUsableFromAdvertisedOnUnusableNodes(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gpu-1", withGPU("4")),
		node("gpu-2", withGPU("4"), notReady),
		node("gpu-3", withGPU("4"), gpuTestCordoned))
	r := run(t, f, "gpu.nodes")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "only 4 of 12 nvidia.com/gpu sit on Ready, schedulable nodes",
		"node NotReady", "cordoned")
}

func TestGPUNodesDetectsNonNVIDIAVendors(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gaudi-1", gpuTestAdvertises("habana.ai/gaudi", "8")),
		node("amd-1", gpuTestAdvertises("amd.com/gpu", "2")))
	r := run(t, f, "gpu.nodes")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "habana.ai/gaudi", "amd.com/gpu", "2 GPU nodes")
}

// registry.hami-scheduler and the report both read this list. If gpu.nodes
// stopped publishing it, those would silently degrade rather than fail.
func TestGPUNodesPublishesTheFleetForLaterChecks(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-2", withGPU("1")), node("gpu-1", withGPU("1")), node("cpu-1"))
	c := gpuTestCtx(t, f, false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	engine.Lookup("gpu.nodes").Run(ctx, c)

	v, ok := c.Get(engine.KeyGPUNodes)
	if !ok {
		t.Fatal("gpu.nodes did not publish engine.KeyGPUNodes; downstream checks would see a CPU-only cluster")
	}
	got, _ := v.([]string)
	if len(got) != 2 || got[0] != "gpu-1" || got[1] != "gpu-2" {
		t.Fatalf("published fleet %v, want [gpu-1 gpu-2] (sorted, CPU nodes excluded)", got)
	}
}

// ---------------------------------------------------------------------------
// gpu.device-plugin — BLOCK
// ---------------------------------------------------------------------------

// The fixture case from TEST_CASES.md: capacity without allocatable. Reading
// capacity would call this node healthy while every GPU pod stays Pending.
func TestGPUDevicePluginBlocksOnCapacityWithoutAllocatable(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", gpuCapacityOnly("4")))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "gpu-1",
		"the plugin registered once and has since stopped",
		"stays Pending forever")
}

// Hardware present, nothing advertised: the plugin never registered, which is
// nearly always an unloaded driver module. Its remedy differs from the stale
// advertisement above, so the two must not collapse into one message.
func TestGPUDevicePluginBlocksWhenPluginNeverRegistered(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gpu-1", gpuTestLabel("feature.node.kubernetes.io/pci-10de.present", "true")))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "the plugin has never registered", "driver module is not loaded")
}

// A DaemonSet reports 2/3 ready. The count alone never says WHICH node has no
// plugin, and the uncovered node is the only actionable fact here.
func TestGPUDevicePluginBlocksAndNamesTheUncoveredNodeOfThree(t *testing.T) {
	f := vanilla().
		with("nodes", "",
			node("gpu-1", withGPU("4")), node("gpu-2", withGPU("4")), node("gpu-3", withGPU("4"))).
		with("daemonsets.apps", "", gpuTestPluginDaemonSet(
			"gpu-operator", "nvidia-device-plugin-daemonset", "nvcr.io/nvidia/k8s-device-plugin:v0.16.2", 2, 3)).
		with("pods", "",
			gpuTestPluginPod("gpu-operator", "nvidia-device-plugin-aaa", "gpu-1", "nvidia-device-plugin-daemonset", true),
			gpuTestPluginPod("gpu-operator", "nvidia-device-plugin-bbb", "gpu-2", "nvidia-device-plugin-daemonset", true),
			gpuTestPluginPod("gpu-operator", "nvidia-device-plugin-ccc", "gpu-3", "nvidia-device-plugin-daemonset", false))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "does not cover 1 of 3 GPU nodes (gpu-3)", "the advertisement is stale")
	gpuTestAssertSilentOn(t, r, "(gpu-1")
}

// No plugin pod on the node at all is the same blocker, and the evidence has to
// say "none scheduled" rather than leaving the node's line blank.
func TestGPUDevicePluginBlocksWhenNoPluginPodIsScheduledOnAGPUNode(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4")), node("gpu-2", withGPU("4"))).
		with("daemonsets.apps", "", gpuTestPluginDaemonSet(
			"kube-system", "nvidia-device-plugin", "k8s-device-plugin:v0.16.2", 1, 2)).
		with("pods", "",
			gpuTestPluginPod("kube-system", "nvidia-device-plugin-aaa", "gpu-1", "nvidia-device-plugin", true))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "gpu-2", "no device-plugin pod scheduled on this node")
}

// budcluster installs HAMi instead of, or beside, the stock plugin, and HAMi is
// what advertises nvidia.com/gpu on those nodes. Failing a HAMi cluster for
// having no "nvidia-device-plugin" would be a false blocker on Bud's own
// default install.
func TestGPUDevicePluginPassesOnHAMiNamedPlugin(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("8"))).
		with("daemonsets.apps", "", gpuTestPluginDaemonSet(
			"hami-system", "hami-device-plugin", "projecthami/hami:v2.4.0", 1, 1)).
		with("pods", "",
			gpuTestPluginPod("hami-system", "hami-device-plugin-xyz", "gpu-1", "hami-device-plugin", true))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "hami-system/hami-device-plugin")
}

func TestGPUDevicePluginPassesWhenEveryNodeIsCovered(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4")), node("gpu-2", withGPU("4"))).
		with("daemonsets.apps", "", gpuTestPluginDaemonSet(
			"gpu-operator", "nvidia-device-plugin-daemonset", "nvcr.io/nvidia/k8s-device-plugin:v0.16.2", 2, 2)).
		with("pods", "",
			gpuTestPluginPod("gpu-operator", "nvidia-device-plugin-aaa", "gpu-1", "nvidia-device-plugin-daemonset", true),
			gpuTestPluginPod("gpu-operator", "nvidia-device-plugin-bbb", "gpu-2", "nvidia-device-plugin-daemonset", true))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "8 devices in total")
}

// Deliberate carve-out (gpu.go:341): when budctl recognises NO plugin DaemonSet
// it will not fail a node that demonstrably advertises, so an in-house or
// renamed plugin is not blocked on a naming convention. This test pins that
// decision so a future "tighten it up" change has to argue with it: the cost is
// that a cluster with a working advertisement and an unrecognisable plugin is
// reported as covered with the words "no DaemonSet was found" only in detail.
func TestGPUDevicePluginPassesWhenPluginIsUnrecognisableButAdvertising(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		with("daemonsets.apps", "", gpuTestPluginDaemonSet(
			"custom", "inhouse-gpu-agent", "internal/agent:1.0", 1, 1))
	r := run(t, f, "gpu.device-plugin")
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "no NVIDIA device-plugin DaemonSet was found in any namespace")
}

// ---------------------------------------------------------------------------
// gpu.runtime-class — BLOCK
// ---------------------------------------------------------------------------

// budcluster pins runtimeClassName: nvidia on every model pod. Without the
// object the API server rejects them outright.
func TestGPURuntimeClassBlocksWhenNVIDIARuntimeClassIsAbsent(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := run(t, f, "gpu.runtime-class")
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "`nvidia` RuntimeClass does not exist",
		"no RuntimeClass objects exist in this cluster")
}

// Other RuntimeClasses existing is not the same as the nvidia one existing, and
// the evidence must list what IS there so the operator can see the near-miss.
func TestGPURuntimeClassBlocksWhenOnlyOtherRuntimeClassesExist(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		with("runtimeclasses.node.k8s.io", "",
			gpuTestRuntimeClass("runc", "runc"),
			gpuTestRuntimeClass("nvidia-cdi", "nvidia-cdi"))
	r := run(t, f, "gpu.runtime-class")
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "runc (handler runc)", "nvidia-cdi (handler nvidia-cdi)")
}

func TestGPURuntimeClassPassesWhenPresent(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		with("runtimeclasses.node.k8s.io", "", gpuTestRuntimeClass("nvidia", "nvidia"))
	r := run(t, f, "gpu.runtime-class")
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "does not prove every node")
}

// A Gaudi or AMD fleet never gets runtimeClassName: nvidia rendered, so
// blocking on a missing NVIDIA RuntimeClass there would be a fabricated
// blocker. The skip must say why, not just skip.
func TestGPURuntimeClassSkipsWithReasonOnNonNVIDIAFleet(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gaudi-1", gpuTestAdvertises("habana.ai/gaudi", "8")))
	r := run(t, f, "gpu.runtime-class")
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "Intel Gaudi", "only for NVIDIA runtime containers")
}

// ---------------------------------------------------------------------------
// gpu.capacity — RISK
// ---------------------------------------------------------------------------

func TestGPUCapacityRisksWhenFleetIsSmallerThanStatedConcurrency(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("1"))).
		withAnswers(func(a *intake.Answers) { a.GPU = true; a.Deployments = 4 })
	r := run(t, f, "gpu.capacity")
	assertStatus(t, r, "RISK")
	gpuTestAssertMentions(t, r, "4 concurrent deployments were stated but only 1 allocatable GPU",
		"every further deployment stays Pending")
}

// The subtle one: the fleet HAS the devices, but they sit on nodes the
// scheduler cannot use. Counting advertised rather than usable would pass this.
func TestGPUCapacityRisksWhenAdvertisedGPUsSitOnUnusableNodes(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"), notReady), node("gpu-2", withGPU("4"), gpuTestCordoned)).
		withAnswers(func(a *intake.Answers) { a.GPU = true; a.Deployments = 2 })
	r := run(t, f, "gpu.capacity")
	assertStatus(t, r, "RISK")
	gpuTestAssertMentions(t, r, "only 0 allocatable",
		"8 advertised GPUs sit on NotReady or cordoned nodes and were not counted")
}

func TestGPUCapacityPassesWhenFleetMeetsStatedConcurrency(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		withAnswers(func(a *intake.Answers) { a.GPU = true; a.Deployments = 3 })
	r := run(t, f, "gpu.capacity")
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "4 allocatable GPUs for 3 stated concurrent deployments",
		"a GPU count is not GPU memory")
}

// Every threshold must trace back to an answer. With no stated concurrency
// there is nothing to size against, and inventing a number is how a green run
// becomes wrong — but the skip must say that out loud.
func TestGPUCapacitySkipsWithReasonWhenNoRequirementWasStated(t *testing.T) {
	cases := []struct {
		name   string
		answer func(*intake.Answers)
		want   string
	}{
		{"intake says CPU-only serving", func(a *intake.Answers) { a.GPU = false; a.Deployments = 3 },
			"no GPU concurrency was stated"},
		{"intake states no concurrency", func(a *intake.Answers) { a.GPU = true; a.Deployments = 0 },
			"does not state how many concurrent deployments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla().with("nodes", "", node("gpu-1", withGPU("4"))).withAnswers(tc.answer)
			r := run(t, f, "gpu.capacity")
			assertSkipHasReason(t, r)
			gpuTestAssertMentions(t, r, tc.want)
		})
	}
}

// modelCount sizes storage, not concurrency. Conflating them would silently
// change the GPU requirement.
func TestGPUCapacitySizesAgainstConcurrencyNotModelCount(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("2"))).
		withAnswers(func(a *intake.Answers) { a.GPU = true; a.Deployments = 2; a.ModelCount = 40 })
	r := run(t, f, "gpu.capacity")
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "modelCount=40 is a storage figure, not a concurrency one")
}

// ---------------------------------------------------------------------------
// gpu.sharing — INFO
// ---------------------------------------------------------------------------

func TestGPUSharingReportsNoSharingByDefault(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("2")))
	r := run(t, f, "gpu.sharing")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "no GPU sharing is configured", "budcluster installs HAMi")
}

func TestGPUSharingReportsTimeSlicingFactor(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("20"), gpuTestLabel("nvidia.com/gpu.count", "2"))).
		with("deployments.apps", "", gpuTestDeployment("hami-system", "hami-scheduler", 1))
	r := run(t, f, "gpu.sharing")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "20 schedulable nvidia.com/gpu slots over 2 physical GPUs (×10)",
		"concurrent deployments contend for the same memory")
}

// budcluster pins model pods to schedulerName: hami-scheduler. A HAMi install
// whose scheduler has no available replica means every model pod stays Pending
// — the check is INFO by design, so this asserts the warning at least reaches
// the operator in detail. See the report: this cannot raise the verdict.
func TestGPUSharingWarnsWhenHAMiSchedulerHasNoReplica(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		with("deployments.apps", "", gpuTestDeployment("hami-system", "hami-scheduler", 0))
	r := run(t, f, "gpu.sharing")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "hami-system/hami-scheduler has no available replica",
		"they would stay Pending until it runs")
}

func TestGPUSharingDetectsMIG(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gpu-1", withGPU("1"), gpuTestLabel("nvidia.com/mig.capable", "true"),
			gpuTestLabel("nvidia.com/mig.strategy", "mixed")))
	r := run(t, f, "gpu.sharing")
	assertStatus(t, r, "INFO")
	gpuTestAssertMentions(t, r, "MIG partitioning is configured", "distinct resource names")
}

// ---------------------------------------------------------------------------
// gpu.operator-functional — the probe, by stage
// ---------------------------------------------------------------------------

// --no-probe (and any run without a probe runner) must not read as a pass: the
// chain was not exercised and the skip has to say so.
func TestGPUOperatorFunctionalSkipsWithReasonWhenProbesDisabled(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		withOpts(func(o *engine.Options) { o.NoProbe = true })
	r := run(t, f, "gpu.operator-functional")
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "probes are disabled", "is not confirmed working")
}

// STAGE 1 without creating anything: nothing advertises allocatable, so the
// answer is already known and a probe pod could only sit Pending until timeout.
func TestGPUOperatorFunctionalBlocksAtAllocationWithoutCreatingAPod(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", gpuCapacityOnly("4")))
	r := gpuTestRunWithProbes(t, f, 10*time.Second, nil)
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r,
		"no Ready, schedulable node advertises allocatable nvidia.com/gpu",
		"the probe pod was not created")
}

// A GPU node the Bud charts cannot land on is a blocker even though the fleet
// looks perfect: no chart in the stack declares a toleration.
func TestGPUOperatorFunctionalAllocationRemedyNamesTheBlockingTaint(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gpu-1", withGPU("4"), gpuTestTaint("nvidia.com/gpu", "present", "NoSchedule"), notReady))
	r := gpuTestRunWithProbes(t, f, 10*time.Second, nil)
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "nvidia.com/gpu=present:NoSchedule", "no chart in the stack declares a toleration")
}

// STAGE 1 with a real pod: it was created and never scheduled. Attribution
// matters because the remedy (free a device / drop a taint) has nothing in
// common with the runtime or driver remedies below.
func TestGPUOperatorFunctionalBlocksAtAllocationWhenProbePodStaysPending(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := gpuTestRunWithProbes(t, f, 2*time.Second,
		gpuTestPodReactor("", "", gpuTestWaiting("Pending", "Unschedulable", "0/1 nodes are available: insufficient nvidia.com/gpu")))
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "stage: ALLOCATION", "was never scheduled onto any node")
	gpuTestAssertSilentOn(t, r, "stage: RUNTIME CLASS", "stage: DRIVER")
}

// STAGE 2. Allocation already worked, so this is the RuntimeClass handler or
// the container toolkit — a different team and a different fix.
func TestGPUOperatorFunctionalBlocksAtRuntimeClassStageWhenContainerNeverStarts(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", "", gpuTestWaiting("Failed", "CreateContainerError",
			`failed to create containerd task: no runtime for "nvidia" is configured`)))
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "stage: RUNTIME CLASS / CONTAINER TOOLKIT",
		"container never started", "nvidia-container-toolkit")
	gpuTestAssertSilentOn(t, r, "stage: ALLOCATION", "stage: DRIVER")
}

// STAGE 3. The container ran and got nothing: the plugin handed out a device
// the driver never created. A model pod here gets no GPU and silently falls
// back to CPU, which is the worst outcome of the three to miss.
func TestGPUOperatorFunctionalBlocksAtDriverStageWhenDeviceIsMissingInContainer(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	logs := gpuDeviceMissing + "\nnull\nzero\nurandom\n"
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", logs, gpuTestTerminated("Failed", "Error", 1)))
	assertStatus(t, r, "BLOCK")
	gpuTestAssertMentions(t, r, "stage: DRIVER / DEVICE PLUGIN",
		"no /dev/nvidiactl//dev/nvidia0 device node was injected",
		"silently fall back to CPU")
	gpuTestAssertSilentOn(t, r, "stage: ALLOCATION", "stage: RUNTIME CLASS")
}

// The pass case, which is what makes the three failures above meaningful.
func TestGPUOperatorFunctionalPassesWhenDeviceIsPresentInContainer(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	logs := gpuDevicePresent + "\ncrw-rw-rw- 1 root root 195, 255 /dev/nvidiactl\n"
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", logs, gpuTestTerminated("Succeeded", "Completed", 0)))
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "scheduled, started, and found /dev/nvidiactl or /dev/nvidia0")
}

// FRD-020 D10: the probe must cost megabytes, not gigabytes. The recorded
// evidence is where a regression to a CUDA image would show up.
func TestGPUOperatorFunctionalProbesWithASlimImageNotCUDA(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", gpuDevicePresent, gpuTestTerminated("Succeeded", "Completed", 0)))
	assertStatus(t, r, "PASS")
	// Asserted on the recorded request itself, not on the prose: the detail line
	// legitimately contains the word CUDA to explain why it is NOT used.
	asked := strings.ToLower(r.Evidence[0].What)
	if !strings.Contains(asked, "image "+gpuDefaultProbeImage+", requesting nvidia.com/gpu: 1") {
		t.Fatalf("probe transcript does not show the default slim image: %q", r.Evidence[0].What)
	}
	if strings.Contains(asked, "cuda") || strings.Contains(asked, "nvcr.io") {
		t.Fatalf("the default GPU probe pulled a CUDA-class image (FRD-020 D10): %q", r.Evidence[0].What)
	}
}

// ...unless the operator opted in, which must be visible in the transcript.
func TestGPUOperatorFunctionalHonoursExplicitProbeImage(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		withOpts(func(o *engine.Options) { o.GPUProbeImage = "nvcr.io/nvidia/cuda:12.4.1-base-ubi9" })
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", gpuDevicePresent, gpuTestTerminated("Succeeded", "Completed", 0)))
	assertStatus(t, r, "PASS")
	gpuTestAssertMentions(t, r, "image nvcr.io/nvidia/cuda:12.4.1-base-ubi9")
}

// A node that cannot pull a few megabytes of base image has told us nothing about
// its GPU. Reporting that as a GPU fault would send the operator to the wrong
// stack entirely — it belongs to registry/egress.
func TestGPUOperatorFunctionalSkipsAndRedirectsOnImagePullFailure(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", "", gpuTestWaiting("Failed", "ImagePullBackOff",
			"Back-off pulling image "+gpuDefaultProbeImage)))
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "registry.from-cluster", "egress.install", "was not exercised")
	gpuTestAssertSilentOn(t, r, "stage:")
}

// Admission or RBAC refused the pod. Claiming a GPU verdict from that would be
// a guess, so it must skip with the API server's own error.
func TestGPUOperatorFunctionalSkipsWhenProbePodCannotBeCreated(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := gpuTestRunWithProbes(t, f, 10*time.Second, func(cs *k8sfake.Clientset) {
		cs.PrependReactor("create", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	})
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "could not be created", "was not exercised")
}

// The tcs-vmware GPU node: HAMi scheduled the probe, the container started, and
// busybox's shell died loading HAMi's preloaded vGPU library. That is the image
// failing, not the GPU — a skip that names the loader error and the flag, never
// a device fault and never the generic "unreadable output".
func TestGPUOperatorFunctionalSkipsAndNamesTheImageWhenTheLoaderFails(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		withOpts(func(o *engine.Options) { o.GPUProbeImage = "busybox:1.36" })
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1",
			"/bin/sh: error while loading shared libraries: libdl.so.2: cannot open shared object file: No such file or directory\n",
			gpuTestTerminated("Failed", "Error", 127)))
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "busybox:1.36", "libdl.so.2", "--gpu-probe-image", gpuDefaultProbeImage)
	gpuTestAssertSilentOn(t, r, "stage:")
}

// Ran, exited, and asserted nothing readable. Inferring a device fault from a
// missing log line would be inventing a finding.
func TestGPUOperatorFunctionalSkipsWhenProbeOutputIsUnreadable(t *testing.T) {
	f := vanilla().with("nodes", "", node("gpu-1", withGPU("4")))
	r := gpuTestRunWithProbes(t, f, 10*time.Second,
		gpuTestPodReactor("gpu-1", "sh: applet not found\n", gpuTestTerminated("Succeeded", "Completed", 0)))
	assertSkipHasReason(t, r)
	gpuTestAssertMentions(t, r, "no readable device assertion", "device injection is unverified")
}
