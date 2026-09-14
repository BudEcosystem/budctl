package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The nodes group is the one place where a green result is most dangerous: a
// fleet that is Ready, amd64 and big enough on paper still schedules nothing if
// every node is tainted, and still flaps in ImagePullBackOff if the image
// filesystem is 20 GiB. Every check below therefore has a fixture that drives it
// to BLOCK or RISK — a pass-only test would only prove the code runs.

// ---------------------------------------------------------------------------
// Builders and runners. Group-prefixed so they cannot collide with a sibling
// test file for another group.
// ---------------------------------------------------------------------------

// nodesTestCordoned models a drained node: the kubelet is alive and Ready, so
// only spec.unschedulable separates it from a node that can take work.
func nodesTestCordoned(o adapters.Object) {
	o["spec"].(map[string]any)["unschedulable"] = true
}

// nodesTestDiskPressure is the kubelet saying it is already evicting. It is a
// separate signal from the imageFs percentage and must be honoured on its own.
func nodesTestDiskPressure(o adapters.Object) {
	st := o["status"].(map[string]any)
	st["conditions"] = append(st["conditions"].([]any),
		map[string]any{"type": "DiskPressure", "status": "True"})
}

// nodesTestNoArch strips both architecture sources. A kubelet that reports
// neither must not be assumed amd64 — that would turn a blind spot into a pass
// on the one property that makes every image unpullable.
func nodesTestNoArch(o adapters.Object) {
	delete(o["status"].(map[string]any)["nodeInfo"].(map[string]any), "architecture")
	delete(o["metadata"].(map[string]any)["labels"].(map[string]any), "kubernetes.io/arch")
}

func nodesTestAlloc(cpu, mem string) func(adapters.Object) {
	return func(o adapters.Object) {
		alloc := o["status"].(map[string]any)["allocatable"].(map[string]any)
		alloc["cpu"] = cpu
		alloc["memory"] = mem
	}
}

func nodesTestPodSlots(n string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["status"].(map[string]any)["allocatable"].(map[string]any)["pods"] = n
	}
}

func nodesTestNoPodSlots(o adapters.Object) {
	delete(o["status"].(map[string]any)["allocatable"].(map[string]any), "pods")
}

// nodesTestPreferNoSchedule costs placement, not schedulability: a pod with no
// toleration still lands here, so this node must count as open.
func nodesTestPreferNoSchedule(o adapters.Object) {
	o["spec"].(map[string]any)["taints"] = []any{
		map[string]any{"key": "workload", "value": "models", "effect": "PreferNoSchedule"},
	}
}

func nodesTestMIG(count string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["status"].(map[string]any)["allocatable"].(map[string]any)["nvidia.com/mig-1g.5gb"] = count
	}
}

// nodesTestPod is a pod the scheduler has already placed. Requests, not usage:
// a node idling at 5% CPU with everything requested is full.
func nodesTestPod(ns, name, nodeName, cpu, mem string) adapters.Object {
	return adapters.Object{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"nodeName": nodeName,
			"containers": []any{map[string]any{
				"name": "c", "image": "x:1",
				"resources": map[string]any{"requests": map[string]any{"cpu": cpu, "memory": mem}},
			}},
		},
		"status": map[string]any{"phase": "Running"},
	}
}

func nodesTestPodPhase(p adapters.Object, phase string) adapters.Object {
	p["status"].(map[string]any)["phase"] = phase
	return p
}

func nodesTestUnscheduled(p adapters.Object) adapters.Object {
	delete(p["spec"].(map[string]any), "nodeName")
	return p
}

// nodesTestDeployment is a rendered workload, used where a check prefers the
// --values render over the profile floor.
func nodesTestDeployment(name, cpu, mem string, replicas int) adapters.Object {
	return adapters.Object{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": "bud"},
		"spec": map[string]any{
			"replicas": int64(replicas),
			"template": map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{
					"name": "c", "image": "x:1",
					"resources": map[string]any{"requests": map[string]any{"cpu": cpu, "memory": mem}},
				}},
			}},
		},
	}
}

// nodesRun is run() with a hook on the context, so a test can nil out Kube
// (cluster unreachable), raise a profile floor, or pre-seed a render without
// reaching into the harness.
func nodesRun(t *testing.T, f *fakeCluster, id string, tweak func(*engine.Ctx)) engine.Result {
	t.Helper()
	r, _ := nodesRunCtx(t, f, id, tweak)
	return r
}

// nodesRunCtx also returns the context, which is the only way to assert what a
// check published for a later group (nodes.accelerators → engine.KeyGPUNodes).
func nodesRunCtx(t *testing.T, f *fakeCluster, id string, tweak func(*engine.Ctx)) (engine.Result, *engine.Ctx) {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	if tweak != nil {
		tweak(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c), c
}

// nodesAssertMentions enforces G2: a failure has to name its consequence and a
// remedy an operator can act on, not just a status word.
func nodesAssertMentions(t *testing.T, r engine.Result, substrings ...string) {
	t.Helper()
	parts := []string{r.Summary, r.Remedy}
	parts = append(parts, r.Detail...)
	for _, ev := range r.Evidence {
		parts = append(parts, ev.What, ev.Output)
	}
	hay := strings.ToLower(strings.Join(parts, "\n"))
	for _, want := range substrings {
		if !strings.Contains(hay, strings.ToLower(want)) {
			t.Fatalf("%s [%s]: result never mentions %q\n  summary: %s\n  remedy: %s\n  detail: %v",
				r.ID, r.Status(), want, r.Summary, r.Remedy, r.Detail)
		}
	}
}

func nodesAssertHasEvidence(t *testing.T, r engine.Result) {
	t.Helper()
	if len(r.Evidence) == 0 || strings.TrimSpace(r.Evidence[0].Output) == "" {
		t.Fatalf("%s: claim carries no evidence, so nobody can check the arithmetic: %s", r.ID, r.Summary)
	}
}

// ---------------------------------------------------------------------------
// nodes.ready
// ---------------------------------------------------------------------------

// The whole install is pods. If nothing is both Ready and uncordoned, every one
// of them stays Pending forever, which is a blocker and not a warning.
func TestNodesReadyBlocksWhenEveryNodeNotReady(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", notReady), node("n2", notReady))
	r := run(t, f, "nodes.ready")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "pending", "n1", "n2")
	nodesAssertHasEvidence(t, r)
}

// A cordoned fleet reads as healthy to anything that only looks at Ready. It
// schedules exactly as much as a NotReady one: nothing.
func TestNodesReadyBlocksWhenEveryNodeCordoned(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", nodesTestCordoned), node("n2", nodesTestCordoned))
	r := run(t, f, "nodes.ready")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "cordoned")
}

func TestNodesReadyBlocksWhenClusterHasNoNodes(t *testing.T) {
	r := run(t, vanilla(), "nodes.ready")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "no nodes")
}

// One lost node is not a blocker — the install can still land — but the survivors
// now have to carry the whole platform, so it must not read as a clean pass.
func TestNodesReadyRisksWhenSomeNodesUnavailable(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2", notReady), node("n3", nodesTestCordoned))
	r := run(t, f, "nodes.ready")
	assertStatus(t, r, "RISK")
	nodesAssertMentions(t, r, "n2", "n3")
}

func TestNodesReadyPassesWhenAllSchedulable(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	r := run(t, f, "nodes.ready")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("nodes.ready passed without bounding the claim (G3)")
	}
}

// ---------------------------------------------------------------------------
// nodes.count
// ---------------------------------------------------------------------------

// MinNodes is about placement, so NotReady nodes do not count towards it: a
// count taken from len(nodes) would pass a cluster with nowhere to schedule.
func TestNodesCountBlocksBelowMinNodes(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", notReady), node("n2", notReady))
	r := run(t, f, "nodes.count")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "0 schedulable")
}

// The floor must come from the profile rather than from a hardcoded zero test:
// raise it and a two-node cluster has to block.
func TestNodesCountBlocksAgainstProfileMinimum(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	r := nodesRun(t, f, "nodes.count", func(c *engine.Ctx) { c.Profile.MinNodes = 3 })
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "minimum of 3")
}

// Two nodes with in-cluster data stores is the real-world shape this check
// exists for: Kafka's min.insync.replicas=2, Keeper's 3-member quorum and CNPG's
// 3 instances all install, and none of them is actually redundant.
func TestNodesCountRisksBelowAddonFloorWithInClusterData(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		withAnswers(func(a *intake.Answers) { a.InClusterData = true })
	r := run(t, f, "nodes.count")
	assertStatus(t, r, "RISK")
	nodesAssertMentions(t, r, "kafka", "keeper", "cloudnativepg")
}

// The 3-node floor is a consequence of the in-cluster answer, not a property of
// the cluster. Answer "external" and the same two nodes are fine — otherwise the
// check would demand capacity for stores that are never installed.
func TestNodesCountPassesOnTwoNodesWhenDataStoresAreExternal(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		withAnswers(func(a *intake.Answers) { a.InClusterData = false })
	r := run(t, f, "nodes.count")
	assertStatus(t, r, "PASS")
	nodesAssertMentions(t, r, "external")
}

func TestNodesCountPassesAtAddonFloor(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"), node("n3"))
	assertStatus(t, run(t, f, "nodes.count"), "PASS")
}

// ---------------------------------------------------------------------------
// nodes.architecture
// ---------------------------------------------------------------------------

// Every Bud image is linux/amd64 only, so an arm64 node is not "smaller
// capacity", it is a node where the pod can never pull.
func TestNodesArchitectureBlocksOnAllArm64Fleet(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", arm64), node("n2", arm64))
	r := run(t, f, "nodes.architecture")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "imagepullbackoff", "arm64")
}

// A mixed fleet is still a blocker: no chart sets an arch nodeSelector, so the
// scheduler is free to place a pod on the node that cannot run it.
func TestNodesArchitectureBlocksOnMixedFleet(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2", arm64))
	r := run(t, f, "nodes.architecture")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "nodeselector", "n2")
}

// Claiming amd64 when no kubelet said so would convert a blind spot into a pass.
func TestNodesArchitectureSkipsWhenNoNodeReportsAnArchitecture(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", nodesTestNoArch))
	assertSkipHasReason(t, run(t, f, "nodes.architecture"))
}

func TestNodesArchitectureSkipsWithNoNodes(t *testing.T) {
	assertSkipHasReason(t, run(t, vanilla(), "nodes.architecture"))
}

func TestNodesArchitecturePassesOnAmd64Fleet(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	assertStatus(t, run(t, f, "nodes.architecture"), "PASS")
}

// ---------------------------------------------------------------------------
// nodes.tolerations
// ---------------------------------------------------------------------------

// The finding this check was written for: no chart in infra/charts/** declares a
// toleration, so a fully tainted fleet schedules nothing and the only symptom is
// silent Pending with no event that explains it.
func TestNodesTolerationsBlocksOnFullyTaintedFleetVanilla(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", tainted), node("n2", tainted))
	r := run(t, f, "nodes.tolerations")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "no chart", "toleration", "kubectl taint node")
}

// Same cluster shape, different remedy: on OpenShift the control-plane taint is
// by design and telling an operator to remove it is wrong advice.
func TestNodesTolerationsBlocksOnOpenShiftWithMachineSetRemedy(t *testing.T) {
	f := openShift().with("nodes", "", node("m1", tainted))
	r := run(t, f, "nodes.tolerations")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "machineset")
	if strings.Contains(strings.ToLower(r.Remedy), "kubectl taint node") {
		t.Fatalf("OpenShift remedy leaked the vanilla untaint advice: %s", r.Remedy)
	}
}

// One open node is enough to schedule, but the tainted nodes' cores must be
// excluded from the capacity story rather than quietly counted.
func TestNodesTolerationsPassesWhenOneNodeIsUntainted(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", tainted), node("n2"))
	r := run(t, f, "nodes.tolerations")
	assertStatus(t, r, "PASS")
	nodesAssertMentions(t, r, "n1", "excluded")
}

// PreferNoSchedule costs placement, not schedulability. Treating it as a fence
// would block a cluster that schedules perfectly well.
func TestNodesTolerationsIgnoresPreferNoSchedule(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", nodesTestPreferNoSchedule))
	assertStatus(t, run(t, f, "nodes.tolerations"), "PASS")
}

// With nothing Ready there are no taints to read. That is "not looked at", and
// nodes.ready already states the consequence.
func TestNodesTolerationsSkipsWhenNothingIsReady(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", notReady))
	assertSkipHasReason(t, run(t, f, "nodes.tolerations"))
}

// ---------------------------------------------------------------------------
// nodes.capacity
// ---------------------------------------------------------------------------

// The requirement is derived from the intake answers, so raising the concurrent
// deployment count has to move the bar — a fixed profile number would pass here.
func TestNodesCapacityBlocksWhenDeploymentsScaleTheRequirement(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		withAnswers(func(a *intake.Answers) { a.Deployments = 12 })
	r := run(t, f, "nodes.capacity")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "short", "insufficient cpu/memory", "12 concurrent deployments")
	nodesAssertHasEvidence(t, r)
	// The arithmetic has to be in the evidence, or the operator cannot tell how
	// much to add.
	nodesAssertMentions(t, r, "cluster free:", "required:")
}

// Allocatable alone is a fiction once the cluster is in use: the scheduler
// places against requests, so committed pods must come off the total.
func TestNodesCapacityBlocksWhenExistingPodsHaveCommittedTheMemory(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		with("pods", "",
			nodesTestPod("other", "hog-a", "n1", "1", "30Gi"),
			nodesTestPod("other", "hog-b", "n2", "1", "30Gi"))
	r := run(t, f, "nodes.capacity")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "short of memory")
}

// Terminated pods hold nothing, and an unscheduled pod holds nothing yet.
// Charging either against a node would invent a shortage that does not exist.
func TestNodesCapacityIgnoresTerminatedAndUnscheduledPods(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		with("pods", "",
			nodesTestPodPhase(nodesTestPod("other", "done", "n1", "4", "30Gi"), "Succeeded"),
			nodesTestUnscheduled(nodesTestPod("other", "pending", "n2", "4", "30Gi")))
	assertStatus(t, run(t, f, "nodes.capacity"), "PASS")
}

// Tainted nodes are unreachable to this install, so measuring them would produce
// a green capacity check for a cluster that schedules nothing.
func TestNodesCapacitySkipsWhenEveryNodeIsTainted(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", tainted))
	assertSkipHasReason(t, run(t, f, "nodes.capacity"))
}

func TestNodesCapacityPassesWithHeadroom(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	r := run(t, f, "nodes.capacity")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("nodes.capacity passed without bounding the claim to totals (G3)")
	}
}

// ---------------------------------------------------------------------------
// nodes.largest-pod
// ---------------------------------------------------------------------------

// The case cluster totals hide: 16 GiB free across four nodes is not 6 GiB on
// one, and Kubernetes never splits a pod.
func TestNodesLargestPodBlocksWhenTotalsFitButNoSingleNodeDoes(t *testing.T) {
	small := nodesTestAlloc("4", "4Gi")
	f := vanilla().with("nodes", "",
		node("n1", small), node("n2", small), node("n3", small), node("n4", small))
	r := run(t, f, "nodes.largest-pod")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "semantic-router", "pending")
	nodesAssertHasEvidence(t, r)
}

// Free, not allocatable: a 8 GiB node with 4 GiB already requested cannot hold a
// 6 GiB pod, however empty it looks in `kubectl get nodes`.
func TestNodesLargestPodBlocksWhenRequestsEatTheRoom(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1", nodesTestAlloc("8", "8Gi"))).
		with("pods", "", nodesTestPod("other", "tenant", "n1", "1", "4Gi"))
	assertStatus(t, run(t, f, "nodes.largest-pod"), "BLOCK")
}

// With a --values render the rendered chart beats the profile floor (FRD §7),
// so a pod larger than semantic-router has to be the one measured.
func TestNodesLargestPodPrefersTheRenderedChartOverTheProfileFloor(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1")) // 32Gi allocatable: clears the 6Gi floor
	r := nodesRun(t, f, "nodes.largest-pod", func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			nodesTestDeployment("budsim", "2", "64Gi", 1),
		})
	})
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "budsim", "rendered chart")
}

func TestNodesLargestPodPassesOnANodeThatHoldsIt(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"))
	assertStatus(t, run(t, f, "nodes.largest-pod"), "PASS")
}

func TestNodesLargestPodSkipsWithNoUsableNode(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", tainted))
	assertSkipHasReason(t, run(t, f, "nodes.largest-pod"))
}

// ---------------------------------------------------------------------------
// nodes.imagefs
// ---------------------------------------------------------------------------

// 20 GiB free against ~55 GiB of images: the kubelet garbage-collects layers it
// just pulled and the pods flap rather than fail cleanly.
func TestNodesImageFsBlocksBelowTheFloorAndCitesTheFootprint(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(200), ImageFsAvailable: gib(120)}).
		withStats("n2", adapters.NodeStats{Node: "n2", ImageFsCapacity: gib(200), ImageFsAvailable: gib(20)})
	r := run(t, f, "nodes.imagefs")
	assertStatus(t, r, "BLOCK")
	nodesAssertMentions(t, r, "19.8 GiB compressed", "80 GiB", "n2")
	nodesAssertHasEvidence(t, r)
}

func TestNodesImageFsPassesAboveTheFloor(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(400), ImageFsAvailable: gib(120)})
	r := run(t, f, "nodes.imagefs")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("nodes.imagefs passed without noting the model runtime images it does not cover (G3)")
	}
}

// The kubelet proxy is a separate RBAC verb from listing nodes, so a 403 here is
// ordinary. It must read as "not verified", never as a pass.
func TestNodesImageFsSkipsWhenTheKubeletProxyIsForbidden(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1", Err: "nodes \"n1\" is forbidden: User cannot get resource \"nodes/proxy\""})
	r := run(t, f, "nodes.imagefs")
	assertSkipHasReason(t, r)
	nodesAssertMentions(t, r, "forbidden")
}

// A partial measurement is not a fleet-wide claim: one good node plus one
// unreadable node is a skip, not a pass on the node that answered.
func TestNodesImageFsSkipsWhenAnyNodeIsUnmeasured(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(400), ImageFsAvailable: gib(200)})
	r := run(t, f, "nodes.imagefs")
	assertSkipHasReason(t, r)
	nodesAssertMentions(t, r, "n2")
}

// A node known to be short still blocks even if another node could not be read:
// an unknown does not soften a measured failure.
func TestNodesImageFsBlocksEvenWhenAnotherNodeIsUnreadable(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1"), node("n2")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(200), ImageFsAvailable: gib(10)})
	assertStatus(t, run(t, f, "nodes.imagefs"), "BLOCK")
}

// ---------------------------------------------------------------------------
// nodes.eviction-pressure
// ---------------------------------------------------------------------------

// 100 GiB free clears the 80 GiB floor, yet 10% of capacity is inside the
// kubelet's imagefs.available<15% eviction band — the node is collecting images
// right now, so the absolute figure alone would miss it.
func TestNodesEvictionPressureRisksBelowTheThresholdDespiteAbsoluteHeadroom(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(1000), ImageFsAvailable: gib(100)})
	r := run(t, f, "nodes.eviction-pressure")
	assertStatus(t, r, "RISK")
	nodesAssertMentions(t, r, "eviction", "crictl rmi --prune")
	// The same fixture must NOT block on the floor, or this test would prove
	// nothing about the percentage branch.
	assertStatus(t, run(t, f, "nodes.imagefs"), "PASS")
}

// The kubelet's own DiskPressure condition is a second, independent signal: a
// node can be evicting for reasons the imageFs percentage does not show.
func TestNodesEvictionPressureRisksOnDiskPressureCondition(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1", nodesTestDiskPressure)).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(1000), ImageFsAvailable: gib(900)})
	r := run(t, f, "nodes.eviction-pressure")
	assertStatus(t, r, "RISK")
	nodesAssertMentions(t, r, "diskpressure")
}

func TestNodesEvictionPressurePassesWithRoom(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1", ImageFsCapacity: gib(400), ImageFsAvailable: gib(200)})
	assertStatus(t, run(t, f, "nodes.eviction-pressure"), "PASS")
}

func TestNodesEvictionPressureSkipsWhenNoNodeCouldBeMeasured(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	assertSkipHasReason(t, run(t, f, "nodes.eviction-pressure"))
}

// GAP, asserted so it is visible rather than discovered later: a kubelet that
// answers /stats/summary without a runtime.imageFs block yields zeros with no
// error, and the percentage branch skips it (capacity 0) while still counting
// the node as "measured" — so this check reports PASS having measured nothing.
// nodes.imagefs is what actually catches the fixture today.
func TestNodesEvictionPressureReportsPassWhenImageFsIsUnreported(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withStats("n1", adapters.NodeStats{Node: "n1"}) // no Err, no imageFs figures
	assertStatus(t, run(t, f, "nodes.eviction-pressure"), "PASS")
	assertStatus(t, run(t, f, "nodes.imagefs"), "BLOCK")
}

// ---------------------------------------------------------------------------
// nodes.pod-slots
// ---------------------------------------------------------------------------

// "Too many pods" reads like a capacity problem and is not one: CPU and memory
// headroom does nothing for the kubelet max-pods ceiling.
func TestNodesPodSlotsRisksWhenTheMaxPodsCeilingIsTooLow(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", nodesTestPodSlots("10")))
	r := run(t, f, "nodes.pod-slots")
	assertStatus(t, r, "RISK")
	nodesAssertMentions(t, r, "too many pods", "max-pods")
	nodesAssertHasEvidence(t, r)
}

// Slots already taken by other workloads count against the ceiling.
func TestNodesPodSlotsRisksWhenRunningPodsHaveTakenTheSlots(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", nodesTestPodSlots("64")))
	for i := 0; i < 40; i++ {
		f = f.with("pods", "", nodesTestPod("other", fmt.Sprintf("tenant-%d", i), "n1", "10m", "10Mi"))
	}
	assertStatus(t, run(t, f, "nodes.pod-slots"), "RISK")
}

func TestNodesPodSlotsPassesWithDefaultCeiling(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	assertStatus(t, run(t, f, "nodes.pod-slots"), "PASS")
}

// An unknown ceiling is not a clear one.
func TestNodesPodSlotsSkipsWhenNoNodeReportsAllocatablePods(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", nodesTestNoPodSlots))
	assertSkipHasReason(t, run(t, f, "nodes.pod-slots"))
}

func TestNodesPodSlotsSkipsWithNoUsableNode(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1", tainted))
	assertSkipHasReason(t, run(t, f, "nodes.pod-slots"))
}

// ---------------------------------------------------------------------------
// nodes.accelerators
// ---------------------------------------------------------------------------

func nodesGPUNodesFrom(t *testing.T, c *engine.Ctx) []string {
	t.Helper()
	v, ok := c.Get(engine.KeyGPUNodes)
	if !ok {
		t.Fatalf("nodes.accelerators did not publish %s, so a later Get cannot tell 'no GPUs' from 'nobody looked'", engine.KeyGPUNodes)
	}
	names, ok := v.([]string)
	if !ok {
		t.Fatalf("%s is %T, not []string", engine.KeyGPUNodes, v)
	}
	return names
}

// The failure this exists to catch: a node whose device plugin has died still
// advertises CAPACITY. Counting capacity would hand the gpu group a fleet that
// cannot schedule a single GPU pod.
func TestNodesAcceleratorsCountsAllocatableNotCapacity(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("gpu-live", withGPU("4")),
		node("gpu-dead", gpuCapacityOnly("8")))
	r, c := nodesRunCtx(t, f, "nodes.accelerators", nil)
	assertStatus(t, r, "INFO")
	got := nodesGPUNodesFrom(t, c)
	if len(got) != 1 || got[0] != "gpu-live" {
		t.Fatalf("GPU node list is %v, want [gpu-live] only: gpu-dead advertises capacity with no allocatable", got)
	}
	nodesAssertMentions(t, r, "gpu-live", "4×nvidia.com/gpu")
}

// MIG slices carry the profile in the resource name, so they have to be matched
// by prefix or a partitioned A100 reads as a GPU-less node.
func TestNodesAcceleratorsCountsMIGSlices(t *testing.T) {
	f := vanilla().with("nodes", "", node("mig1", nodesTestMIG("7")))
	r, c := nodesRunCtx(t, f, "nodes.accelerators", nil)
	assertStatus(t, r, "INFO")
	if got := nodesGPUNodesFrom(t, c); len(got) != 1 {
		t.Fatalf("MIG node not counted as an accelerator node: %v", got)
	}
	nodesAssertMentions(t, r, "nvidia.com/mig-1g.5gb")
}

// The key must be set even when there is nothing to report, so the gpu group
// can distinguish "no GPUs" from "nobody looked".
func TestNodesAcceleratorsPublishesAnEmptyListOnCPUOnlyFleets(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"))
	r, c := nodesRunCtx(t, f, "nodes.accelerators", nil)
	assertStatus(t, r, "INFO")
	if got := nodesGPUNodesFrom(t, c); len(got) != 0 {
		t.Fatalf("CPU-only fleet published %v as GPU nodes", got)
	}
}

// Answering "GPU workloads planned" on a fleet with no device plugin is a
// contradiction the operator has to see — still INFO, because CPU-only is
// supported and this check never decides the verdict.
func TestNodesAcceleratorsNotesTheGPUAnswerWithNoDevicePlugin(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("n1")).
		withAnswers(func(a *intake.Answers) { a.GPU = true })
	r := run(t, f, "nodes.accelerators")
	assertStatus(t, r, "INFO")
	nodesAssertMentions(t, r, "device plugin")
}

// ---------------------------------------------------------------------------
// nodes.control-plane-label
// ---------------------------------------------------------------------------

// Every chart's preferred nodeAffinity (weight 75) matches this label. With it
// absent the preference matches nothing and platform pods land wherever there is
// room — including the GPU nodes meant for models.
func TestNodesControlPlaneLabelRisksWhenAbsent(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	r := run(t, f, "nodes.control-plane-label")
	assertStatus(t, r, "RISK")
	// "no node carries", not "the labelled node is unschedulable": the two
	// branches have different remedies and must not be collapsed.
	nodesAssertMentions(t, r, "no node carries", "bud.studio/control-plane", "kubectl label node")
}

// A label on a node nothing can schedule to resolves to the same nothing.
func TestNodesControlPlaneLabelRisksWhenTheLabelledNodeIsUnschedulable(t *testing.T) {
	f := vanilla().with("nodes", "",
		node("cp1", controlPlaneLabel, tainted),
		node("w1"))
	r := run(t, f, "nodes.control-plane-label")
	assertStatus(t, r, "RISK")
	nodesAssertMentions(t, r, "cp1", "not schedulable")
}

func TestNodesControlPlaneLabelPassesWhenLabelledAndSchedulable(t *testing.T) {
	f := vanilla().with("nodes", "", node("cp1", controlPlaneLabel), node("w1"))
	r := run(t, f, "nodes.control-plane-label")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("a preferred affinity is a hint; the pass must say so (G3)")
	}
}

func TestNodesControlPlaneLabelSkipsWithNoNodes(t *testing.T) {
	assertSkipHasReason(t, run(t, vanilla(), "nodes.control-plane-label"))
}

// ---------------------------------------------------------------------------
// Cluster unreachable — every check in the group, as a class
// ---------------------------------------------------------------------------

// D5: when the API server cannot be reached there is nothing to claim. Each of
// these must skip WITH a reason rather than pass on an empty node list, which is
// exactly what a naive len(nodes)==0 branch would do.
func TestNodesEveryCheckSkipsWithAReasonWhenClusterUnreachable(t *testing.T) {
	ids := []string{
		"nodes.ready", "nodes.count", "nodes.architecture", "nodes.tolerations",
		"nodes.capacity", "nodes.largest-pod", "nodes.imagefs",
		"nodes.eviction-pressure", "nodes.pod-slots", "nodes.accelerators",
		"nodes.control-plane-label",
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			f := vanilla().with("nodes", "", node("n1"))
			r := nodesRun(t, f, id, func(c *engine.Ctx) { c.Kube = nil })
			assertSkipHasReason(t, r)
		})
	}
}
