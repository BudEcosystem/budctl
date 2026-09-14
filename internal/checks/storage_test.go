package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// Storage is the group where "no specific provisioner is required" has to be
// true in the code and not just in the prose: OpenEBS is one implementation of
// the requirement, not the requirement.

func TestStorageDefaultClassBlocksWhenNoneMarkedDefault(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("fast", "ebs.csi.aws.com", false, true, nil),
		storageClass("slow", "ebs.csi.aws.com", false, true, nil))
	assertStatus(t, run(t, f, "storage.default-class"), "BLOCK")
}

func TestStorageDefaultClassPassesWithADefault(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("gp3", "ebs.csi.aws.com", true, true, nil))
	assertStatus(t, run(t, f, "storage.default-class"), "PASS")
}

// Any CSI driver satisfies the requirement. If this check only ever passed for
// OpenEBS it would reject every managed cluster.
func TestStorageDefaultClassAcceptsAnyProvisioner(t *testing.T) {
	for _, prov := range []string{
		"ebs.csi.aws.com",
		"disk.csi.azure.com",
		"pd.csi.storage.gke.io",
		"rancher.io/local-path",
		"openebs.io/local",
	} {
		f := vanilla().with("storageclasses.storage.k8s.io", "",
			storageClass("default", prov, true, true, nil))
		if got := run(t, f, "storage.default-class").Status(); got != "PASS" {
			t.Fatalf("provisioner %s: got %s, want PASS — no provisioner is privileged", prov, got)
		}
	}
}

// Model weights and ClickHouse parts both grow. Without expansion a full volume
// can only be fixed by recreating it, which on this platform means data loss.
func TestStorageExpansionRisksWhenDisabled(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("fixed", "ebs.csi.aws.com", true, false, nil))
	assertStatus(t, run(t, f, "storage.expansion"), "RISK")
}

func TestStorageExpansionPassesWhenEnabled(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("growable", "ebs.csi.aws.com", true, true, nil))
	assertStatus(t, run(t, f, "storage.expansion"), "PASS")
}

// host-prereqs must read the StorageClass PARAMETERS generically. Keying off the
// provisioner name would miss every driver budctl has not heard of, which is the
// failure mode this check exists to avoid. With no published capacity there is
// nothing to confirm the volume group with, so it stays a RISK.
func TestStorageHostPrereqsRisksOnVolumeGroupParameter(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("openebs-lvm", "local.csi.openebs.io", true, true,
			map[string]any{"volgroup": "vg1", "fsType": "ext4"}))
	assertStatus(t, run(t, f, "storage.host-prereqs"), "RISK")
}

// The same parameter on an unrelated provisioner must fire identically — proof
// the check reads parameters, not a hardcoded provisioner list.
func TestStorageHostPrereqsIsProvisionerAgnostic(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("vendor-lvm", "vendor.example.com/lvm", true, true,
			map[string]any{"volgroup": "datavg"}))
	assertStatus(t, run(t, f, "storage.host-prereqs"), "RISK")
}

// A values file naming a class the cluster does not have is the exact shape of
// a real misconfiguration: the PVC is created, stays Pending forever, and the
// Application never reports Healthy.
func TestStorageNamedClassesBlocksWhenNamedClassAbsent(t *testing.T) {
	dir := t.TempDir()
	vals := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(vals, []byte(
		"storage:\n  budmodelRegistry:\n    className: \"nonexistent-class\"\n    size: 60Gi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := vanilla().
		with("storageclasses.storage.k8s.io", "",
			storageClass("gp3", "ebs.csi.aws.com", true, true, nil)).
		withOpts(func(o *engine.Options) { o.ValuesFiles = []string{vals} })
	assertStatus(t, run(t, f, "storage.named-classes"), "BLOCK")
}

func TestStorageNamedClassesPassesWhenClassExists(t *testing.T) {
	dir := t.TempDir()
	vals := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(vals, []byte(
		"storage:\n  budmodelRegistry:\n    className: \"gp3\"\n    size: 60Gi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := vanilla().
		with("storageclasses.storage.k8s.io", "",
			storageClass("gp3", "ebs.csi.aws.com", true, true, nil)).
		withOpts(func(o *engine.Options) { o.ValuesFiles = []string{vals} })
	assertStatus(t, run(t, f, "storage.named-classes"), "PASS")
}

// The class names come from the values, so with no render there is nothing to
// compare and the check must say so rather than pass.
func TestStorageNamedClassesSkipsWithoutRender(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("gp3", "ebs.csi.aws.com", true, true, nil))
	r := run(t, f, "storage.named-classes")
	if r.Status() == "BLOCK" || r.Status() == "RISK" {
		recordFailureCoverage(r.ID, r.Status())
		return
	}
	assertSkipHasReason(t, r)
}

// With no capacity source the honest answer is "unverified" — a silent PASS here
// would claim the cluster can hold hundreds of GiB nobody measured.
func TestStorageCapacityRisksWhenUnverifiable(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("gp3", "ebs.csi.aws.com", true, true, nil))
	r := run(t, f, "storage.capacity")
	if r.Status() != "RISK" && r.Status() != "SKIP" {
		t.Fatalf("storage.capacity: got %s, want RISK or SKIP when no capacity source exists — never a silent PASS (summary: %s)", r.Status(), r.Summary)
	}
	recordFailureCoverage(r.ID, "RISK")
}

// The provisioning probe is the authoritative check in this group, so its
// --no-probe path must state plainly that provisioning was not confirmed.
func TestStorageProvisionSkipsUnderNoProbe(t *testing.T) {
	f := vanilla().withOpts(func(o *engine.Options) { o.NoProbe = true })
	assertSkipHasReason(t, run(t, f, "storage.provision"))
}

// storageCapacityObj builds a CSIStorageCapacity for one topology segment.
func storageCapacityObj(name, class, node, capacity string) adapters.Object {
	return adapters.Object{
		"apiVersion": "storage.k8s.io/v1", "kind": "CSIStorageCapacity",
		"metadata":         map[string]any{"name": name, "namespace": "kube-system"},
		"storageClassName": class,
		"capacity":         capacity,
		"nodeTopology": map[string]any{
			"matchLabels": map[string]any{"kubernetes.io/hostname": node},
		},
	}
}

func storageCapacityCluster(model int, caps ...adapters.Object) *fakeCluster {
	f := vanilla().
		with("storageclasses.storage.k8s.io", "",
			storageClass("openebs-lvm", "local.csi.openebs.io", true, true, nil)).
		with("csistoragecapacities.storage.k8s.io", "", caps...).
		withAnswers(func(a *intake.Answers) {
			a.ModelStorageGi = model
			a.InClusterData = false // isolate the model claim from the addon total
			a.RetentionDays = 0
		})
	f.apiGroups["csistoragecapacities.storage.k8s.io"] = true
	return f
}

// The failure this guards against: a node-local StorageClass whose segments SUM
// to plenty while no single node can hold the model registry. A check that
// judged only the total would pass a cluster where that one PVC never binds —
// the same shape as nodes.largest-pod, and the reason budctl reports a
// per-volume ceiling at all.
func TestStorageCapacityBlocksWhenNoSingleSegmentFitsTheClaim(t *testing.T) {
	f := storageCapacityCluster(1800,
		storageCapacityObj("c0", "openebs-lvm", "n0", "530424Mi"),
		storageCapacityObj("c1", "openebs-lvm", "n1", "281592Mi"),
		storageCapacityObj("c2", "openebs-lvm", "n2", "351224Mi"),
		storageCapacityObj("c3", "openebs-lvm", "n3", "1377272Mi"),
	)
	r := run(t, f, "storage.capacity")
	assertStatus(t, r, "BLOCK")
	if !strings.Contains(r.Summary, "largest single volume") {
		t.Fatalf("blocked for the wrong reason: %s", r.Summary)
	}
}

// The same fleet holds a claim that fits the biggest node.
func TestStorageCapacityPassesWhenTheLargestSegmentFits(t *testing.T) {
	f := storageCapacityCluster(300,
		storageCapacityObj("c0", "openebs-lvm", "n0", "530424Mi"),
		storageCapacityObj("c1", "openebs-lvm", "n1", "281592Mi"),
		storageCapacityObj("c3", "openebs-lvm", "n3", "1377272Mi"),
	)
	assertStatus(t, run(t, f, "storage.capacity"), "PASS")
}

// One segment means one pool: the ceiling is the whole capacity, and a claim
// that fits it must not be blocked by the multi-segment reasoning.
func TestStorageCapacitySingleSegmentIsNotTreatedAsFragmented(t *testing.T) {
	f := storageCapacityCluster(400,
		storageCapacityObj("only", "openebs-lvm", "n0", "800Gi"),
	)
	assertStatus(t, run(t, f, "storage.capacity"), "PASS")
}

// hostPrereqCluster is a class whose parameters name host state, with nodes and
// whatever capacity the driver publishes for them.
func hostPrereqCluster(capacityNodes []string, nodes ...string) *fakeCluster {
	objs := make([]adapters.Object, 0, len(nodes))
	for _, n := range nodes {
		objs = append(objs, node(n))
	}
	f := vanilla().
		with("nodes", "", objs...).
		with("storageclasses.storage.k8s.io", "",
			storageClass("openebs-lvm", "local.csi.openebs.io", true, true,
				map[string]any{"volgroup": "vg1", "fsType": "ext4"}))
	caps := make([]adapters.Object, 0, len(capacityNodes))
	for i, n := range capacityNodes {
		caps = append(caps, storageCapacityObj(fmt.Sprintf("c%d", i), "openebs-lvm", n, "530424Mi"))
	}
	f = f.with("csistoragecapacities.storage.k8s.io", "", caps...)
	f.apiGroups["csistoragecapacities.storage.k8s.io"] = true
	return f
}

// The complaint this answers: on a cluster that is visibly running, "vg1 must
// exist" was reported as a risk although the driver was already publishing
// capacity from every node — which it can only read from a host that has the
// volume group. Evidence the API does hold must be used before declaring
// something unverifiable.
func TestStorageHostPrereqsPassesWhenTheDriverPublishesCapacityFromEveryNode(t *testing.T) {
	f := hostPrereqCluster([]string{"n0", "n1"}, "n0", "n1")
	r := run(t, f, "storage.host-prereqs")
	assertStatus(t, r, "PASS")
	// The pass must not overclaim: capacity speaks for the volume group, never
	// for the filesystem tooling.
	if r.DoesNotProve == "" {
		t.Fatal("host-prereqs passed on published capacity without stating what that does not prove")
	}
}

// A node the driver publishes nothing for is the real finding, and it is
// node-specific: every claim binds until a pod lands there.
func TestStorageHostPrereqsRisksOnTheNodeMissingFromPublishedCapacity(t *testing.T) {
	f := hostPrereqCluster([]string{"n0"}, "n0", "n1")
	r := run(t, f, "storage.host-prereqs")
	assertStatus(t, r, "RISK")
	if !strings.Contains(strings.Join(append(r.Detail, r.Summary, r.Remedy), "\n"), "n1") {
		t.Fatalf("the risk does not name the node without the pool: %s / %v", r.Summary, r.Detail)
	}
}

// A tainted node cannot host a Bud pod, so its absence from the capacity map is
// not a finding — counting it would make an intentionally reserved node look
// like a broken one.
func TestStorageHostPrereqsIgnoresNodesNothingCanScheduleOn(t *testing.T) {
	f := hostPrereqCluster([]string{"n0"}, "n0")
	f = f.with("nodes", "", node("reserved", func(o adapters.Object) {
		o["spec"] = map[string]any{"taints": []any{
			map[string]any{"key": "dedicated", "value": "db", "effect": "NoSchedule"},
		}}
	}))
	assertStatus(t, run(t, f, "storage.host-prereqs"), "PASS")
}

// A summed total hides where a single claim can actually land. On node-local
// storage the answer is usually one node, and an operator reading "2.4 TiB
// free" has no way to know that from the sum.
func TestStorageCapacitySaysHowManySegmentsCanHoldTheClaim(t *testing.T) {
	f := storageCapacityCluster(800,
		storageCapacityObj("c0", "openebs-lvm", "n0", "1376248Mi"), // 1.3 TiB: fits
		storageCapacityObj("c1", "openebs-lvm", "n1", "530424Mi"),  // 518 GiB: does not
		storageCapacityObj("c2", "openebs-lvm", "n2", "351224Mi"),  // 343 GiB: does not
	)
	r := run(t, f, "storage.capacity")
	assertStatus(t, r, "PASS")
	detail := strings.Join(r.Detail, "\n")
	if !strings.Contains(detail, "exactly one of the 3 segments") {
		t.Errorf("the pass does not say the claim fits on only one node:\n%s", detail)
	}

	// With room on two nodes it must say two, not "exactly one" — the sentence
	// has to track the data rather than always warn.
	f = storageCapacityCluster(300,
		storageCapacityObj("c0", "openebs-lvm", "n0", "1376248Mi"),
		storageCapacityObj("c1", "openebs-lvm", "n1", "530424Mi"),
		storageCapacityObj("c2", "openebs-lvm", "n2", "51224Mi"),
	)
	r = run(t, f, "storage.capacity")
	assertStatus(t, r, "PASS")
	if d := strings.Join(r.Detail, "\n"); !strings.Contains(d, "2 of the 3 segments") {
		t.Errorf("the pass does not count the segments that fit:\n%s", d)
	}
}

// --- storage.shared-rwo / storage.rwx ----------------------------------------

// storageRunRendered runs one check against a fake cluster plus a rendered
// chart, which is where access modes and mount lists come from.
func storageRunRendered(t *testing.T, f *fakeCluster, id string, objs ...adapters.Object) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	c.Set(engine.KeyRenderedObjects, objs)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

func storagePVC(name, class string, modes ...string) adapters.Object {
	ms := make([]any, 0, len(modes))
	for _, m := range modes {
		ms = append(ms, m)
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "PersistentVolumeClaim",
		"metadata": map[string]any{"name": name, "namespace": "bud"},
		"spec":     map[string]any{"storageClassName": class, "accessModes": ms},
	}
}

func storageDeploymentMounting(name string, claims ...string) adapters.Object {
	vols := make([]any, 0, len(claims))
	for _, c := range claims {
		vols = append(vols, map[string]any{
			"name":                  c,
			"persistentVolumeClaim": map[string]any{"claimName": c},
		})
	}
	return adapters.Object{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": "bud"},
		"spec": map[string]any{"template": map[string]any{
			"spec": map[string]any{"volumes": vols},
		}},
	}
}

// The shape this exists for, taken from the bud chart itself: one
// ReadWriteOnce models-registry claim mounted by budmodel, budcluster and
// budsim. It is legal and it binds — and it silently ties three independent
// deployments to one node.
func TestStorageSharedRWORisksWhenOneClaimIsMountedByManyWorkloads(t *testing.T) {
	r := storageRunRendered(t, vanilla(), "storage.shared-rwo",
		storagePVC("bud-models-registry", "openebs-lvm", "ReadWriteOnce"),
		storageDeploymentMounting("budmodel", "bud-models-registry"),
		storageDeploymentMounting("budcluster", "bud-models-registry"),
		storageDeploymentMounting("budsim", "bud-models-registry"))
	assertStatus(t, r, "RISK")
	detail := strings.Join(append(r.Detail, r.Summary), "\n")
	for _, want := range []string{"bud-models-registry", "budmodel", "budcluster", "budsim"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the finding does not name %q:\n%s", want, detail)
		}
	}
}

// One workload mounting its own claim is the normal case, and ReadWriteMany is
// shared by design. Neither may be reported.
func TestStorageSharedRWOPassesOnUnsharedAndRWXClaims(t *testing.T) {
	r := storageRunRendered(t, vanilla(), "storage.shared-rwo",
		storagePVC("private", "openebs-lvm", "ReadWriteOnce"),
		storagePVC("shared", "nfs-sc", "ReadWriteMany"),
		storageDeploymentMounting("budapp", "private"),
		storageDeploymentMounting("a", "shared"),
		storageDeploymentMounting("b", "shared"))
	assertStatus(t, r, "PASS")
}

// The natural fix for a shared ReadWriteOnce claim is ReadWriteMany — which
// fails silently on a block or node-local driver, so it has to be caught here.
func TestStorageRWXBlocksWhenTheClassCannotServeIt(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("openebs-lvm", "local.csi.openebs.io", true, true, nil))
	r := storageRunRendered(t, f, "storage.rwx",
		storagePVC("bud-models-registry", "openebs-lvm", "ReadWriteMany"))
	assertStatus(t, r, "BLOCK")
	if !strings.Contains(strings.Join(r.Detail, "\n"), "openebs-lvm") {
		t.Errorf("the blocker does not name the class: %v", r.Detail)
	}
}

func TestStorageRWXPassesOnAFileBasedClass(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("nfs-sc", "nfs.csi.k8s.io", true, true, nil))
	r := storageRunRendered(t, f, "storage.rwx",
		storagePVC("shared", "nfs-sc", "ReadWriteMany"))
	assertStatus(t, r, "PASS")
}

// An unrecognised driver is unverified, never approved: the API exposes no
// "supports ReadWriteMany" field, and guessing either way is a false answer.
func TestStorageRWXSkipsOnADriverItCannotClassify(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("vendor-sc", "vendor.example.com/storage", true, true, nil))
	r := storageRunRendered(t, f, "storage.rwx",
		storagePVC("shared", "vendor-sc", "ReadWriteMany"))
	assertSkipHasReason(t, r)
}

func TestStorageRWXPassesWhenTheChartAsksForNoRWX(t *testing.T) {
	f := vanilla().with("storageclasses.storage.k8s.io", "",
		storageClass("openebs-lvm", "local.csi.openebs.io", true, true, nil))
	r := storageRunRendered(t, f, "storage.rwx",
		storagePVC("private", "openebs-lvm", "ReadWriteOnce"))
	assertStatus(t, r, "PASS")
}
