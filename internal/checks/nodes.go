package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The nodes group answers "will the pods this install creates actually land
// somewhere, and will the images they need fit on the disk when they do"
// (FRD-020 §5.6). Two of its findings come from a real cluster rather than from
// theory: a node with 46.7 GiB free that could not hold the ~55 GiB of images
// the platform pulls, and the fact that no chart in infra/charts/** declares a
// single toleration — so a fully tainted fleet schedules nothing and the only
// symptom is silent Pending.

const (
	// The kubelet's default hard eviction signal is imagefs.available<15%. A
	// node already under it is garbage-collecting images right now, so an
	// install that pulls tens of GiB thrashes instead of converging.
	nodesImageFsEvictionFraction = 0.15

	// Without a render the pod count is an estimate: each ApplicationSet
	// component averages about three pods (an operator, its workload, and a
	// DaemonSet or sidecar), and each concurrent deployment adds a runtime pod.
	nodesPodsPerComponent = 3

	// The label every chart's preferred nodeAffinity matches, at weight 75
	// (infra/charts/bud/values.yaml). Preferred, so its absence degrades
	// placement rather than blocking it.
	nodesControlPlaneLabel = "bud.studio/control-plane"

	// The images are published for linux/amd64 only, so this is the one
	// architecture a Bud pod can start on.
	nodesRequiredArch = "amd64"
)

// nodesAccelResources are the extended resources a device plugin advertises.
// MIG slices are matched by prefix because their names carry the profile
// (nvidia.com/mig-1g.5gb).
var nodesAccelResources = []string{"nvidia.com/gpu", "amd.com/gpu", "habana.ai/gaudi"}

func init() {
	engine.Register(&engine.Check{
		ID: "nodes.ready", Group: "nodes", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.ready")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: there is no node list to read")
			}
			nodes := nodesGather(ctx, c)
			if len(nodes) == 0 {
				return ch.Fail(
					"the API server reports no nodes at all, so nothing the ApplicationSet creates can ever run",
					"join at least one worker node to the cluster, then re-run")
			}

			var active, notReady, cordoned []string
			lines := make([]string, 0, len(nodes))
			for _, n := range nodes {
				lines = append(lines, n.evidenceLine())
				switch {
				case !n.Ready:
					notReady = append(notReady, n.Name)
				case n.Cordoned:
					cordoned = append(cordoned, n.Name)
				default:
					active = append(active, n.Name)
				}
			}
			ev := engine.Evidence{
				What:   fmt.Sprintf("Ready condition and spec.unschedulable on %d %s", len(nodes), Plural(len(nodes), "node", "nodes")),
				Output: strings.Join(lines, "\n"),
			}

			if len(active) == 0 {
				detail := []string{}
				if len(notReady) > 0 {
					detail = append(detail, "NotReady: "+strings.Join(Sorted(notReady), ", "))
				}
				if len(cordoned) > 0 {
					detail = append(detail, "cordoned: "+strings.Join(Sorted(cordoned), ", "))
				}
				return ch.Fail(
					fmt.Sprintf("no node is both Ready and uncordoned (%d NotReady, %d cordoned) — every pod the install creates stays Pending forever",
						len(notReady), len(cordoned)),
					"recover the kubelets (systemctl status kubelet on each node) and uncordon what was drained, before installing anything",
					detail...,
				).WithEvidence(ev)
			}
			if len(notReady)+len(cordoned) > 0 {
				// The install can still proceed, so this is a capacity story
				// rather than a blocker: what is left has to carry the whole
				// platform, which nodes.capacity then measures.
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("%d of %d nodes are unavailable, so the install has to fit on the remaining %d",
						len(notReady)+len(cordoned), len(nodes), len(active)),
					"recover or uncordon the unavailable nodes, or confirm the remaining nodes carry the whole platform",
					"unavailable: "+strings.Join(Sorted(append(append([]string{}, notReady...), cordoned...)), ", "),
				).WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("all %d %s Ready and uncordoned", len(nodes), Plural(len(nodes), "node is", "nodes are"))).
				With("schedulable: " + strings.Join(Sorted(active), ", ")).
				WithEvidence(ev).
				Bounds("a Ready kubelet does not prove the node can pull images or has disk left for them — nodes.imagefs measures that separately")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.count", Group: "nodes", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.count")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: there is no node list to read")
			}
			nodes := nodesGather(ctx, c)
			active := nodesFilter(nodes, func(n nodeFacts) bool { return n.Active() })
			quorum := []string{
				"Kafka sets min.insync.replicas=2, so a single broker cannot acknowledge a write",
				"ClickHouse Keeper runs a 3-member quorum",
				"CloudNativePG runs 3 PostgreSQL instances",
			}

			if len(active) < c.Profile.MinNodes {
				return ch.Fail(
					fmt.Sprintf("%d schedulable %s, below the minimum of %d — the ApplicationSet has nowhere to place its workloads",
						len(active), Plural(len(active), "node", "nodes"), c.Profile.MinNodes),
					fmt.Sprintf("bring at least %d node(s) Ready and uncordoned before installing", c.Profile.MinNodes))
			}
			if c.Answers.InClusterData && len(active) < c.Profile.MinNodesWithAddons {
				// Pod anti-affinity and quorum sizes are what make three real:
				// three replicas on one node survive nothing and, where the
				// charts spread them, simply stay Pending.
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("%d schedulable %s for in-cluster data stores that expect %d — the stateful addons install without redundancy, and their quorum members compete for one machine",
						len(active), Plural(len(active), "node", "nodes"), c.Profile.MinNodesWithAddons),
					fmt.Sprintf("add nodes to reach %d, or answer 'external' for the data stores and point the chart at managed PostgreSQL/ClickHouse/Kafka/MongoDB", c.Profile.MinNodesWithAddons),
					quorum...)
			}
			res := ch.Pass(fmt.Sprintf("%d schedulable %s", len(active), Plural(len(active), "node", "nodes")))
			if !c.Answers.InClusterData && len(active) < c.Profile.MinNodesWithAddons {
				res = res.With(fmt.Sprintf("the %d-node floor does not apply: the intake answers say the data stores are external, so no in-cluster quorum is installed", c.Profile.MinNodesWithAddons))
			}
			return res.With("counted: " + strings.Join(Sorted(nodesNames(active)), ", ")).
				Bounds("node count says nothing about the size of those nodes — nodes.capacity and nodes.largest-pod measure that")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.architecture", Group: "nodes", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.architecture")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: there is no node list to read")
			}
			nodes := nodesGather(ctx, c)
			if len(nodes) == 0 {
				return ch.Skip("the API server reports no nodes; nodes.ready states the consequence")
			}
			var amd64, foreign, unknown []string
			lines := make([]string, 0, len(nodes))
			for _, n := range nodes {
				lines = append(lines, fmt.Sprintf("node/%s status.nodeInfo.architecture=%s", n.Name, firstNonEmpty(n.Arch, "<unreported>")))
				switch n.Arch {
				case nodesRequiredArch:
					amd64 = append(amd64, n.Name)
				case "":
					unknown = append(unknown, n.Name)
				default:
					foreign = append(foreign, n.Name+" ("+n.Arch+")")
				}
			}
			ev := engine.Evidence{What: "architecture reported by each kubelet", Output: strings.Join(lines, "\n")}

			if len(amd64) == 0 && len(foreign) == 0 {
				// Every kubelet withheld nodeInfo.architecture and no node
				// carries kubernetes.io/arch. Claiming amd64 here would turn a
				// blind spot into a pass on the one thing that makes every
				// image unpullable.
				return ch.Skip("no node reports an architecture, in status.nodeInfo or in the kubernetes.io/arch label").WithEvidence(ev)
			}
			if len(amd64) == 0 && len(foreign) > 0 {
				return ch.Fail(
					fmt.Sprintf("no %s node exists — every Bud image is published for linux/%s only, so every pod ends in ImagePullBackOff 'no matching manifest'",
						nodesRequiredArch, nodesRequiredArch),
					fmt.Sprintf("install on %s nodes; there is no multi-arch image set to fall back to", nodesRequiredArch),
					"non-amd64: "+strings.Join(Sorted(foreign), ", "),
				).WithEvidence(ev)
			}
			if len(foreign) > 0 {
				// A mixed fleet is still a blocker: no Bud chart sets a
				// nodeSelector or arch affinity, so the scheduler is free to
				// place a pod on the foreign node and that pod never pulls.
				return ch.Fail(
					fmt.Sprintf("%d %s of a different architecture — no chart sets a kubernetes.io/arch nodeSelector, so whichever pods land there fail to pull",
						len(foreign), Plural(len(foreign), "node is", "nodes are")),
					fmt.Sprintf("taint the non-%s %s NoSchedule (or remove them from the pool) so the scheduler cannot place platform pods on them",
						nodesRequiredArch, Plural(len(foreign), "node", "nodes")),
					"non-amd64: "+strings.Join(Sorted(foreign), ", "),
				).WithEvidence(ev)
			}
			res := ch.Pass(fmt.Sprintf("all %d %s linux/%s", len(nodes), Plural(len(nodes), "node is", "nodes are"), nodesRequiredArch)).WithEvidence(ev)
			if len(unknown) > 0 {
				res = res.With("architecture unreported by: " + strings.Join(Sorted(unknown), ", "))
			}
			return res
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.tolerations", Group: "nodes", Severity: engine.Block,
		// Branches on the distribution: the remedy for an all-tainted fleet is
		// completely different on OpenShift, where the control plane keeps its
		// taint by design and the answer is a worker MachineSet.
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.tolerations")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: there is no node list to read")
			}
			nodes := nodesGather(ctx, c)
			active := nodesFilter(nodes, func(n nodeFacts) bool { return n.Active() })
			if len(active) == 0 {
				return ch.Skip("no Ready, uncordoned node to inspect for taints; nodes.ready reports why")
			}
			var open, fenced []string
			lines := make([]string, 0, len(active))
			for _, n := range active {
				if len(n.Taints) == 0 {
					open = append(open, n.Name)
					lines = append(lines, "node/"+n.Name+" taints: none")
					continue
				}
				fenced = append(fenced, n.Name)
				lines = append(lines, "node/"+n.Name+" taints: "+strings.Join(n.Taints, " "))
			}
			ev := engine.Evidence{What: "spec.taints with effect NoSchedule or NoExecute on every Ready node", Output: strings.Join(lines, "\n")}

			if len(open) == 0 {
				remedy := "untaint at least one node (kubectl taint node <name> <key>-), or add an untainted worker — adding tolerations to the charts is not an option today, none are templated"
				if c.Platform.IsOpenShift() {
					remedy = "add a worker MachineSet: OpenShift control-plane nodes keep node-role.kubernetes.io/master:NoSchedule and no Bud chart tolerates it (on single-node OpenShift, remove that taint from the one node instead)"
				}
				return ch.Fail(
					fmt.Sprintf("every one of the %d Ready nodes carries a NoSchedule/NoExecute taint, and no chart in infra/charts declares a single toleration — every pod stays Pending with no event that explains it",
						len(active)),
					remedy,
					"tainted: "+strings.Join(Sorted(fenced), ", "),
				).WithEvidence(ev)
			}
			res := ch.Pass(fmt.Sprintf("%d of %d Ready %s schedulable without a toleration", len(open), len(active), Plural(len(active), "node is", "nodes are"))).
				WithEvidence(ev).
				Bounds("it does not prove the untainted nodes have room — that is nodes.capacity — nor that a PodSecurity or SCC policy will admit the pods")
			if len(fenced) > 0 {
				res = res.With(
					"tainted and therefore unusable by this install: "+strings.Join(Sorted(fenced), ", "),
					"their CPU and memory are excluded from nodes.capacity for the same reason")
			}
			return res
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.capacity", Group: "nodes", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.capacity")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: allocatable and committed requests cannot be read")
			}
			usable := nodesFilter(nodesGather(ctx, c), func(n nodeFacts) bool { return n.Usable() })
			if len(usable) == 0 {
				return ch.Skip("no Ready, uncordoned, untainted node to measure; nodes.ready and nodes.tolerations report why")
			}
			committed := nodesCommitments(ctx, c)

			var allocCPU, allocMem, usedCPU, usedMem float64
			lines := make([]string, 0, len(usable)+3)
			for _, n := range usable {
				cm := committed[n.Name]
				allocCPU += n.CPU
				allocMem += n.Mem
				usedCPU += cm.CPU
				usedMem += cm.Mem
				lines = append(lines, fmt.Sprintf("node/%s allocatable %.1f cores / %s − requested %.1f cores / %s = free %.1f cores / %s",
					n.Name, n.CPU, HumanBytes(n.Mem), cm.CPU, HumanBytes(cm.Mem), n.CPU-cm.CPU, HumanBytes(n.Mem-cm.Mem)))
			}
			freeCPU, freeMem := allocCPU-usedCPU, allocMem-usedMem

			scale := nodesCapacityScale(c.Answers)
			reqCPU := c.Profile.BaseCPUCores * scale
			reqMem := nodesGiBytes(c.Profile.BaseMemoryGi * scale)
			lines = append(lines,
				fmt.Sprintf("cluster free: %.1f cores / %s", freeCPU, HumanBytes(freeMem)),
				fmt.Sprintf("required: %.1f cores / %s  (profile base %.1f cores / %.0f GiB × %.2f for %d concurrent %s)",
					reqCPU, HumanBytes(reqMem), c.Profile.BaseCPUCores, c.Profile.BaseMemoryGi, scale,
					c.Answers.Deployments, Plural(c.Answers.Deployments, "deployment", "deployments")))
			ev := engine.Evidence{
				What:   "allocatable (not capacity — capacity includes what the kubelet and system reserve) minus pod requests across all namespaces",
				Output: strings.Join(lines, "\n"),
			}

			short := []string{}
			if freeCPU < reqCPU {
				short = append(short, fmt.Sprintf("%.1f cores short", reqCPU-freeCPU))
			}
			if freeMem < reqMem {
				short = append(short, fmt.Sprintf("%s short of memory", HumanBytes(reqMem-freeMem)))
			}
			capGauges := []engine.Gauge{
				{Label: "CPU", Have: freeCPU, Need: reqCPU, Unit: "cores"},
				{Label: "memory", Have: freeMem, Need: reqMem, Unit: "bytes"},
			}
			if len(short) > 0 {
				return ch.Fail(
					fmt.Sprintf("the schedulable nodes are %s — the platform's own pods cannot all be placed and the last ones stay Pending with Insufficient cpu/memory",
						strings.Join(short, " and ")),
					fmt.Sprintf("add capacity to reach %.1f free cores and %s free, or lower the concurrent-deployment answer and re-run",
						reqCPU, HumanBytes(reqMem)),
					fmt.Sprintf("free now: %.1f cores / %s across %d %s", freeCPU, HumanBytes(freeMem), len(usable), Plural(len(usable), "node", "nodes")),
				).WithEvidence(ev).WithGauges(capGauges...)
			}
			return ch.Pass(fmt.Sprintf("%.1f cores and %s free against a requirement of %.1f cores and %s",
				freeCPU, HumanBytes(freeMem), reqCPU, HumanBytes(reqMem))).
				WithEvidence(ev).WithGauges(capGauges...).
				Bounds("totals only: it does not prove any single pod fits on a single node (nodes.largest-pod), and it excludes the model runtime pods themselves, which budsim sizes at deploy time and which are far larger than the platform")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.largest-pod", Group: "nodes", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.largest-pod")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: allocatable and committed requests cannot be read")
			}
			usable := nodesFilter(nodesGather(ctx, c), func(n nodeFacts) bool { return n.Usable() })
			if len(usable) == 0 {
				return ch.Skip("no Ready, uncordoned, untainted node to measure; nodes.ready and nodes.tolerations report why")
			}
			committed := nodesCommitments(ctx, c)
			name, needCPU, needMem, source := nodesLargestPod(c)

			var fits []string
			var bestMem float64
			lines := make([]string, 0, len(usable)+1)
			for _, n := range usable {
				cm := committed[n.Name]
				fCPU, fMem := n.CPU-cm.CPU, n.Mem-cm.Mem
				if fMem > bestMem {
					bestMem = fMem
				}
				ok := fMem >= needMem && fCPU >= needCPU
				if ok {
					fits = append(fits, n.Name)
				}
				lines = append(lines, fmt.Sprintf("node/%s free %.1f cores / %s → fits: %t", n.Name, fCPU, HumanBytes(fMem), ok))
			}
			lines = append(lines, fmt.Sprintf("largest single pod: %s requests %.1f cores / %s (%s)", name, needCPU, HumanBytes(needMem), source))
			ev := engine.Evidence{
				What:   "per-node free allocatable against the largest single pod request",
				Output: strings.Join(lines, "\n"),
			}

			if len(fits) == 0 {
				return ch.Fail(
					fmt.Sprintf("no single node has room for %s (%s, %.1f cores) — the best node offers %s, and Kubernetes never splits a pod across nodes, so it stays Pending however large the cluster total is",
						name, HumanBytes(needMem), needCPU, HumanBytes(bestMem)),
					fmt.Sprintf("add a node with at least %s allocatable free, or free that much on an existing one — spreading the same total over more small nodes does not help",
						HumanBytes(needMem)),
					"budsentinel is the next largest at 4Gi; a node that clears "+HumanBytes(needMem)+" clears both",
				).WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("%d of %d nodes can hold %s (%s, %.1f cores)",
				len(fits), len(usable), name, HumanBytes(needMem), needCPU)).
				With("fits on: " + strings.Join(Sorted(fits), ", ")).
				WithEvidence(ev).
				Bounds("it does not prove the scheduler will choose that node: anti-affinity, topology spread and the model runtime pods competing for the same node can still leave a pod Pending")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.imagefs", Group: "nodes", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.imagefs")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the kubelet stats endpoint is proxied through the API server")
			}
			active := nodesFilter(nodesGather(ctx, c), func(n nodeFacts) bool { return n.Active() })
			if len(active) == 0 {
				return ch.Skip("no Ready, uncordoned node whose image filesystem could be measured; nodes.ready reports why")
			}
			floor := Gi(c.Profile.ImageFsGi)

			var short, ok, unreadable []string
			var gauges []engine.Gauge
			lines := make([]string, 0, len(active))
			for _, n := range active {
				// allocatable ephemeral-storage does not describe the image
				// store, so the kubelet's own /stats/summary is the only source.
				st := c.Kube.NodeStats(ctx, n.Name)
				if st.Err != "" {
					unreadable = append(unreadable, n.Name+": "+nodesTrimErr(st.Err))
					lines = append(lines, "node/"+n.Name+" stats/summary error: "+nodesTrimErr(st.Err))
					continue
				}
				avail := float64(st.ImageFsAvailable)
				gauges = append(gauges, engine.Gauge{Label: n.Name, Have: avail, Need: floor, Unit: "bytes"})
				lines = append(lines, fmt.Sprintf("node/%s imageFs available %s of %s (used %s)",
					n.Name, HumanBytes(avail), HumanBytes(float64(st.ImageFsCapacity)), HumanBytes(float64(st.ImageFsUsed))))
				if avail < floor {
					short = append(short, fmt.Sprintf("%s has %s free", n.Name, HumanBytes(avail)))
				} else {
					ok = append(ok, n.Name)
				}
			}
			ev := engine.Evidence{
				What:   "kubelet /stats/summary node.runtime.imageFs.availableBytes, via the API server node proxy",
				Output: strings.Join(lines, "\n"),
			}

			if len(short) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d %s below the %d GiB image-filesystem floor (%s) — the 14 first-party images at 1.2.8 are 19.8 GiB compressed and extract to roughly 40 GiB, and with novu, otel and prometheus the platform pulls about 55 GiB, so the kubelet garbage-collects images it just pulled and pods flap in ImagePullBackOff",
						len(short), Plural(len(short), "node is", "nodes are"), c.Profile.ImageFsGi, strings.Join(Sorted(short), "; ")),
					fmt.Sprintf("grow the image filesystem (/var/lib/containerd or /var/lib/containers) to at least %d GiB free per node, or replace the node with one that has it",
						c.Profile.ImageFsGi),
				).WithEvidence(ev).WithGauges(gauges...)
			}
			if len(unreadable) > 0 {
				// A partial measurement is not a fleet-wide claim. Reporting it
				// as a pass is exactly the false assurance FRD-020 §4.1 forbids.
				return ch.Skip(fmt.Sprintf("%d of %d nodes could not be measured (%s), so the fleet cannot be declared clear",
					len(unreadable), len(active), strings.Join(Sorted(unreadable), "; "))).
					With("measured and above the floor: " + strings.Join(Sorted(ok), ", ")).
					WithEvidence(ev).WithGauges(gauges...)
			}
			return ch.Pass(fmt.Sprintf("all %d %s at least %d GiB free on the image filesystem",
				len(ok), Plural(len(ok), "node has", "nodes have"), c.Profile.ImageFsGi)).
				WithEvidence(ev).WithGauges(gauges...).
				Bounds("it does not cover the model runtime images (bud-runtime-cuda/cpu/hpu), which land on whichever node runs a model and are substantially larger than the platform's own images")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.eviction-pressure", Group: "nodes", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.eviction-pressure")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the kubelet stats endpoint is proxied through the API server")
			}
			active := nodesFilter(nodesGather(ctx, c), func(n nodeFacts) bool { return n.Active() })
			if len(active) == 0 {
				return ch.Skip("no Ready, uncordoned node to inspect; nodes.ready reports why")
			}

			var pressured, measured, unreadable []string
			lines := make([]string, 0, len(active))
			for _, n := range active {
				if n.DiskPressure {
					pressured = append(pressured, n.Name+" (kubelet condition DiskPressure=True)")
				}
				st := c.Kube.NodeStats(ctx, n.Name)
				if st.Err != "" {
					unreadable = append(unreadable, n.Name+": "+nodesTrimErr(st.Err))
					continue
				}
				measured = append(measured, n.Name)
				if st.ImageFsCapacity == 0 {
					continue
				}
				frac := float64(st.ImageFsAvailable) / float64(st.ImageFsCapacity)
				lines = append(lines, fmt.Sprintf("node/%s imageFs %.1f%% free (%s of %s), DiskPressure=%t",
					n.Name, frac*100, HumanBytes(float64(st.ImageFsAvailable)), HumanBytes(float64(st.ImageFsCapacity)), n.DiskPressure))
				if frac < nodesImageFsEvictionFraction {
					pressured = append(pressured, fmt.Sprintf("%s (%.1f%% free)", n.Name, frac*100))
				}
			}
			ev := engine.Evidence{
				What:   fmt.Sprintf("imageFs available/capacity against the kubelet default eviction signal imagefs.available<%.0f%%, plus the DiskPressure condition", nodesImageFsEvictionFraction*100),
				Output: strings.Join(lines, "\n"),
			}

			if len(pressured) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d %s already inside the kubelet's imagefs eviction band (%s) — the node is garbage-collecting images as we speak, so the install's pulls will evict each other and pods may be killed mid-rollout",
						len(pressured), Plural(len(pressured), "node is", "nodes are"), strings.Join(Sorted(pressured), "; ")),
					"free disk on those nodes before installing: prune unused images (crictl rmi --prune) or grow the filesystem; a node at the eviction threshold does not recover by itself under install load")
			}
			if len(measured) == 0 {
				return ch.Skip("kubelet /stats/summary was not readable on any node (" + strings.Join(Sorted(unreadable), "; ") + ")")
			}
			res := ch.Pass(fmt.Sprintf("no node is under the imagefs.available<%.0f%% eviction threshold", nodesImageFsEvictionFraction*100)).WithEvidence(ev)
			if len(unreadable) > 0 {
				res = res.With("not measured: " + strings.Join(Sorted(unreadable), "; "))
			}
			return res.Bounds("it reads the image filesystem only: memory.available and nodefs.inodesFree can still trigger eviction, and a node just above the threshold crosses it as soon as the install starts pulling")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.pod-slots", Group: "nodes", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.pod-slots")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: allocatable pods and running pods cannot be counted")
			}
			usable := nodesFilter(nodesGather(ctx, c), func(n nodeFacts) bool { return n.Usable() })
			if len(usable) == 0 {
				return ch.Skip("no Ready, uncordoned, untainted node to count slots on; nodes.ready and nodes.tolerations report why")
			}
			committed := nodesCommitments(ctx, c)

			var slots, used float64
			lines := make([]string, 0, len(usable)+2)
			for _, n := range usable {
				if n.PodSlots == 0 {
					continue
				}
				slots += n.PodSlots
				used += committed[n.Name].Pods
				lines = append(lines, fmt.Sprintf("node/%s allocatable pods %.0f, running %.0f, free %.0f",
					n.Name, n.PodSlots, committed[n.Name].Pods, n.PodSlots-committed[n.Name].Pods))
			}
			if slots == 0 {
				return ch.Skip("no node reports allocatable.pods, so the kubelet max-pods ceiling is unknown")
			}
			free := slots - used
			expected, source := nodesExpectedPods(c, len(usable))
			lines = append(lines,
				fmt.Sprintf("free slots: %.0f of %.0f", free, slots),
				fmt.Sprintf("expected new pods: %d (%s)", expected, source))
			ev := engine.Evidence{
				What:   "allocatable.pods per node (the kubelet max-pods ceiling) minus pods already scheduled there",
				Output: strings.Join(lines, "\n"),
			}

			if free < float64(expected) {
				return ch.Fail(
					fmt.Sprintf("only %.0f pod slots free across %d schedulable %s but the install needs about %d — the pods that do not fit stay Pending with 'Too many pods', which reads like a capacity problem and is not one",
						free, len(usable), Plural(len(usable), "node", "nodes"), expected),
					"raise the kubelet --max-pods (or the node pool's pods-per-node setting) on those nodes, or add a node; CPU and memory headroom does not help here",
				).WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("%.0f pod slots free against about %d expected", free, expected)).
				WithEvidence(ev).
				Bounds("the expected count is " + source + "; DaemonSets added later, model runtime pods and per-deployment sidecars each consume further slots")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.accelerators", Group: "nodes", Severity: engine.Info,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.accelerators")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the accelerator inventory cannot be read")
			}
			nodes := nodesGather(ctx, c)
			totals := map[string]float64{}
			gpuNodes := []string{}
			lines := []string{}
			for _, n := range nodes {
				if len(n.Accel) == 0 {
					continue
				}
				gpuNodes = append(gpuNodes, n.Name)
				parts := []string{}
				for res, q := range n.Accel {
					totals[res] += q
					parts = append(parts, fmt.Sprintf("%s=%.0f", res, q))
				}
				lines = append(lines, "node/"+n.Name+" allocatable "+strings.Join(Sorted(parts), " "))
			}
			// The gpu group keys off this. Set it on every path, including the
			// empty one, so a later Get distinguishes "no GPUs" from "nobody
			// looked". Allocatable, never capacity: a node whose device plugin
			// has died still reports capacity and would be counted as GPU-ready.
			gpuNodes = Sorted(gpuNodes)
			c.Set(engine.KeyGPUNodes, gpuNodes)

			if len(gpuNodes) == 0 {
				res := ch.Infof("no node advertises an accelerator; the platform runs CPU-only, which is supported")
				if c.Answers.GPU {
					res = res.With("the intake answers say GPU workloads are planned, but no nvidia.com/gpu, amd.com/gpu or habana.ai/gaudi resource is allocatable anywhere — install the vendor device plugin, or the gpu group will have nothing to exercise")
				}
				return res
			}
			summary := []string{}
			for res, q := range totals {
				summary = append(summary, fmt.Sprintf("%.0f×%s", q, res))
			}
			return ch.Infof("%d of %d nodes advertise accelerators: %s",
				len(gpuNodes), len(nodes), strings.Join(Sorted(summary), ", ")).
				With("GPU nodes: " + strings.Join(gpuNodes, ", ")).
				WithEvidence(engine.Evidence{
					What:   "status.allocatable accelerator resources per node (allocatable, not capacity: a node whose device plugin stopped still reports capacity)",
					Output: strings.Join(Sorted(lines), "\n"),
				}).
				Bounds("an advertised resource does not prove the driver loaded, the container toolkit is wired into the runtime, or the RuntimeClass resolves — gpu.operator-functional exercises that with a real pod")
		},
	})

	engine.Register(&engine.Check{
		ID: "nodes.control-plane-label", Group: "nodes", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("nodes.control-plane-label")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: node labels cannot be read")
			}
			nodes := nodesGather(ctx, c)
			if len(nodes) == 0 {
				return ch.Skip("the API server reports no nodes; nodes.ready states the consequence")
			}
			var labelled, schedulable []string
			for _, n := range nodes {
				if n.Labels[nodesControlPlaneLabel] != "true" {
					continue
				}
				labelled = append(labelled, n.Name)
				if n.Usable() {
					schedulable = append(schedulable, n.Name)
				}
			}
			remedy := fmt.Sprintf("label the node(s) that should host the platform: kubectl label node <name> %s=true", nodesControlPlaneLabel)

			if len(labelled) == 0 {
				return ch.Fail(
					fmt.Sprintf("no node carries %s=true, so every chart's preferred nodeAffinity (weight 75) matches nothing and platform pods land wherever there is room — including on GPU nodes meant for models",
						nodesControlPlaneLabel),
					remedy,
					"the affinity is preferred, not required, so the install still completes; placement is what degrades")
			}
			if len(schedulable) == 0 {
				return ch.Fail(
					fmt.Sprintf("the %s labelled %s=true %s not schedulable (NotReady, cordoned or tainted), so the placement preference resolves to nothing",
						Plural(len(labelled), "node", "nodes"), nodesControlPlaneLabel, Plural(len(labelled), "is", "are")),
					"recover or uncordon "+strings.Join(Sorted(labelled), ", ")+", or "+remedy,
					"labelled: "+strings.Join(Sorted(labelled), ", "))
			}
			return ch.Pass(fmt.Sprintf("%d schedulable %s labelled %s=true",
				len(schedulable), Plural(len(schedulable), "node", "nodes"), nodesControlPlaneLabel)).
				With("labelled: " + strings.Join(Sorted(schedulable), ", ")).
				Bounds("a preferred affinity is a hint: under pressure the scheduler still places platform pods elsewhere, and nothing keeps other workloads off these nodes")
		},
	})
}

// nodeFacts reduces a node to the handful of properties this group asks about,
// so nine checks share one interpretation of the same object instead of nine.
type nodeFacts struct {
	Name         string
	Ready        bool
	Cordoned     bool
	DiskPressure bool
	Arch         string
	// Taints holds only NoSchedule/NoExecute, rendered as key=value:Effect.
	// PreferNoSchedule is excluded: it costs placement, not schedulability.
	Taints   []string
	CPU      float64 // allocatable cores
	Mem      float64 // allocatable bytes
	PodSlots float64 // allocatable pods, i.e. the kubelet max-pods ceiling
	Accel    map[string]float64
	Labels   map[string]string
}

// Active is "the kubelet is alive and nobody drained it".
func (n nodeFacts) Active() bool { return n.Ready && !n.Cordoned }

// Usable is where a Bud pod could actually land. It subtracts tainted nodes on
// purpose: no chart in infra/charts/** declares a toleration, so a tainted
// node's cores are unreachable to this install and counting them would produce
// a green capacity check for a cluster that schedules nothing.
func (n nodeFacts) Usable() bool { return n.Active() && len(n.Taints) == 0 }

func (n nodeFacts) evidenceLine() string {
	taints := "none"
	if len(n.Taints) > 0 {
		taints = strings.Join(n.Taints, " ")
	}
	return fmt.Sprintf("node/%s Ready=%t cordoned=%t arch=%s taints=%s",
		n.Name, n.Ready, n.Cordoned, firstNonEmpty(n.Arch, "<unreported>"), taints)
}

func nodesGather(ctx context.Context, c *engine.Ctx) []nodeFacts {
	if c.Kube == nil {
		return nil
	}
	objs := c.Kube.List(ctx, "nodes", "")
	out := make([]nodeFacts, 0, len(objs))
	for _, o := range objs {
		f := nodeFacts{Name: o.Name(), Labels: o.Labels(), Accel: map[string]float64{}}
		if u, ok := o.Dig("spec", "unschedulable").(bool); ok {
			f.Cordoned = u
		}
		f.Arch = o.DigString("status", "nodeInfo", "architecture")
		if f.Arch == "" {
			f.Arch = f.Labels["kubernetes.io/arch"]
		}
		for _, raw := range o.DigSlice("status", "conditions") {
			cond, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := cond["type"].(string)
			status, _ := cond["status"].(string)
			switch typ {
			case "Ready":
				f.Ready = status == "True"
			case "DiskPressure":
				f.DiskPressure = status == "True"
			}
		}
		for _, raw := range o.DigSlice("spec", "taints") {
			t, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			effect, _ := t["effect"].(string)
			if effect != "NoSchedule" && effect != "NoExecute" {
				continue
			}
			key, _ := t["key"].(string)
			value, _ := t["value"].(string)
			f.Taints = append(f.Taints, key+"="+value+":"+effect)
		}
		// Allocatable, not capacity: capacity includes everything the kubelet
		// and the OS reserve, and the scheduler never gets to use it.
		if alloc, ok := o.Dig("status", "allocatable").(map[string]any); ok {
			f.CPU = QuantityOf(alloc, "cpu")
			f.Mem = QuantityOf(alloc, "memory")
			f.PodSlots = QuantityOf(alloc, "pods")
			f.Accel = nodesAcceleratorsOf(alloc)
		}
		out = append(out, f)
	}
	return out
}

func nodesAcceleratorsOf(alloc map[string]any) map[string]float64 {
	out := map[string]float64{}
	for k, v := range alloc {
		s, ok := v.(string)
		if !ok {
			continue
		}
		q := ParseQuantity(s)
		if q <= 0 {
			continue
		}
		if strings.HasPrefix(k, "nvidia.com/mig-") {
			out[k] = q
			continue
		}
		for _, known := range nodesAccelResources {
			if k == known {
				out[k] = q
			}
		}
	}
	return out
}

func nodesFilter(in []nodeFacts, keep func(nodeFacts) bool) []nodeFacts {
	out := make([]nodeFacts, 0, len(in))
	for _, n := range in {
		if keep(n) {
			out = append(out, n)
		}
	}
	return out
}

func nodesNames(in []nodeFacts) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, n.Name)
	}
	return out
}

// nodeCommitment is what the scheduler has already promised on one node.
// Requests, not usage: the scheduler places pods against requests, so a node
// idling at 5% CPU with everything requested is still full.
type nodeCommitment struct{ CPU, Mem, Pods float64 }

func nodesCommitments(ctx context.Context, c *engine.Ctx) map[string]nodeCommitment {
	out := map[string]nodeCommitment{}
	if c.Kube == nil {
		return out
	}
	// Namespace "" lists pods in every namespace: a check that only looked at
	// the install namespace would report a nearly empty cluster.
	for _, p := range c.Kube.List(ctx, "pods", "") {
		phase := p.DigString("status", "phase")
		if phase == "Succeeded" || phase == "Failed" {
			continue
		}
		node := p.DigString("spec", "nodeName")
		if node == "" {
			// Unscheduled: it holds nothing yet, and counting it against a node
			// we are about to size would double-charge the same request.
			continue
		}
		// Read spec directly rather than through Object.PodSpec(): list items
		// do not always carry a kind, and PodSpec() branches on it.
		spec, ok := p.Dig("spec").(map[string]any)
		if !ok {
			continue
		}
		cpu, mem := nodesPodRequests(spec)
		cur := out[node]
		cur.CPU += cpu
		cur.Mem += mem
		cur.Pods++
		out[node] = cur
	}
	return out
}

// nodesPodRequests sizes a pod the way the scheduler does: the sum of the app
// containers, or the largest init container if that is bigger (init containers
// run before the others, so their peak is what must fit), plus any declared
// pod overhead from the RuntimeClass.
func nodesPodRequests(spec map[string]any) (cpu, mem float64) {
	list := func(field string) []map[string]any {
		out := []map[string]any{}
		raw, ok := spec[field].([]any)
		if !ok {
			return out
		}
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	for _, ct := range list("containers") {
		cpu += QuantityOf(ct, "resources", "requests", "cpu")
		mem += QuantityOf(ct, "resources", "requests", "memory")
	}
	for _, ct := range list("initContainers") {
		if q := QuantityOf(ct, "resources", "requests", "cpu"); q > cpu {
			cpu = q
		}
		if q := QuantityOf(ct, "resources", "requests", "memory"); q > mem {
			mem = q
		}
	}
	if ov, ok := spec["overhead"].(map[string]any); ok {
		cpu += QuantityOf(ov, "cpu")
		mem += QuantityOf(ov, "memory")
	}
	return cpu, mem
}

// nodesCapacityScale turns the intake answer into a multiplier. The profile's
// base figures are measured for the platform at the default concurrency, and
// the deployment-facing surface (gateway, router, workflow engine, metrics
// ingest) grows with it. It never drops below 1: the fixed footprint — the
// datastores, admin and auth — does not shrink when fewer models will run.
func nodesCapacityScale(a intake.Answers) float64 {
	baseline := intake.Defaults().Deployments
	if baseline <= 0 {
		baseline = 1
	}
	if a.Deployments <= baseline {
		return 1
	}
	return float64(a.Deployments) / float64(baseline)
}

// nodesLargestPod is the biggest single pod this install will try to place.
// With --values the render is the ground truth (FRD-020 §7: the render beats
// both the form and the file); the config group runs after this one, so in the
// normal ordering Rendered() is nil and the profile floor — semantic-router's
// 6Gi/1 core — applies. The source is reported either way.
func nodesLargestPod(c *engine.Ctx) (name string, cpu, mem float64, source string) {
	found := false
	for _, o := range Rendered(c) {
		spec := o.PodSpec()
		if spec == nil {
			continue
		}
		rc, rm := nodesPodRequests(spec)
		if !found || rm > mem {
			name, cpu, mem, found = o.Kind()+"/"+o.Name(), rc, rm, true
		}
	}
	if found {
		return name, cpu, mem, "largest pod in the rendered chart"
	}
	return "semantic-router", c.Profile.LargestPodCPU, nodesGiBytes(c.Profile.LargestPodMemoryGi),
		"profile floor, no --values render available"
}

// nodesExpectedPods answers "how many pods is this install about to create".
func nodesExpectedPods(c *engine.Ctx, nodeCount int) (int, string) {
	total := 0
	for _, o := range Rendered(c) {
		if o.PodSpec() == nil {
			continue
		}
		switch o.Kind() {
		case "DaemonSet":
			total += nodeCount
		case "Deployment", "StatefulSet", "ReplicaSet":
			total += nodesReplicas(o)
		default:
			total++
		}
	}
	if total > 0 {
		return total, "counted from the rendered chart"
	}
	return nodesPodsPerComponent*len(c.Profile.AppsetComponents) + c.Answers.Deployments,
		fmt.Sprintf("an estimate of ~%d pods per ApplicationSet component plus one runtime pod per concurrent deployment; run with --values for the rendered count", nodesPodsPerComponent)
}

func nodesReplicas(o adapters.Object) int {
	switch v := o.Dig("spec", "replicas").(type) {
	case float64:
		return int(v)
	case int64:
		return int(v)
	case int:
		return v
	case string:
		return int(ParseQuantity(v))
	}
	return 1 // absent means the Kubernetes default of one
}

func nodesGiBytes(f float64) float64 { return f * (1 << 30) }

// nodesTrimErr keeps a kubelet proxy error to one readable line — these arrive
// as multi-line API machinery errors and a 403 is the fact that matters.
func nodesTrimErr(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}
