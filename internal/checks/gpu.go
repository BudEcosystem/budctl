package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The gpu group is the one place where budctl insists on doing rather than
// reading. A node label proves a label exists; allocatable capacity proves a
// plugin once registered. Neither proves the driver loaded, the container
// toolkit is wired into the runtime, or that a container actually receives a
// device — and a model deployment fails on any one of those. So the group ends
// in a functional probe (FRD-020 §5.12).
//
// Every check here reads the fleet itself rather than a value gpu.nodes left
// behind: checks inside one group run concurrently, so ordering between them is
// not guaranteed. The Kube adapter caches the node LIST, so the repetition
// costs one API call for the whole group.

const (
	// The probe container prints one of these markers and nothing else is
	// parsed. Attributing the outcome to a marker rather than to the exit code
	// keeps "started and found no device" separate from "never started".
	gpuDevicePresent = "BUDCTL_DEVICE_PRESENT"
	gpuDeviceMissing = "BUDCTL_DEVICE_MISSING"

	// Deliberately NOT a CUDA image (FRD-020 D10). Requesting nvidia.com/gpu: 1
	// makes the device plugin inject the device nodes whatever the image is, so
	// asserting /dev/nvidiactl inside a slim image proves allocation, injection
	// and the runtime-hook chain for megabytes instead of gigabytes.
	//
	// Slim, but glibc with its compatibility libraries — not busybox. HAMi
	// preloads its vGPU interceptor into every container that asks for a GPU,
	// and that library needs libdl.so.2: busybox's shell then dies in the
	// loader before it prints a line. budcluster's own GPU canary uses a Debian
	// slim image for the same reason.
	gpuDefaultProbeImage = "debian:trixie-slim"

	// gpuLoaderError is what the dynamic loader prints when an injected library
	// needs something the probe image does not ship.
	gpuLoaderError = "error while loading shared libraries"
)

// gpuVendor is one accelerator family: what the kubelet advertises, what the
// plugin injects into the container, and how the vendor's device-plugin
// DaemonSet can be recognised in whatever namespace it was installed into.
type gpuVendor struct {
	Resource string
	Name     string
	// Devices are the device nodes the plugin injects. Presence of ANY of them
	// inside the probe container is the proof; vendors differ in which appears.
	Devices []string
	// PluginTokens identify the device-plugin DaemonSet by name or image. HAMi
	// counts as an NVIDIA plugin: budcluster installs it instead of, or beside,
	// the stock one, and it is what advertises nvidia.com/gpu on those nodes.
	PluginTokens []string
	// HardwareLabels mean the silicon is present even when nothing advertises a
	// resource for it — the "driver never loaded" case, which advertises
	// neither allocatable nor capacity. These are the same labels budcluster's
	// onboarding uses to decide a cluster is a GPU cluster
	// (charts/nfd/templates/accelerator-detection-noderule.yaml), so budctl and
	// budcluster agree on what counts as a GPU node.
	HardwareLabels []string
	// CountLabel carries the physical device count where the vendor publishes
	// one, which is how a time-sliced slot count is told from real hardware.
	CountLabel string
}

var gpuVendors = []gpuVendor{
	{
		Resource:     "nvidia.com/gpu",
		Name:         "NVIDIA",
		Devices:      []string{"/dev/nvidiactl", "/dev/nvidia0"},
		PluginTokens: []string{"nvidia", "nvdp", "hami"},
		HardwareLabels: []string{
			"nvidia.com/gpu.present",
			"feature.node.kubernetes.io/pci-10de.present",
		},
		CountLabel: "nvidia.com/gpu.count",
	},
	{
		Resource:     "habana.ai/gaudi",
		Name:         "Intel Gaudi",
		Devices:      []string{"/dev/accel/accel0", "/dev/hl0", "/dev/hl_controlD0"},
		PluginTokens: []string{"habana", "gaudi"},
		HardwareLabels: []string{
			"feature.node.kubernetes.io/pci-8086.device-1020",
			"feature.node.kubernetes.io/pci-8086.device-1021",
			"feature.node.kubernetes.io/pci-8086.device-1022",
		},
	},
	{
		Resource:     "amd.com/gpu",
		Name:         "AMD",
		Devices:      []string{"/dev/kfd"},
		PluginTokens: []string{"amd", "rocm"},
		HardwareLabels: []string{
			"amd.com/gpu.device-id",
			"beta.amd.com/gpu.device-id",
			"feature.node.kubernetes.io/pci-1002.present",
		},
	},
}

// gpuNode is one (node, vendor) pair. DetectedBy records WHICH of the three
// signals found it, because the three mean very different things.
type gpuNode struct {
	Name        string
	Vendor      gpuVendor
	Allocatable float64
	Capacity    float64
	Physical    float64
	Ready       bool
	Schedulable bool
	Taints      []string
	DetectedBy  string
}

type gpuFleet struct{ Nodes []gpuNode }

func (f gpuFleet) empty() bool { return len(f.Nodes) == 0 }

func (f gpuFleet) names() []string {
	out := make([]string, 0, len(f.Nodes))
	for _, n := range f.Nodes {
		out = append(out, n.Name)
	}
	return Sorted(out)
}

// vendors returns the accelerator families actually present, in catalogue order
// so the report does not reshuffle between runs.
func (f gpuFleet) vendors() []gpuVendor {
	out := []gpuVendor{}
	for _, v := range gpuVendors {
		for _, n := range f.Nodes {
			if n.Vendor.Resource == v.Resource {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func (f gpuFleet) ofVendor(resource string) []gpuNode {
	out := []gpuNode{}
	for _, n := range f.Nodes {
		if n.Vendor.Resource == resource {
			out = append(out, n)
		}
	}
	return out
}

func (f gpuFleet) hasVendor(resource string) bool { return len(f.ofVendor(resource)) > 0 }

// allocatableOf totals what the scheduler can actually hand out. Nodes that are
// NotReady or cordoned are excluded: their advertised GPUs are not usable, and
// counting them is how a fleet looks big enough right up to the first deploy.
func (f gpuFleet) allocatableOf(resource string) (usable, advertised float64) {
	for _, n := range f.ofVendor(resource) {
		advertised += n.Allocatable
		if n.Ready && n.Schedulable {
			usable += n.Allocatable
		}
	}
	return usable, advertised
}

// probeVendor picks what the functional probe will ask for. NVIDIA first: it is
// what the FRD names, what budcluster's runtime chart requests, and the only
// family whose whole toolkit chain is in play.
func (f gpuFleet) probeVendor() gpuVendor {
	for _, v := range f.vendors() {
		if usable, _ := f.allocatableOf(v.Resource); usable > 0 {
			return v
		}
	}
	return f.vendors()[0]
}

func gpuFleetOf(ctx context.Context, c *engine.Ctx) gpuFleet {
	f := gpuFleet{}
	if c.Kube == nil {
		return f
	}
	for _, n := range c.Kube.List(ctx, "nodes", "") {
		labels := n.Labels()
		ready := gpuNodeReady(n)
		unsched, _ := n.Dig("spec", "unschedulable").(bool)
		taints := gpuNodeTaints(n)
		for _, v := range gpuVendors {
			// Allocatable, not capacity: a node whose plugin has died still
			// reports capacity, and reading capacity is exactly how a dead
			// plugin passes for a healthy one (FRD-020 §5.12).
			alloc := QuantityOf(n, "status", "allocatable", v.Resource)
			capacity := QuantityOf(n, "status", "capacity", v.Resource)
			var detected string
			switch {
			case alloc > 0:
				detected = "allocatable"
			case capacity > 0:
				detected = "capacity only"
			case gpuHasHardwareLabel(labels, v):
				detected = "hardware label only"
			default:
				continue
			}
			f.Nodes = append(f.Nodes, gpuNode{
				Name:        n.Name(),
				Vendor:      v,
				Allocatable: alloc,
				Capacity:    capacity,
				Physical:    ParseQuantity(labels[v.CountLabel]),
				Ready:       ready,
				Schedulable: !unsched,
				Taints:      taints,
				DetectedBy:  detected,
			})
		}
	}
	sort.SliceStable(f.Nodes, func(i, j int) bool { return f.Nodes[i].Name < f.Nodes[j].Name })
	return f
}

// gpuSkipReason names the contradiction when the intake asked for GPU serving
// and the fleet has none: the group still skips (there is nothing here to
// check, and the verdict must not move on an absent accelerator), but the
// reason says what it costs instead of reading as a clean bill of health.
func gpuSkipReason(c *engine.Ctx) string {
	base := "no node advertises nvidia.com/gpu, habana.ai/gaudi or amd.com/gpu, and none carries accelerator hardware labels"
	if c.Answers.GPU {
		return base + " — the intake states GPU serving, so on this fleet every GPU deployment would stay Pending; nodes.capacity covers what the cluster does have"
	}
	return base + ": this is a CPU-only cluster, which Bud supports"
}

func init() {
	engine.Register(&engine.Check{
		ID: "gpu.nodes", Group: "gpu", Severity: engine.Info,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("gpu.nodes")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the GPU fleet can only be read from the API server")
			}
			f := gpuFleetOf(ctx, c)
			if f.empty() {
				return ch.Skip(gpuSkipReason(c))
			}
			c.Set(engine.KeyGPUNodes, f.names())

			detail, evidence := []string{}, []string{}
			totals := []string{}
			for _, v := range f.vendors() {
				usable, advertised := f.allocatableOf(v.Resource)
				nodes := f.ofVendor(v.Resource)
				totals = append(totals, fmt.Sprintf("%.0f %s on %d %s",
					advertised, v.Resource, len(nodes), Plural(len(nodes), "node", "nodes")))
				for _, n := range nodes {
					line := fmt.Sprintf("%s: %s allocatable %.0f, capacity %.0f (detected by %s)",
						n.Name, v.Resource, n.Allocatable, n.Capacity, n.DetectedBy)
					if n.Physical > 0 {
						line += fmt.Sprintf(", %s=%.0f", v.CountLabel, n.Physical)
					}
					if !n.Ready {
						line += ", node NotReady"
					}
					if !n.Schedulable {
						line += ", cordoned"
					}
					if len(n.Taints) > 0 {
						line += ", taints " + strings.Join(n.Taints, " ")
					}
					evidence = append(evidence, line)
					if n.DetectedBy != "allocatable" {
						detail = append(detail, fmt.Sprintf(
							"%s advertises no allocatable %s (%s) — gpu.device-plugin reports what that costs",
							n.Name, v.Resource, n.DetectedBy))
					}
				}
				if usable < advertised {
					detail = append(detail, fmt.Sprintf(
						"only %.0f of %.0f %s sit on Ready, schedulable nodes", usable, advertised, v.Resource))
				}
			}

			return ch.Infof("%d GPU %s: %s",
				len(f.names()), Plural(len(f.names()), "node", "nodes"), strings.Join(totals, "; ")).
				With(detail...).
				WithEvidence(engine.Evidence{
					What:   "nodes .status.allocatable / .status.capacity for nvidia.com/gpu, habana.ai/gaudi, amd.com/gpu",
					Output: strings.Join(evidence, "\n"),
				}).
				Bounds("an advertised device is a claim by the kubelet, not a working one: it does not prove the driver is loaded, the runtime injects the device, or that a container ever receives it — gpu.operator-functional is what establishes that")
		},
	})

	engine.Register(&engine.Check{
		ID: "gpu.device-plugin", Group: "gpu", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("gpu.device-plugin")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: device-plugin coverage can only be read from the API server")
			}
			f := gpuFleetOf(ctx, c)
			if f.empty() {
				return ch.Skip(gpuSkipReason(c))
			}

			type uncovered struct{ node, why string }
			var gaps []uncovered
			detail, evidence := []string{}, []string{}

			for _, v := range f.vendors() {
				view := gpuPluginCoverage(ctx, c, v)
				if len(view.DaemonSets) == 0 {
					detail = append(detail, fmt.Sprintf(
						"no %s device-plugin DaemonSet was found in any namespace", v.Name))
				} else {
					detail = append(detail, fmt.Sprintf("%s device-plugin DaemonSets: %s",
						v.Name, strings.Join(Sorted(view.DaemonSets), ", ")))
				}
				for _, n := range f.ofVendor(v.Resource) {
					pods := view.PodsByNode[n.Name]
					if pods == "" {
						pods = "no device-plugin pod scheduled on this node"
					}
					evidence = append(evidence, fmt.Sprintf("%s: allocatable %.0f, capacity %.0f — %s",
						n.Name, n.Allocatable, n.Capacity, pods))
					switch {
					case n.Allocatable <= 0 && n.Capacity > 0:
						// The fixture case: a stopped plugin leaves capacity
						// behind. Reading capacity would call this node healthy.
						gaps = append(gaps, uncovered{n.Name, fmt.Sprintf(
							"advertises %.0f %s in capacity but 0 allocatable — the plugin registered once and has since stopped",
							n.Capacity, v.Resource)})
					case n.Allocatable <= 0:
						gaps = append(gaps, uncovered{n.Name, fmt.Sprintf(
							"carries %s hardware labels but advertises no %s at all — the plugin has never registered, usually because the driver module is not loaded",
							v.Name, v.Resource)})
					case len(view.DaemonSets) > 0 && !view.ReadyNodes[n.Name]:
						// Allocatable is still advertised, but the plugin that
						// advertised it is gone: the number is stale and the
						// kubelet drops it on the next re-registration. Only
						// asserted when a DaemonSet was positively identified,
						// so a cluster whose plugin budctl cannot recognise —
						// yet which demonstrably advertises — is not failed on
						// a naming convention.
						gaps = append(gaps, uncovered{n.Name, fmt.Sprintf(
							"advertises %.0f %s but no %s device-plugin pod is Ready on it (%s) — the advertisement is stale",
							n.Allocatable, v.Resource, v.Name, pods)})
					}
				}
			}

			ev := engine.Evidence{What: "GPU node allocatable vs device-plugin pod readiness", Output: strings.Join(evidence, "\n")}
			if len(gaps) > 0 {
				names := make([]string, 0, len(gaps))
				for _, g := range gaps {
					names = append(names, g.node)
					detail = append(detail, g.node+": "+g.why)
				}
				return ch.Fail(
					fmt.Sprintf("the device plugin does not cover %d of %d GPU %s (%s): those GPUs can never be allocated, so every model pod that targets them stays Pending forever",
						len(gaps), len(f.Nodes), Plural(len(f.Nodes), "node", "nodes"), strings.Join(Sorted(names), ", ")),
					"restart the vendor device-plugin DaemonSet and confirm the node advertises the resource again: "+
						"`kubectl -n <plugin-namespace> rollout restart ds/<plugin>` then "+
						"`kubectl get node <node> -o jsonpath='{.status.allocatable}'`. "+
						"A plugin that crash-loops on start is nearly always a driver that did not build or load on that node — check the driver DaemonSet's logs there first.").
					With(detail...).WithEvidence(ev)
			}

			total := 0.0
			for _, v := range f.vendors() {
				_, advertised := f.allocatableOf(v.Resource)
				total += advertised
			}
			return ch.Pass(fmt.Sprintf("every one of the %d GPU %s has a device plugin advertising allocatable capacity (%.0f devices in total)",
				len(f.Nodes), Plural(len(f.Nodes), "node", "nodes"), total)).
				With(detail...).WithEvidence(ev).
				Bounds("a plugin that advertises is not a plugin that delivers: injecting the device into a container is a separate step, proven only by gpu.operator-functional")
		},
	})

	engine.Register(&engine.Check{
		ID: "gpu.runtime-class", Group: "gpu", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("gpu.runtime-class")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: RuntimeClasses can only be read from the API server")
			}
			f := gpuFleetOf(ctx, c)
			if f.empty() {
				return ch.Skip(gpuSkipReason(c))
			}
			// budcluster sets runtimeClassName: nvidia on NVIDIA runtime
			// containers only (charts/bud_runtime_container/templates/*.yaml);
			// a Gaudi or AMD fleet neither needs nor gets one.
			if !f.hasVendor("nvidia.com/gpu") {
				present := []string{}
				for _, v := range f.vendors() {
					present = append(present, v.Name)
				}
				return ch.Skip("the only accelerators detected are " + strings.Join(present, ", ") +
					"; runtimeClassName: nvidia is rendered only for NVIDIA runtime containers, so no RuntimeClass is required here")
			}

			existing := []string{}
			for _, rc := range c.Kube.List(ctx, "runtimeclasses.node.k8s.io", "") {
				existing = append(existing, fmt.Sprintf("%s (handler %s)", rc.Name(), rc.DigString("handler")))
			}
			ev := engine.Evidence{What: "runtimeclasses.node.k8s.io", Output: gpuOrNone(strings.Join(Sorted(existing), "\n"), "no RuntimeClass objects exist in this cluster")}

			rc := c.Kube.Get(ctx, "runtimeclasses.node.k8s.io", "", "nvidia")
			if rc == nil {
				return ch.Fail(
					"the `nvidia` RuntimeClass does not exist, so the API server rejects every model pod budcluster renders (they pin runtimeClassName: nvidia) and no GPU deployment ever starts",
					"create it, and make sure the node runtime has a handler of the same name "+
						"(the gpu-operator's nvidia-container-toolkit DaemonSet writes one into containerd/CRI-O):\n"+
						"  apiVersion: node.k8s.io/v1\n  kind: RuntimeClass\n  metadata:\n    name: nvidia\n  handler: nvidia").
					With("budcluster renders runtimeClassName: nvidia in charts/bud_runtime_container/templates/single-node.yaml and multi-node.yaml",
						"installing the NVIDIA GPU Operator creates this object as a side effect; a cluster whose driver was installed by hand usually has not").
					WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("the `nvidia` RuntimeClass exists, handler %q", rc.DigString("handler"))).
				WithEvidence(ev).
				Bounds("a RuntimeClass object only names a handler; it does not prove every node's container runtime has that handler configured — a pod scheduled onto a node without it fails at container creation, which is what gpu.operator-functional exercises")
		},
	})

	engine.Register(&engine.Check{
		ID: "gpu.operator-functional", Group: "gpu", Severity: engine.Block,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("gpu.operator-functional")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the probe pod needs an API server to be created in")
			}
			if c.Probes == nil {
				return ch.Skip("probes are disabled, so the driver, device-plugin and runtime chain was NOT exercised and is not confirmed working")
			}
			f := gpuFleetOf(ctx, c)
			if f.empty() {
				return ch.Skip(gpuSkipReason(c))
			}

			v := f.probeVendor()
			usable, advertised := f.allocatableOf(v.Resource)
			taints := Sorted(gpuFleetTaints(f, v.Resource))

			// A pod requesting a resource nothing advertises can only sit
			// Pending until the check times out. The answer is already known,
			// and it is the allocation stage — so report it without creating
			// anything.
			if usable <= 0 {
				return ch.Fail(
					fmt.Sprintf("no Ready, schedulable node advertises allocatable %s, so a pod requesting one can never be scheduled and every GPU model deployment will sit Pending", v.Resource),
					gpuAllocationRemedy(v, taints)).
					With(gpuFleetLines(f, v.Resource)...).
					With(fmt.Sprintf("%.0f %s are advertised cluster-wide but none on a node that can accept a pod", advertised, v.Resource),
						"the probe pod was not created: there is nothing for it to land on").
					WithEvidence(engine.Evidence{
						What:   "sum of allocatable " + v.Resource + " over Ready, schedulable nodes",
						Output: strings.Join(gpuFleetLines(f, v.Resource), "\n"),
					})
			}

			image := c.Opts.GPUProbeImage
			if image == "" {
				image = gpuDefaultProbeImage
			}
			// Stay inside the per-check deadline: RunPod returns ctx.Err() the
			// moment the check's context expires, which would lose the stage
			// attribution that is the whole point of this check.
			timeout := 75 * time.Second
			if c.Opts.CheckTimeout > 0 {
				timeout = c.Opts.CheckTimeout - 15*time.Second
			}
			if timeout < 30*time.Second {
				timeout = 30 * time.Second
			}

			spec := probes.PodSpec{
				Name:      "budctl-gpu-probe",
				Image:     image,
				Command:   gpuProbeCommand(v),
				Resources: map[string]string{v.Resource: "1"},
				Timeout:   timeout,
			}
			outcome, err := c.Probes.RunPod(ctx, spec)

			asked := fmt.Sprintf("pod %s/%s, image %s, requesting %s: 1",
				c.Probes.Namespace(), spec.Name, image, v.Resource)
			ev := []engine.Evidence{{
				What: asked,
				Output: fmt.Sprintf("scheduled=%t started=%t succeeded=%t phase=%s reason=%s",
					outcome.Scheduled, outcome.Started, outcome.Succeeded,
					gpuOrNone(outcome.Phase, "none"), gpuOrNone(outcome.Reason, "none")),
			}}
			if len(outcome.Events) > 0 {
				ev = append(ev, engine.Evidence{What: "Kubernetes Events on the probe pod", Output: strings.Join(outcome.Events, "\n")})
			}
			if strings.TrimSpace(outcome.Logs) != "" {
				ev = append(ev, engine.Evidence{What: "probe container output", Output: outcome.Logs})
			}

			// The pod never reached the API server at all: an RBAC or admission
			// refusal, not a GPU answer. Claiming either way would be a guess.
			if err != nil && outcome.Phase == "" && !outcome.Scheduled {
				return ch.Skip("the GPU probe pod could not be created, so the driver/device-plugin/runtime chain was not exercised: " + err.Error()).
					WithEvidence(ev...)
			}

			deadline := ""
			if err != nil {
				deadline = fmt.Sprintf(" (the probe did not finish: %s)", err.Error())
			}

			switch {
			case !outcome.Scheduled:
				// STAGE 1 — allocation. The scheduler found no node that could
				// satisfy the request: no free allocatable device, or a taint
				// with no toleration to match it.
				return ch.Fail(
					fmt.Sprintf("a pod requesting %s: 1 was never scheduled onto any node%s, so no model deployment can be placed either", v.Resource, deadline),
					gpuAllocationRemedy(v, taints)).
					With("stage: ALLOCATION — the pod never reached a node, so this is the scheduler's view of the fleet, not the driver or the runtime").
					With(gpuFleetLines(f, v.Resource)...).
					WithEvidence(ev...)

			case gpuImagePullFailure(outcome.Reason, outcome.Events):
				// Not a GPU answer: the node could not fetch a few megabytes of
				// base image. registry.from-cluster and egress.install own that
				// blocker; reporting it here as a GPU fault would send the
				// operator to the wrong stack.
				return ch.Skip(fmt.Sprintf(
					"the probe image %s could not be pulled onto the GPU node (%s), so the driver/device-plugin/runtime chain was not exercised — this is a registry/egress finding, see registry.from-cluster and egress.install",
					image, gpuOrNone(outcome.Reason, "see events"))).
					WithEvidence(ev...)

			case !outcome.Started:
				// STAGE 2 — the kubelet accepted the pod and the runtime
				// refused to create the container. Allocation already worked,
				// so this is the RuntimeClass handler or the container toolkit.
				return ch.Fail(
					fmt.Sprintf("the GPU probe was scheduled but its container never started%s: the container runtime refused to create it, which is the RuntimeClass / nvidia-container-toolkit wiring rather than the driver", deadline),
					"confirm the node's container runtime has a handler matching the `nvidia` RuntimeClass — the gpu-operator's "+
						"nvidia-container-toolkit DaemonSet writes it into containerd's config and restarts the runtime: "+
						"`kubectl -n gpu-operator logs ds/nvidia-container-toolkit-daemonset` and "+
						"`kubectl -n gpu-operator get pods -o wide`. The Events below carry the runtime's own message.").
					With("stage: RUNTIME CLASS / CONTAINER TOOLKIT — allocation succeeded, container creation did not").
					With(fmt.Sprintf("last container state: %s", gpuOrNone(outcome.Reason, "none reported"))).
					WithEvidence(ev...)

			case strings.Contains(outcome.Logs, gpuDevicePresent):
				return ch.Pass(fmt.Sprintf("a pod requesting %s: 1 scheduled, started, and found %s inside the container",
					v.Resource, strings.Join(v.Devices, " or "))).
					With(fmt.Sprintf("probe image %s — a slim base image, not CUDA: the device plugin injects the device nodes whatever the image is (FRD-020 D10)", image)).
					WithEvidence(ev...).
					Bounds("the probe runs under the default scheduler with no runtimeClassName and no toleration, while budcluster renders model pods with runtimeClassName: nvidia and schedulerName: hami-scheduler; and it says nothing about whether a specific model fits in the GPU's memory or whether MIG partitioning matches the deployment profile — budsim answers those at deploy time")

			case strings.Contains(outcome.Logs, gpuDeviceMissing):
				// STAGE 3 — the container ran and got nothing. Allocation and
				// container creation both worked, so the device plugin
				// allocated a device the driver never produced.
				node := "the GPU node"
				return ch.Fail(
					fmt.Sprintf("the GPU probe started but no %s device node was injected into the container: a model pod would get no GPU at all, and fail or silently fall back to CPU", strings.Join(v.Devices, "/")),
					"this is the driver or the device plugin, not scheduling: confirm the driver DaemonSet is Ready on "+node+
						" (`kubectl -n gpu-operator get pods -o wide`), that `nvidia-smi` works on the node itself, and restart the "+
						"device plugin once the kernel module is loaded. A plugin that hands out devices the driver never created is the classic symptom of a driver upgrade that did not reboot.").
					With("stage: DRIVER / DEVICE PLUGIN — the container was created and the device was absent inside it").
					With("the container listed /dev; the output is in the evidence below").
					WithEvidence(ev...)

			case strings.Contains(outcome.Logs, gpuLoaderError):
				// Started, and the shell died in the dynamic loader before the
				// script ran: a library the GPU stack injected (HAMi's vGPU
				// interceptor, or the NVIDIA hook's driver libraries) needs one
				// the probe image lacks. Allocation and container creation
				// worked; the device assertion never ran, so it is unverified
				// rather than failed — and the image is the thing to change.
				return ch.Skip(fmt.Sprintf(
					"the GPU probe started, but the probe image %s could not load a library the GPU stack injected into it (%s), so device injection is unverified; re-run with --gpu-probe-image set to a glibc image such as %s",
					image, gpuFirstLine(outcome.Logs, gpuLoaderError), gpuDefaultProbeImage)).
					WithEvidence(ev...)

			default:
				// Started, exited, and said neither. Reporting a device fault
				// here would be inventing a finding out of a missing log.
				return ch.Skip(fmt.Sprintf(
					"the GPU probe container ran but returned no readable device assertion%s, so device injection is unverified (phase %s); re-run with --keep to inspect the pod",
					deadline, gpuOrNone(outcome.Phase, "unknown"))).
					WithEvidence(ev...)
			}
		},
	})

	engine.Register(&engine.Check{
		ID: "gpu.sharing", Group: "gpu", Severity: engine.Info,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("gpu.sharing")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: sharing configuration can only be read from the API server")
			}
			f := gpuFleetOf(ctx, c)
			if f.empty() {
				return ch.Skip(gpuSkipReason(c))
			}

			detail, evidence := []string{}, []string{}
			hami, mig := false, false
			var hamiKeys, migKeys []string

			for _, n := range c.Kube.List(ctx, "nodes", "") {
				for key, val := range gpuAllocatableKeys(n) {
					switch {
					case key == "nvidia.com/gpumem" || key == "nvidia.com/gpucores" || key == "nvidia.com/gpumem-percentage":
						hami = true
						hamiKeys = append(hamiKeys, fmt.Sprintf("%s=%.0f on %s", key, val, n.Name()))
					case strings.HasPrefix(key, "nvidia.com/mig-"):
						mig = true
						migKeys = append(migKeys, fmt.Sprintf("%s=%.0f on %s", key, val, n.Name()))
					}
				}
				labels := n.Labels()
				if labels["nvidia.com/mig.capable"] == "true" {
					mig = true
					migKeys = append(migKeys, fmt.Sprintf("%s: nvidia.com/mig.capable=true, strategy %s",
						n.Name(), gpuOrNone(labels["nvidia.com/mig.strategy"], "unset")))
				} else if s := labels["nvidia.com/mig.strategy"]; s != "" && s != "none" {
					mig = true
					migKeys = append(migKeys, fmt.Sprintf("%s: nvidia.com/mig.strategy=%s", n.Name(), s))
				}
			}

			// HAMi is what budcluster installs on any NVIDIA cluster during
			// onboarding, and it also re-points model pods at its own scheduler
			// — so its absence and its half-presence are both worth naming.
			for _, d := range c.Kube.List(ctx, "deployments.apps", "") {
				if d.Name() != "hami-scheduler" {
					continue
				}
				hami = true
				avail := gpuNum(d.Dig("status", "availableReplicas"))
				evidence = append(evidence, fmt.Sprintf("deployment %s/%s availableReplicas=%.0f", d.Namespace(), d.Name(), avail))
				if avail <= 0 {
					detail = append(detail, fmt.Sprintf(
						"%s/%s has no available replica — budcluster pins model pods to schedulerName: hami-scheduler, so on this cluster they would stay Pending until it runs",
						d.Namespace(), d.Name()))
				}
			}
			for _, ds := range c.Kube.List(ctx, "daemonsets.apps", "") {
				if strings.Contains(strings.ToLower(ds.Name()), "hami") {
					hami = true
					evidence = append(evidence, fmt.Sprintf("daemonset %s/%s ready=%.0f/%.0f",
						ds.Namespace(), ds.Name(),
						gpuNum(ds.Dig("status", "numberReady")), gpuNum(ds.Dig("status", "desiredNumberScheduled"))))
				}
			}

			slots, _ := f.allocatableOf("nvidia.com/gpu")
			var physical float64
			for _, n := range f.ofVendor("nvidia.com/gpu") {
				physical += n.Physical
			}
			evidence = append(evidence, Sorted(append(hamiKeys, migKeys...))...)

			var summary string
			switch {
			case hami && physical > 0 && slots > physical:
				summary = fmt.Sprintf("HAMi time-slicing is in place: %.0f schedulable nvidia.com/gpu slots over %.0f physical %s (×%.0f)",
					slots, physical, Plural(int(physical), "GPU", "GPUs"), slots/physical)
				detail = append(detail, "each slot is a share of a physical device, not a device: concurrent deployments contend for the same memory and SMs, and budsim sizes that at deploy time")
			case hami:
				summary = fmt.Sprintf("HAMi is installed; the fleet advertises %.0f allocatable nvidia.com/gpu", slots)
				if physical == 0 {
					detail = append(detail, "no node publishes nvidia.com/gpu.count, so the split factor between slots and physical devices could not be derived")
				}
			case mig:
				summary = fmt.Sprintf("MIG partitioning is configured; the fleet advertises %.0f allocatable GPU resources", slots)
				detail = append(detail, "MIG instances are advertised as distinct resource names, so a deployment profile asking for whole nvidia.com/gpu will not match a mixed-strategy node")
			default:
				used := slots
				summary = fmt.Sprintf("no GPU sharing is configured: each of the %.0f allocatable %s is one whole physical device",
					used, Plural(int(used), "GPU", "GPUs"))
				detail = append(detail, "budcluster installs HAMi during cluster onboarding when NVIDIA GPUs are detected; until it runs, one deployment occupies one whole GPU")
			}
			if mig && hami {
				detail = append(detail, "both HAMi and MIG were detected: HAMi's device plugin is installed with migStrategy: none by budcluster, so MIG instances would not be advertised as it expects")
			}

			return ch.Infof("%s", summary).With(detail...).
				WithEvidence(engine.Evidence{What: "sharing signals: HAMi workloads, MIG labels, and vendor sub-resources in node allocatable",
					Output: gpuOrNone(strings.Join(Sorted(evidence), "\n"), "no HAMi workload, MIG label or shared-GPU resource found")})
		},
	})

	engine.Register(&engine.Check{
		ID: "gpu.capacity", Group: "gpu", Severity: engine.Risk,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("gpu.capacity")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: allocatable GPU capacity can only be read from the API server")
			}
			f := gpuFleetOf(ctx, c)
			if f.empty() {
				return ch.Skip(gpuSkipReason(c))
			}
			// Every threshold traces back to an answer (FRD-020 §7). Without a
			// stated concurrency there is no requirement to compare against,
			// and inventing one is how a green run becomes wrong.
			if !c.Answers.GPU {
				return ch.Skip("the intake states CPU-only serving (gpu: false), so no GPU concurrency was stated to size this fleet against")
			}
			want := c.Answers.Deployments
			if want <= 0 {
				return ch.Skip("the intake does not state how many concurrent deployments will run, so there is no requirement to size the GPU fleet against")
			}

			var usable, advertised float64
			lines := []string{}
			for _, v := range f.vendors() {
				u, a := f.allocatableOf(v.Resource)
				usable += u
				advertised += a
				lines = append(lines, fmt.Sprintf("%s: %.0f usable of %.0f advertised", v.Resource, u, a))
				lines = append(lines, gpuFleetLines(f, v.Resource)...)
			}
			ev := engine.Evidence{
				What:   fmt.Sprintf("allocatable GPUs on Ready, schedulable nodes vs concurrentDeployments=%d", want),
				Output: strings.Join(lines, "\n"),
			}
			detail := []string{
				fmt.Sprintf("required %d (one GPU per concurrent deployment) · usable %.0f · advertised %.0f", want, usable, advertised),
				fmt.Sprintf("modelCount=%d is a storage figure, not a concurrency one — storage.capacity sizes the registry against it", c.Answers.ModelCount),
			}
			if advertised > usable {
				detail = append(detail, fmt.Sprintf("%.0f advertised %s sit on NotReady or cordoned nodes and were not counted",
					advertised-usable, Plural(int(advertised-usable), "GPU", "GPUs")))
			}

			if usable < float64(want) {
				return ch.Fail(
					fmt.Sprintf("%d concurrent deployments were stated but only %.0f allocatable %s are usable: at most %.0f models run at once and every further deployment stays Pending until one is freed",
						want, usable, Plural(int(usable), "GPU", "GPUs"), usable),
					fmt.Sprintf("add GPU nodes, enable HAMi time-slicing so one physical GPU serves several deployments (budcluster installs it during cluster onboarding when NVIDIA GPUs are detected), or set concurrentDeployments to %.0f in the intake so the rest of the plan is sized honestly", usable)).
					With(detail...).WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("%.0f allocatable %s for %d stated concurrent %s",
				usable, Plural(int(usable), "GPU", "GPUs"), want, Plural(want, "deployment", "deployments"))).
				With(detail...).WithEvidence(ev).
				Bounds("a GPU count is not GPU memory: whether a given model fits on one of these devices, and how many replicas it needs, is budsim's answer at deploy time")
		},
	})
}

// gpuProbeCommand asserts the injected device node from inside the container.
// It prints /dev on failure, because the listing is what tells a driver fault
// (nothing at all) from a partial injection (nvidiactl without nvidia0).
func gpuProbeCommand(v gpuVendor) []string {
	tests := make([]string, 0, len(v.Devices))
	for _, d := range v.Devices {
		tests = append(tests, fmt.Sprintf("[ -e %s ]", d))
	}
	script := fmt.Sprintf(
		"if %s; then echo %s; ls -l %s 2>/dev/null; exit 0; fi; echo %s; ls -1 /dev; exit 1",
		strings.Join(tests, " || "), gpuDevicePresent, strings.Join(v.Devices, " "), gpuDeviceMissing)
	return []string{"/bin/sh", "-c", script}
}

// gpuAllocationRemedy is shared by the two ways allocation can fail, because
// the operator's next move is the same in both.
func gpuAllocationRemedy(v gpuVendor, taints []string) string {
	remedy := fmt.Sprintf(
		"make one node Ready, schedulable and advertising %s: `kubectl get nodes -o custom-columns=NAME:.metadata.name,GPU:.status.allocatable.'%s'` shows which do, "+
			"and gpu.device-plugin names what is stopping the rest.", v.Resource, v.Resource)
	if len(taints) > 0 {
		// Worth spelling out: nothing in the Bud charts declares a toleration,
		// so a NoSchedule taint on the GPU nodes keeps every Bud workload off
		// them, not just this probe.
		remedy += fmt.Sprintf(" The GPU nodes carry %s — no chart in the stack declares a toleration, so remove the taint or no Bud workload will ever land on them.",
			strings.Join(taints, ", "))
	}
	return remedy
}

func gpuFleetTaints(f gpuFleet, resource string) []string {
	out := []string{}
	for _, n := range f.ofVendor(resource) {
		out = append(out, n.Taints...)
	}
	return out
}

func gpuFleetLines(f gpuFleet, resource string) []string {
	out := []string{}
	for _, n := range f.ofVendor(resource) {
		line := fmt.Sprintf("%s: allocatable %.0f %s", n.Name, n.Allocatable, resource)
		if !n.Ready {
			line += ", NotReady"
		}
		if !n.Schedulable {
			line += ", cordoned"
		}
		if len(n.Taints) > 0 {
			line += ", taints " + strings.Join(n.Taints, " ")
		}
		out = append(out, line)
	}
	return out
}

// gpuPluginView is the device plugin as seen from the nodes it must cover:
// DaemonSet counts say how many pods are ready, never WHICH node is uncovered.
type gpuPluginView struct {
	DaemonSets []string
	ReadyNodes map[string]bool
	PodsByNode map[string]string
}

func gpuPluginCoverage(ctx context.Context, c *engine.Ctx, v gpuVendor) gpuPluginView {
	view := gpuPluginView{ReadyNodes: map[string]bool{}, PodsByNode: map[string]string{}}
	if c.Kube == nil {
		return view
	}
	uids, names := map[string]bool{}, map[string]bool{}
	// Cluster-wide: vendors install their plugin into gpu-operator, kube-system,
	// nvidia-device-plugin or a namespace of the customer's choosing, and a
	// hard-coded namespace list would silently report "no plugin" on the fourth.
	for _, ds := range c.Kube.List(ctx, "daemonsets.apps", "") {
		if !gpuIsDevicePluginFor(ds, v) {
			continue
		}
		view.DaemonSets = append(view.DaemonSets, fmt.Sprintf("%s/%s (%.0f/%.0f ready)",
			ds.Namespace(), ds.Name(),
			gpuNum(ds.Dig("status", "numberReady")), gpuNum(ds.Dig("status", "desiredNumberScheduled"))))
		uids[ds.DigString("metadata", "uid")] = true
		names[ds.Name()] = true
	}
	if len(view.DaemonSets) == 0 {
		return view
	}
	for _, p := range c.Kube.List(ctx, "pods", "") {
		owned := false
		for _, raw := range p.DigSlice("metadata", "ownerReferences") {
			o, ok := raw.(map[string]any)
			if !ok || gpuStr(o["kind"]) != "DaemonSet" {
				continue
			}
			if uids[gpuStr(o["uid"])] || names[gpuStr(o["name"])] {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		node := p.DigString("spec", "nodeName")
		if node == "" {
			continue
		}
		state := fmt.Sprintf("%s/%s phase=%s", p.Namespace(), p.Name(), p.DigString("status", "phase"))
		if gpuPodReady(p) {
			view.ReadyNodes[node] = true
			state += " Ready"
		} else {
			state += " not Ready"
		}
		if prev := view.PodsByNode[node]; prev != "" {
			state = prev + "; " + state
		}
		view.PodsByNode[node] = state
	}
	return view
}

func gpuIsDevicePluginFor(ds adapters.Object, v gpuVendor) bool {
	hay := strings.ToLower(ds.Name())
	for _, ct := range ds.Containers() {
		hay += " " + strings.ToLower(gpuStr(ct["image"]))
	}
	if !strings.Contains(hay, "device-plugin") && !strings.Contains(hay, "deviceplugin") {
		return false
	}
	for _, tok := range v.PluginTokens {
		if strings.Contains(hay, tok) {
			return true
		}
	}
	return false
}

func gpuPodReady(p adapters.Object) bool {
	if p.DigString("status", "phase") != "Running" {
		return false
	}
	for _, raw := range p.DigSlice("status", "conditions") {
		cond, ok := raw.(map[string]any)
		if !ok || gpuStr(cond["type"]) != "Ready" {
			continue
		}
		return gpuStr(cond["status"]) == "True"
	}
	return false
}

func gpuNodeReady(n adapters.Object) bool {
	for _, raw := range n.DigSlice("status", "conditions") {
		cond, ok := raw.(map[string]any)
		if !ok || gpuStr(cond["type"]) != "Ready" {
			continue
		}
		return gpuStr(cond["status"]) == "True"
	}
	return false
}

// gpuNodeTaints reports only the effects that keep a pod off the node; a
// PreferNoSchedule taint is not why anything failed to schedule.
func gpuNodeTaints(n adapters.Object) []string {
	out := []string{}
	for _, raw := range n.DigSlice("spec", "taints") {
		t, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		effect := gpuStr(t["effect"])
		if effect != "NoSchedule" && effect != "NoExecute" {
			continue
		}
		key := gpuStr(t["key"])
		if val := gpuStr(t["value"]); val != "" {
			key += "=" + val
		}
		out = append(out, key+":"+effect)
	}
	return out
}

func gpuHasHardwareLabel(labels map[string]string, v gpuVendor) bool {
	for _, key := range v.HardwareLabels {
		if val, ok := labels[key]; ok && val != "false" {
			return true
		}
	}
	return false
}

func gpuAllocatableKeys(n adapters.Object) map[string]float64 {
	out := map[string]float64{}
	m, ok := n.Dig("status", "allocatable").(map[string]any)
	if !ok {
		return out
	}
	for k, v := range m {
		out[k] = gpuNum(v)
	}
	return out
}

// gpuNum handles both shapes the API returns: unstructured decoding gives
// int64 for counts such as numberReady, while quantities arrive as strings.
func gpuNum(v any) float64 {
	switch t := v.(type) {
	case int64:
		return float64(t)
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		return ParseQuantity(t)
	}
	return 0
}

func gpuStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func gpuOrNone(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// gpuImagePullFailure separates "the node could not fetch the image" from "the
// runtime refused to create the container". Both leave the pod scheduled and
// not started, and their remedies have nothing in common.
func gpuImagePullFailure(reason string, events []string) bool {
	hay := strings.ToLower(reason + " " + strings.Join(events, " "))
	for _, tok := range []string{"errimagepull", "imagepullbackoff", "invalidimagename", "errimageneverpull", "failed to pull"} {
		if strings.Contains(hay, tok) {
			return true
		}
	}
	return false
}

// gpuFirstLine returns the first output line containing needle, trimmed.
func gpuFirstLine(logs, needle string) string {
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, needle) {
			return strings.TrimSpace(line)
		}
	}
	return needle
}
