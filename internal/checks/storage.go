package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
)

// The storage group answers one question — "will the claims this install
// creates actually bind?" — and it answers it provisioner-agnostically.
//
// OpenEBS appears in the cluster-addons ApplicationSet and in the reference
// environment's values, but it is AN implementation of the requirement, not THE
// requirement (FRD-020 §5.7). local-path on k3s, EBS, Azure Disk, ODF, Ceph and
// NFS are all acceptable. So nothing below tests for a named provisioner: the
// metadata checks read StorageClass fields and .parameters generically, and
// storage.provision — the only check that exercises the provisioner rather than
// its metadata — is the authoritative one.

const (
	stSCResource     = "storageclasses.storage.k8s.io"
	stDefaultAnn     = "storageclass.kubernetes.io/is-default-class"
	stDefaultAnnBeta = "storageclass.beta.kubernetes.io/is-default-class"
)

func init() {
	engine.Register(&engine.Check{
		ID: "storage.default-class", Group: "storage", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.default-class")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: no StorageClass could be read")
			}
			classes := stLoadClasses(ctx, c)
			d := stDemandOf(c)
			ev := engine.Evidence{What: "kubectl get storageclass", Output: stClassTable(classes)}

			defaults := []string{}
			for _, sc := range classes {
				if sc.Default {
					defaults = append(defaults, sc.Name)
				}
			}

			switch {
			case len(classes) == 0:
				return ch.Fail(
					"the cluster has no StorageClass at all, so every PVC the install creates stays Pending forever and no Application reaches Healthy",
					"install a CSI driver — any of them — and mark one class default: "+stPatchDefaultCmd("<class>"),
					"budctl does not require a particular provisioner; local-path, EBS, Azure Disk, ODF, Ceph, NFS and OpenEBS are all acceptable").
					WithEvidence(ev)

			case len(defaults) == 0 && len(d.DefaultUsers) > 0:
				// This is the failure the openebs chart ships by design: it
				// creates four classes and marks none default
				// (defaultProvisoner: false), while the bud chart leaves
				// storageClassName empty on every claim.
				return ch.Fail(
					fmt.Sprintf("no StorageClass is marked default, and %d %s leave storageClassName empty — those PVCs stay Pending forever and the Application never becomes Healthy",
						len(d.DefaultUsers), Plural(len(d.DefaultUsers), "claim", "claims")),
					"mark one existing class default: "+stPatchDefaultCmd(stFirstClassName(classes))+
						" — or set an explicit class on each claim instead",
					append([]string{"relying on a default: " + strings.Join(Sorted(d.DefaultUsers), ", "),
						"source: " + d.Source}, stClassDetail(classes)...)...).
					WithEvidence(ev)

			case len(defaults) == 0:
				// Every claim budctl can see names a class, so the install
				// itself survives. It is still a risk: the addons in the
				// ApplicationSet, and anything added later, omit the field.
				return ch.FailAs(engine.Risk,
					"no StorageClass is marked default; this install names a class on every claim, but any addon or later workload that omits storageClassName will stay Pending",
					"mark one class default so the omitted case works: "+stPatchDefaultCmd(stFirstClassName(classes)),
					"classes named by the values: "+strings.Join(Sorted(d.NamedList()), ", "),
					"source: "+d.Source).
					WithEvidence(ev)

			case len(defaults) > 1:
				// More than one default is not an error the API rejects; the
				// binder picks the newest, so which class a claim lands on
				// changes silently when a class is recreated.
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("%d StorageClasses are marked default (%s); which one an empty storageClassName lands on is decided by creation timestamp and changes silently",
						len(defaults), strings.Join(defaults, ", ")),
					"leave exactly one default: kubectl annotate storageclass <name> "+stDefaultAnn+"- for each of the others").
					WithEvidence(ev)
			}

			sc := stClassByName(classes, defaults[0])
			relying := "nothing budctl can see leaves storageClassName empty, but the addons in the ApplicationSet do"
			if len(d.DefaultUsers) > 0 {
				relying = strings.Join(Sorted(d.DefaultUsers), ", ")
			}
			return ch.Pass(
				fmt.Sprintf("default StorageClass %q (%s)", sc.Name, sc.Provisioner),
				"claims relying on it: "+relying,
				"volumeBindingMode: "+stOrUnset(sc.Binding)).
				WithEvidence(ev).
				Bounds("that a claim in this class binds — only storage.provision exercises the provisioner — nor that it has the capacity storage.capacity sizes")
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.named-classes", Group: "storage", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.named-classes")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: no StorageClass could be read")
			}
			d := stDemandOf(c)
			if len(d.Named) == 0 {
				return ch.Skip("no StorageClass is named in the values (" + d.Source +
					"); every claim relies on the default, which storage.default-class covers")
			}
			classes := stLoadClasses(ctx, c)
			have := map[string]bool{}
			for _, sc := range classes {
				have[sc.Name] = true
			}

			missing, askedBy := []string{}, []string{}
			for _, name := range Sorted(d.NamedList()) {
				if !have[name] {
					missing = append(missing, name)
					askedBy = append(askedBy, fmt.Sprintf("%q is named by %s", name, strings.Join(Sorted(d.Named[name]), ", ")))
				}
			}
			ev := engine.Evidence{What: "kubectl get storageclass", Output: stClassTable(classes)}

			if len(missing) > 0 {
				return ch.Fail(
					fmt.Sprintf("StorageClass %s named by the values %s not exist, so every PVC pointing at %s stays Pending and the Application never becomes Healthy",
						stQuoteList(missing), Plural(len(missing), "does", "do"), Plural(len(missing), "it", "them")),
					fmt.Sprintf("create the class, or repoint the values at one that exists (%s): the class name in the values must match `kubectl get storageclass -o name` exactly",
						strings.Join(stClassNames(classes), ", ")),
					append(askedBy, "existing classes: "+strings.Join(stClassNames(classes), ", "), "source: "+d.Source)...).
					WithEvidence(ev)
			}
			return ch.Pass(
				fmt.Sprintf("all %d named %s exist: %s", len(d.Named),
					Plural(len(d.Named), "StorageClass", "StorageClasses"), strings.Join(Sorted(d.NamedList()), ", ")),
				"source: "+d.Source).
				WithEvidence(ev).
				Bounds("that those classes provision — existence is metadata; storage.provision is what binds a claim")
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.csi-healthy", Group: "storage", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.csi-healthy")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: CSI driver pods could not be read")
			}
			classes := stLoadClasses(ctx, c)
			if len(classes) == 0 {
				return ch.Skip("the cluster has no StorageClass, so there is no driver to inspect (see storage.default-class)")
			}
			cands, why := stCandidates(classes, stDemandOf(c))
			if len(cands) == 0 {
				return ch.Skip("no candidate StorageClass could be identified: " + why)
			}

			pods := c.Kube.List(ctx, "pods", "")
			drivers := map[string]bool{}
			for _, o := range c.Kube.List(ctx, "csidrivers.storage.k8s.io", "") {
				drivers[o.Name()] = true
			}
			nodeCount := len(c.Kube.List(ctx, "nodes", ""))
			registered := map[string]int{}
			for _, cn := range c.Kube.List(ctx, "csinodes.storage.k8s.io", "") {
				for _, raw := range cn.DigSlice("spec", "drivers") {
					if m, ok := raw.(map[string]any); ok {
						registered[adapters.Object(m).DigString("name")]++
					}
				}
			}

			broken, orphaned, static, detail := []string{}, []string{}, []string{}, []string{}
			evidence := []engine.Evidence{}
			for _, sc := range cands {
				prov := sc.Provisioner
				// kubernetes.io/no-provisioner is a static class: there is no
				// driver that could be unhealthy, and nothing creates volumes.
				if prov == "kubernetes.io/no-provisioner" {
					static = append(static, sc.Name)
					continue
				}
				matched := stDriverPods(pods, prov)
				bad := []string{}
				for _, p := range matched {
					if t := stPodTrouble(p, c.Now()); t != "" {
						bad = append(bad, fmt.Sprintf("%s/%s %s", p.Namespace(), p.Name(), t))
					}
				}
				switch {
				case len(bad) > 0:
					broken = append(broken, fmt.Sprintf("%s (%s): %s", sc.Name, prov, strings.Join(bad, "; ")))
				case len(matched) == 0 && !drivers[prov] && !strings.HasPrefix(prov, "kubernetes.io/"):
					orphaned = append(orphaned, fmt.Sprintf("%s (%s)", sc.Name, prov))
				default:
					detail = append(detail, fmt.Sprintf("%s: %s — %d/%d %s Running, registered on %d/%d nodes",
						sc.Name, prov, len(matched), len(matched), Plural(len(matched), "pod", "pods"),
						registered[prov], nodeCount))
				}
				if len(matched) > 0 {
					evidence = append(evidence, engine.Evidence{
						What:   fmt.Sprintf("pods implementing %s (matched by driver name in args/env, or by image and pod name)", prov),
						Output: stPodTable(matched, c.Now()),
					})
				}
			}

			if len(broken) > 0 {
				return ch.Fail(
					"the CSI driver behind "+Plural(len(broken), "a class", "classes")+" the install uses is not running, so its PVCs stay Pending and every workload mounting one stays Pending with it",
					"fix the driver before installing: kubectl -n <namespace> describe pod <pod> and kubectl -n <namespace> logs <pod> --previous — a crashlooping node plugin is usually a missing kernel module, a missing device, or a host path the pod cannot see",
					broken...).
					WithEvidence(evidence...)
			}
			if len(orphaned) > 0 {
				return ch.Fail(
					"nothing is registered to provision "+strings.Join(orphaned, ", ")+": there is no CSIDriver object and no pod that answers to that provisioner, so its claims are never acted on",
					"install the CSI driver the class names, or repoint the values at a class whose driver is installed: kubectl get csidrivers",
					"a class can be created before its driver; the claim then waits forever with no event other than the provisioner name").
					WithEvidence(evidence...)
			}
			if len(static) > 0 && len(detail) == 0 {
				return ch.FailAs(engine.Risk,
					strings.Join(static, ", ")+" uses kubernetes.io/no-provisioner: nothing creates volumes dynamically, so each claim needs a PersistentVolume made by hand before it can bind",
					"either point the values at a dynamic class, or pre-create one PV per claim (the bud chart alone makes 4, before the addons) — kubectl get pv",
					"storage.provision is the authoritative answer for this class")
			}
			return ch.Pass(
				fmt.Sprintf("the %s behind %s healthy",
					Plural(len(detail), "CSI driver", "CSI drivers"), Plural(len(cands), "the candidate class is", "every candidate class is")),
				append(detail, "candidates: "+why)...).
				WithEvidence(evidence...).
				Bounds("that the driver provisions — a Running pod with a registered CSINode entry still fails on a full backend, a missing volume group or a bad secret; storage.provision is what binds a claim")
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.expansion", Group: "storage", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.expansion")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: no StorageClass could be read")
			}
			classes := stLoadClasses(ctx, c)
			if len(classes) == 0 {
				return ch.Skip("the cluster has no StorageClass (see storage.default-class)")
			}
			d := stDemandOf(c)
			growth, why := stGrowthClasses(classes, d)
			if len(growth) == 0 {
				return ch.Skip("could not identify which class backs the volumes that grow: " + why)
			}

			fixed := []string{}
			ok := []string{}
			for _, sc := range growth {
				if sc.Expansion {
					ok = append(ok, fmt.Sprintf("%s (%s)", sc.Name, sc.Provisioner))
					continue
				}
				fixed = append(fixed, fmt.Sprintf("%s (%s) backs %s", sc.Name, sc.Provisioner, strings.Join(Sorted(d.Growth[sc.Name]), ", ")))
			}
			ev := engine.Evidence{What: "kubectl get storageclass -o custom-columns=NAME:.metadata.name,EXPANSION:.allowVolumeExpansion", Output: stClassTable(classes)}

			if len(fixed) > 0 {
				return ch.Fail(
					strings.Join(stClassNamesByExpansion(growth, false), ", ")+" has allowVolumeExpansion unset, so the model registry and the ClickHouse volume can only be grown by deleting the PVC and re-downloading every model",
					"set it before the volumes have data in them: kubectl patch storageclass <name> -p '{\"allowVolumeExpansion\":true}' — the field is mutable, but it only affects claims resized after the change",
					append(fixed, "growth-prone volumes: "+why)...).
					WithEvidence(ev)
			}
			return ch.Pass("allowVolumeExpansion is set on "+strings.Join(ok, ", "), "growth-prone volumes: "+why).
				WithEvidence(ev).
				Bounds("that expansion works — the driver must also advertise the EXPAND_VOLUME capability, and an offline-only driver still needs the pod restarted to finish a resize")
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.capacity", Group: "storage", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.capacity")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: no capacity source could be read")
			}
			classes := stLoadClasses(ctx, c)
			if len(classes) == 0 {
				return ch.Skip("the cluster has no StorageClass (see storage.default-class)")
			}
			cands, why := stCandidates(classes, stDemandOf(c))
			if len(cands) == 0 {
				return ch.Skip("no candidate StorageClass could be identified: " + why)
			}

			requiredGi := c.Answers.RequiredStorageGi(c.Profile)
			required := Gi(requiredGi)
			// One definition of the arithmetic, shared with the intake form, so the
			// number the operator was shown and the number judged cannot drift.
			breakdown := c.Answers.ExplainStorage(c.Profile)

			var known float64
			var maxVol float64
			sources, unverified, lines := []string{}, []string{}, []string{}
			evidence := []engine.Evidence{}
			for _, sc := range cands {
				src := stClassCapacity(ctx, c, sc)
				if src == nil {
					unverified = append(unverified, fmt.Sprintf("%s (%s)", sc.Name, sc.Provisioner))
					continue
				}
				known += src.Bytes
				if src.MaxVol > maxVol {
					maxVol = src.MaxVol
				}
				sources = append(sources, src.From)
				lines = append(lines, fmt.Sprintf("%s: %s provisionable, from %s", sc.Name, HumanBytes(src.Bytes), src.From))
				if fit := stSegmentFit(src.Segments, Gi(c.Answers.ModelStorageGi)); fit != "" {
					lines = append(lines, sc.Name+": "+fit)
				}
				evidence = append(evidence, engine.Evidence{What: src.What, Output: src.Output})
			}

			reqLine := fmt.Sprintf("required %d GiB = %s", requiredGi, breakdown)

			totalGauge := engine.Gauge{Label: "provisionable", Have: known, Need: required, Unit: "bytes"}
			gauges := []engine.Gauge{}
			if len(sources) > 0 {
				gauges = append(gauges, totalGauge)
			}
			if maxVol > 0 && c.Answers.ModelStorageGi > 0 {
				gauges = append(gauges, engine.Gauge{
					Label: "largest single volume", Have: maxVol, Need: Gi(c.Answers.ModelStorageGi), Unit: "bytes",
				})
			}

			// A single claim cannot be split across topology segments, so a
			// maximumVolumeSize under the model-registry claim is short even
			// when the summed total looks ample.
			if maxVol > 0 && c.Answers.ModelStorageGi > 0 && maxVol < Gi(c.Answers.ModelStorageGi) {
				return ch.Fail(
					fmt.Sprintf("the largest single volume the driver will provision is %s, below the %d GiB model registry claim — that one PVC never binds, however much total capacity exists",
						HumanBytes(maxVol), c.Answers.ModelStorageGi),
					fmt.Sprintf("either add a backing device large enough for a single %d GiB volume, or lower modelStorageGi in the answers file and hold fewer models",
						c.Answers.ModelStorageGi),
					append(lines, reqLine)...).
					WithEvidence(evidence...).WithGauges(gauges...)
			}

			switch {
			case len(sources) == 0:
				// Never a silent pass: no source means budctl does not know,
				// and "we did not look" is not "we looked and it was fine".
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("provisionable capacity is UNVERIFIED for %s: the driver publishes no CSIStorageCapacity, there is no OpenEBS DiskPool, and the class is not node-local — %s could be short and the install would fail mid-sync",
						strings.Join(unverified, ", "), reqLine),
					"check the backend by hand before installing — `vgs` for LVM, `kubectl get diskpool -A` for Mayastor, the cloud console quota for EBS/Azure Disk — and confirm it holds "+fmt.Sprintf("%d GiB", requiredGi),
					append(lines, "budctl will not guess: an unmeasured backend is reported as unknown, not as sufficient")...).
					WithEvidence(evidence...)

			case known < required && len(unverified) == 0:
				return ch.Fail(
					fmt.Sprintf("%s provisionable across the candidate classes, %d GiB required — the model registry and the data stores run out mid-install and their pods stay Pending",
						HumanBytes(known), requiredGi),
					fmt.Sprintf("add backing capacity (%s more), or lower modelStorageGi / observabilityRetentionDays in the answers file: the requirement is derived from them, not from a fixed profile",
						HumanBytes(required-known)),
					append(lines, reqLine)...).
					WithEvidence(evidence...).WithGauges(gauges...)

			case known < required:
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("only %s of the %d GiB required is measurable; %s publish no capacity source, so the shortfall is unconfirmed rather than disproven",
						HumanBytes(known), requiredGi, strings.Join(unverified, ", ")),
					"measure the unverified backends by hand (`vgs`, `kubectl get diskpool -A`, or the cloud console) and confirm the total reaches "+fmt.Sprintf("%d GiB", requiredGi),
					append(lines, reqLine)...).
					WithEvidence(evidence...)
			}

			res := ch.Pass(
				fmt.Sprintf("%s provisionable, %d GiB required", HumanBytes(known), requiredGi),
				append(lines, reqLine, "candidates: "+why)...).
				WithEvidence(evidence...).WithGauges(gauges...)
			if len(unverified) > 0 {
				res = res.With("unverified (no capacity source): " + strings.Join(unverified, ", "))
			}
			return res.Bounds("that the capacity is contiguous or reachable from the node a pod lands on: a summed figure spread over per-node segments still fails a single large claim, and a driver that reports per-node capacity for one shared pool over-reports the total")
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.shared-rwo", Group: "storage", Severity: engine.Risk,
		DependsOn: []string{"config"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.shared-rwo")
			rendered := Rendered(c)
			if len(rendered) == 0 {
				return ch.Skip("no chart render: pass --chart and --values to check which workloads share a claim")
			}
			modes, mounts := stClaimModes(rendered), stClaimMounters(rendered)

			var shared []string
			evidence := []engine.Evidence{}
			for _, claim := range Sorted(stMountedClaims(mounts)) {
				users := stNodeNames(mounts[claim])
				if len(users) < 2 || stHasMode(modes[claim], "ReadWriteMany") {
					continue
				}
				// An absent claim is one the chart does not create — an existing
				// volume the operator supplies — and its access mode is unknown
				// here, so it is not judged.
				if _, known := modes[claim]; !known {
					continue
				}
				shared = append(shared, fmt.Sprintf("%s (%s) is mounted by %d workloads: %s",
					claim, strings.Join(modes[claim], ","), len(users), strings.Join(Sorted(users), ", ")))
				evidence = append(evidence, engine.Evidence{
					What:   "rendered workloads mounting " + claim,
					Output: strings.Join(Sorted(users), "\n"),
				})
			}
			if len(shared) == 0 {
				return ch.Pass("no ReadWriteOnce claim is mounted by more than one workload").
					Bounds("that each workload fits the node its volume lands on — that is nodes.capacity — nor anything about claims the chart does not create")
			}
			return ch.Fail(
				fmt.Sprintf("%d ReadWriteOnce %s mounted by several workloads at once, which silently pins all of them to whichever node the volume lands on",
					len(shared), Plural(len(shared), "claim is", "claims are")),
				"either give those workloads a ReadWriteMany class that can actually serve it, or accept the co-location and make sure that one node can hold every pod that mounts the claim — when it cannot, the extra pods stay Pending with a multi-attach error, and draining that node takes all of them down together",
				shared...).
				WithEvidence(evidence...)
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.rwx", Group: "storage", Severity: engine.Block,
		DependsOn: []string{"config"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.rwx")
			rendered := Rendered(c)
			if len(rendered) == 0 {
				return ch.Skip("no chart render: pass --chart and --values to check the access modes the chart asks for")
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the provisioner behind each class could not be read")
			}
			classes := stLoadClasses(ctx, c)
			byName, dflt := map[string]stClass{}, ""
			for _, sc := range classes {
				byName[sc.Name] = sc
				if sc.Default {
					dflt = sc.Name
				}
			}

			var incapable, unknown, ok []string
			for claim, modes := range stClaimModes(rendered) {
				if !stHasMode(modes, "ReadWriteMany") {
					continue
				}
				name := stClaimClass(rendered, claim)
				if name == "" {
					name = dflt
				}
				sc, found := byName[name]
				if !found {
					unknown = append(unknown, fmt.Sprintf("%s → class %q is not in the cluster (see storage.named-classes)", claim, name))
					continue
				}
				switch stRWXSupport(sc.Provisioner) {
				case rwxNo:
					incapable = append(incapable, fmt.Sprintf("%s → %s (%s) serves one node at a time", claim, sc.Name, sc.Provisioner))
				case rwxYes:
					ok = append(ok, fmt.Sprintf("%s → %s (%s)", claim, sc.Name, sc.Provisioner))
				default:
					unknown = append(unknown, fmt.Sprintf("%s → %s (%s): budctl does not know whether this driver serves ReadWriteMany", claim, sc.Name, sc.Provisioner))
				}
			}

			switch {
			case len(incapable) > 0:
				return ch.Fail(
					fmt.Sprintf("%d ReadWriteMany %s a class whose provisioner serves one node at a time — the first pod binds it and every other pod fails to mount",
						len(incapable), Plural(len(incapable), "claim asks", "claims ask")),
					"point those claims at a file-based class (NFS, CephFS, SeaweedFS, EFS, Azure Files) or drop the requirement to ReadWriteOnce and accept that the pods must share a node",
					append(incapable, ok...)...)
			case len(unknown) > 0:
				return ch.Skip("ReadWriteMany is requested on a driver budctl cannot classify, so it is unverified rather than approved: " + strings.Join(unknown, "; "))
			case len(ok) > 0:
				return ch.Pass(fmt.Sprintf("all %d ReadWriteMany %s a file-based class", len(ok), Plural(len(ok), "claim is on", "claims are on")), ok...).
					Bounds("that the driver is configured to serve it here — an NFS server with no exports, or a CephFS without a filesystem, still fails at mount time")
			}
			return ch.Pass("the chart asks for no ReadWriteMany claim, so no shared-filesystem driver is required")
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.host-prereqs", Group: "storage", Severity: engine.Risk,
		DependsOn: []string{"platform", "config"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.host-prereqs")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: no StorageClass parameters could be read")
			}
			classes := stLoadClasses(ctx, c)
			if len(classes) == 0 {
				return ch.Skip("the cluster has no StorageClass (see storage.default-class)")
			}
			cands, why := stCandidates(classes, stDemandOf(c))
			if len(cands) == 0 {
				return ch.Skip("no candidate StorageClass could be identified: " + why)
			}

			// Read .parameters generically. Hardcoding "if provisioner ==
			// openebs-lvm then check volgroup" would be wrong on the next
			// driver; the parameter key is what states the host requirement,
			// whoever implements it.
			nodes := nodesGather(ctx, c)
			var usable []string
			for _, n := range nodes {
				if n.Usable() {
					usable = append(usable, n.Name)
				}
			}

			reqs, evidence := []string{}, []engine.Evidence{}
			var proven, unproven, missing []string
			for _, sc := range cands {
				if len(sc.Params) == 0 {
					continue
				}
				evidence = append(evidence, engine.Evidence{
					What:   fmt.Sprintf("kubectl get storageclass %s -o jsonpath='{.parameters}'", sc.Name),
					Output: stParamTable(sc),
				})
				var pooled []string
				for _, key := range Sorted(stParamKeys(sc.Params)) {
					r, corroborable := stHostRequirement(key, sc.Params[key])
					if r == "" {
						continue
					}
					reqs = append(reqs, fmt.Sprintf("%s → %s", sc.Name, r))
					if corroborable {
						pooled = append(pooled, r)
					}
				}
				if len(pooled) == 0 {
					continue
				}
				// A node the driver publishes capacity from has the pool: the
				// figure is read off the host. This is what turns "nobody can
				// see this" into an answer on a cluster that is already running.
				covered, published := stCapacityNodes(ctx, c, sc, nodes)
				if !published {
					unproven = append(unproven, fmt.Sprintf("%s: the driver publishes no CSIStorageCapacity, so nothing here can confirm %s", sc.Name, Plural(len(pooled), "it", "them")))
					continue
				}
				var without []string
				for _, n := range usable {
					if !covered[n] {
						without = append(without, n)
					}
				}
				line := fmt.Sprintf("%s: the driver publishes capacity from %d of %d schedulable %s",
					sc.Name, len(covered), len(usable), Plural(len(usable), "node", "nodes"))
				if len(without) > 0 {
					missing = append(missing, line+" — not "+strings.Join(Sorted(without), ", "))
					continue
				}
				proven = append(proven, line+", which it can only read from a host that has it")
				evidence = append(evidence, engine.Evidence{
					What:   fmt.Sprintf("kubectl get csistoragecapacities -A (storageClassName=%s) → nodes", sc.Name),
					Output: strings.Join(Sorted(stNodeNames(covered)), "\n"),
				})
			}

			if len(reqs) == 0 {
				return ch.Pass("no candidate StorageClass carries a parameter that implies host-level state",
					"candidates: "+why).
					WithEvidence(evidence...).
					Bounds("that the nodes are prepared: a driver can require host state its parameters never name — a kernel module, a device, a mount")
			}

			// A pool the driver cannot see on a node is the real finding, and it
			// is node-specific: everything binds until a pod lands there.
			if len(missing) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d %s where the pool behind the StorageClass is not visible on every schedulable node, so a claim scheduled there stays Pending while the rest of the cluster works",
						len(missing), Plural(len(missing), "class", "classes")),
					"create the volume group or pool on the nodes named below, or keep the workloads off them with a nodeSelector — a claim that lands on a node without the pool never binds",
					append(append(missing, reqs...), "candidates: "+why)...).
					WithEvidence(evidence...)
			}

			if len(proven) > 0 {
				return ch.Pass("the pool behind every candidate StorageClass is visible on every schedulable node",
					append(append(proven, reqs...), "candidates: "+why)...).
					WithEvidence(evidence...).
					Bounds("the requirements capacity cannot speak for — a filesystem type, a directory, a kernel module — nor that provisioning works: storage.provision is what binds a real claim")
			}

			remedy := "verify on every node that could run a workload, before installing — `vgs`, `zpool list`, `cat /proc/filesystems`, `ls -ld <path>` — a claim whose host prerequisite is missing on one node fails only when it lands there"
			if c.Platform.IsOpenShift() {
				// On OpenShift nodes are immutable: an operator who ssh'es in
				// and runs vgcreate loses it on the next MachineConfig roll.
				remedy = "verify on every node with `oc debug node/<name> -- chroot /host vgs` (or zpool list / cat /proc/filesystems), and make any change through a MachineConfig or the LVM Storage operator — a change made by hand on an RHCOS node does not survive the next MachineConfig roll"
			}
			// Nothing here says the host state is absent — only that this run
			// could not confirm it. The consequence belongs in the remedy; put
			// it in the summary and a working cluster reads as a broken one.
			return ch.Fail(
				fmt.Sprintf("%d StorageClass %s name host state that could not be confirmed from the API on this run",
					len(reqs), Plural(len(reqs), "parameter", "parameters")),
				remedy,
				append(append(reqs, unproven...), "candidates: "+why)...).
				WithEvidence(evidence...)
		},
	})

	engine.Register(&engine.Check{
		ID: "storage.provision", Group: "storage", Severity: engine.Block, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("storage.provision")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: no PVC could be created")
			}
			if c.Probes == nil {
				return ch.Skip("probes are disabled (--no-probe): no claim was created, so provisioning is not confirmed working")
			}
			classes := stLoadClasses(ctx, c)
			if len(classes) == 0 {
				return ch.Skip("the cluster has no StorageClass, so there is nothing to provision from (see storage.default-class)")
			}
			cands, why := stCandidates(classes, stDemandOf(c))
			if len(cands) == 0 {
				return ch.Skip("no candidate StorageClass could be identified: " + why)
			}

			per := stPerClassTimeout(ctx, len(cands))
			bound, failed, sched := []string{}, []string{}, []string{}
			evidence := []engine.Evidence{}
			for i, sc := range cands {
				name := fmt.Sprintf("budctl-probe-%d", i)
				// 1 GiB, not the real size: provisioning 600 GiB to prove the
				// provisioner works would allocate 600 GiB for real.
				//
				// ProvisionPVC attaches a consumer pod, and that is mandatory
				// rather than thorough: a WaitForFirstConsumer class binds
				// nothing until a pod referencing the claim is scheduled, so a
				// claim-only probe would report every such class as broken.
				ok, phase, events, err := c.Probes.ProvisionPVC(ctx, name, sc.Name, "1Gi", per)
				out := strings.Join(events, "\n")
				if err != nil {
					out = strings.TrimSpace(out + "\n" + err.Error())
				}
				evidence = append(evidence, engine.Evidence{
					What:   fmt.Sprintf("1Gi PVC + consumer pod in class %s (namespace %s), phase=%s", sc.Name, c.Probes.Namespace(), stOrUnset(phase)),
					Output: stOrUnset(out),
				})
				if ok {
					bound = append(bound, fmt.Sprintf("%s (%s, %s)", sc.Name, sc.Provisioner, stOrUnset(sc.Binding)))
					continue
				}
				// A pod that never schedules and a provisioner that never
				// provisions look identical from the claim's phase, and they
				// have opposite remedies — one is taints and node capacity,
				// the other is the storage backend.
				if stSchedulingFailure(ctx, c, name+"-consumer") {
					sched = append(sched, fmt.Sprintf("%s: the consumer pod was never scheduled (phase %s) — %s",
						sc.Name, stOrUnset(phase), stFirstEvent(events)))
					continue
				}
				failed = append(failed, fmt.Sprintf("%s (%s): PVC %s after %s — %s",
					sc.Name, sc.Provisioner, stOrUnset(phase), per, stFirstEvent(events)))
			}

			switch {
			case len(sched) > 0 && len(failed) == 0:
				return ch.Fail(
					"the probe never reached the provisioner: its consumer pod could not be scheduled, so this is a scheduling failure, not a storage one — and the real workloads will not schedule either",
					"fix scheduling first and re-run `budctl check --only storage`: kubectl describe pod in the probe namespace names the reason — a taint with no matching toleration (no chart in infra/charts declares one), insufficient CPU/memory, or node affinity",
					sched...).
					WithEvidence(evidence...)

			case len(failed) > 0 || len(sched) > 0:
				return ch.Fail(
					fmt.Sprintf("a 1 GiB claim in %s did not bind, so every PVC the install creates there stays Pending and no workload mounting one ever starts",
						stQuoteList(stClassesInLines(failed, sched))),
					"read the Event verbatim above — it is the provisioner's own explanation. Fix the backend (volume group, pool, quota, credentials) or point the values at a class that binds, then re-run `budctl check --only storage`",
					append(failed, sched...)...).
					WithEvidence(evidence...)
			}

			return ch.Pass(
				fmt.Sprintf("a 1 GiB claim bound in %s: %s", Plural(len(bound), "the candidate class", "every candidate class"), strings.Join(bound, ", ")),
				"candidates: "+why,
				"the probe PVC and its consumer pod were deleted").
				WithEvidence(evidence...).
				Bounds(fmt.Sprintf("that a %d GiB claim will bind: the probe is deliberately 1 GiB, because provisioning the real size would allocate it for real — storage.capacity sizes the backend instead", c.Answers.ModelStorageGi))
		},
	})
}

// ---------------------------------------------------------------------------
// StorageClass model
// ---------------------------------------------------------------------------

// stClass is the subset of the object this group reasons about. Note that
// provisioner, parameters and allowVolumeExpansion sit at the TOP level of a
// StorageClass, not under spec.
type stClass struct {
	Name        string
	Provisioner string
	Binding     string
	Default     bool
	Expansion   bool
	Params      map[string]string
}

func stLoadClasses(ctx context.Context, c *engine.Ctx) []stClass {
	out := []stClass{}
	for _, o := range c.Kube.List(ctx, stSCResource, "") {
		sc := stClass{
			Name:        o.Name(),
			Provisioner: o.DigString("provisioner"),
			Binding:     o.DigString("volumeBindingMode"),
			Params:      map[string]string{},
		}
		if b, ok := o.Dig("allowVolumeExpansion").(bool); ok {
			sc.Expansion = b
		}
		if p, ok := o.Dig("parameters").(map[string]any); ok {
			for k, v := range p {
				sc.Params[k] = fmt.Sprint(v)
			}
		}
		ann := o.Annotations()
		// The beta annotation is what several distributions still ship, and a
		// class carrying only it is still the default the binder picks.
		sc.Default = ann[stDefaultAnn] == "true" || ann[stDefaultAnnBeta] == "true"
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func stClassByName(classes []stClass, name string) stClass {
	for _, sc := range classes {
		if sc.Name == name {
			return sc
		}
	}
	return stClass{Name: name}
}

func stClassTable(classes []stClass) string {
	if len(classes) == 0 {
		return "(no StorageClass objects)"
	}
	var b strings.Builder
	for _, sc := range classes {
		fmt.Fprintf(&b, "%s\tprovisioner=%s\tdefault=%t\texpansion=%t\tbinding=%s\n",
			sc.Name, stOrUnset(sc.Provisioner), sc.Default, sc.Expansion, stOrUnset(sc.Binding))
	}
	return strings.TrimRight(b.String(), "\n")
}

func stClassDetail(classes []stClass) []string {
	out := []string{}
	for _, sc := range classes {
		out = append(out, fmt.Sprintf("existing class %s (%s), default=%t", sc.Name, stOrUnset(sc.Provisioner), sc.Default))
	}
	return out
}

func stClassNames(classes []stClass) []string {
	out := []string{}
	for _, sc := range classes {
		out = append(out, sc.Name)
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

func stClassNamesByExpansion(classes []stClass, expansion bool) []string {
	out := []string{}
	for _, sc := range classes {
		if sc.Expansion == expansion {
			out = append(out, sc.Name)
		}
	}
	if len(out) == 0 {
		return []string{"the class backing the growing volumes"}
	}
	return out
}

func stFirstClassName(classes []stClass) string {
	if len(classes) == 0 {
		return "<class>"
	}
	return classes[0].Name
}

func stPatchDefaultCmd(name string) string {
	return fmt.Sprintf("kubectl patch storageclass %s -p '{\"metadata\":{\"annotations\":{\"%s\":\"true\"}}}'", name, stDefaultAnn)
}

// ---------------------------------------------------------------------------
// What the install will ask of storage
// ---------------------------------------------------------------------------

// stDemand is derived from the values the operator will hand to ArgoCD,
// never from a hardcoded list of claim names.
type stDemand struct {
	Named        map[string][]string // class name -> the paths that name it
	DefaultUsers []string            // the claims that leave storageClassName empty
	Growth       map[string][]string // class name -> growth-prone claims it backs
	GrowthOnDflt []string            // growth-prone claims that rely on the default
	Source       string
}

func (d stDemand) NamedList() []string {
	out := []string{}
	for k := range d.Named {
		out = append(out, k)
	}
	return out
}

// stChartClaimPaths are the values paths the umbrella chart's own PVCs read.
// Every one of them defaults to an EMPTY className in infra/charts/bud, which
// is precisely why a default StorageClass is a prerequisite (FRD-020 §5.7).
var stChartClaimPaths = []string{
	"storage.budmodelRegistry.className",
	"storage.budmodelAddDir.className",
	"storage.budevalDataset.className",
	"storage.budappStaticDir.className",
	"microservices.budcache.persistence.className",
}

// stDemandOf reads the rendered chart when the config group has already run,
// and the values files directly otherwise. The group order puts storage before
// config, so the values files are the source that normally fires.
func stDemandOf(c *engine.Ctx) stDemand {
	d := stDemand{Named: map[string][]string{}, Growth: map[string][]string{}}

	rendered := Rendered(c)
	if len(rendered) > 0 {
		stCollectRendered(rendered, &d)
		d.Source = "the rendered chart"
	}
	var vals map[string]any
	if c.Helm != nil && len(c.Opts.ValuesFiles) > 0 {
		if v, err := c.Helm.MergeValues(EffectiveValuesFiles(c)); err == nil {
			vals = v
			stCollectValues("", vals, &d)
			d.Source = stJoinSource(d.Source, fmt.Sprintf("%d values %s", len(c.Opts.ValuesFiles), Plural(len(c.Opts.ValuesFiles), "file", "files")))
		}
	}
	// A values file that never mentions storage does not make the chart's own
	// defaults go away — each of these claims falls back to an empty className.
	// Only a render supersedes them, because a render has already applied them.
	if len(rendered) == 0 {
		for _, path := range stChartClaimPaths {
			if stMentions(d, path) {
				continue
			}
			if s, _ := stDigValue(vals, path); strings.TrimSpace(s) == "" {
				stRecordClaim(&d, path, "")
			}
		}
		d.Source = stJoinSource(d.Source, "the chart's own defaults")
	}
	if d.Source == "" {
		d.Source = "the chart's own defaults (no --values supplied)"
	}
	return d
}

// stDigValue reads a dotted path out of merged values. Absent and empty are
// the same answer for this group — both land on the default class — but the
// lookup is kept explicit so the caller reads as the question it is asking.
func stDigValue(vals map[string]any, path string) (string, bool) {
	var cur any = vals
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = m[seg]; !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

func stMentions(d stDemand, path string) bool {
	for _, p := range d.DefaultUsers {
		if p == path {
			return true
		}
	}
	for _, claims := range d.Named {
		for _, p := range claims {
			if p == path {
				return true
			}
		}
	}
	return false
}

func stJoinSource(a, b string) string {
	if a == "" {
		return b
	}
	return a + " and " + b
}

func stCollectRendered(objs []adapters.Object, d *stDemand) {
	for _, o := range objs {
		switch o.Kind() {
		case "PersistentVolumeClaim":
			stRecordClaim(d, o.Name(), o.DigString("spec", "storageClassName"))
		case "StatefulSet":
			for _, raw := range o.DigSlice("spec", "volumeClaimTemplates") {
				m, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				t := adapters.Object(m)
				stRecordClaim(d, o.Name()+"/"+t.Name(), t.DigString("spec", "storageClassName"))
			}
		}
	}
}

// stRecordClaim treats an absent and an empty storageClassName alike. They differ
// in the API — a literal "" disables dynamic provisioning entirely — but a
// chart that renders `storageClassName: {{ .className }}` with an empty value
// produces a null, and both cases end with a claim that binds nothing unless a
// default exists. Erring toward "relies on a default" errs toward the answer
// that blocks.
func stRecordClaim(d *stDemand, claim, class string) {
	if strings.TrimSpace(class) == "" {
		d.DefaultUsers = append(d.DefaultUsers, claim)
		if stIsGrowthClaim(claim) {
			d.GrowthOnDflt = append(d.GrowthOnDflt, claim)
		}
		return
	}
	d.Named[class] = append(d.Named[class], claim)
	if stIsGrowthClaim(claim) {
		d.Growth[class] = append(d.Growth[class], claim)
	}
}

func stCollectValues(prefix string, node any, d *stDemand) {
	switch v := node.(type) {
	case map[string]any:
		for k, sub := range v {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if stIsClassKey(k, path) {
				switch s := sub.(type) {
				case string:
					stRecordClaim(d, path, s)
					continue
				case nil:
					stRecordClaim(d, path, "")
					continue
				}
			}
			stCollectValues(path, sub, d)
		}
	case []any:
		for i, sub := range v {
			stCollectValues(fmt.Sprintf("%s[%d]", prefix, i), sub, d)
		}
	}
}

// stIsClassKey recognises the three spellings charts use. "className" on
// its own is ambiguous — ingress.className is an IngressClass — so it counts
// only under a storage-ish path, or a values file would produce a phantom
// "StorageClass traefik does not exist" blocker.
func stIsClassKey(key, path string) bool {
	switch strings.ToLower(key) {
	case "storageclass", "storageclassname":
		return true
	case "classname":
		lp := strings.ToLower(path)
		return strings.Contains(lp, "storage") || strings.Contains(lp, "persist") ||
			strings.Contains(lp, "volume") || strings.Contains(lp, "pvc")
	}
	return false
}

// Volumes that grow without an operator touching them: the model registry
// fills as models are added, and the observability store fills with retention.
var stGrowthTokens = []string{"budmodel", "modelregistry", "model-registry", "registry", "adddir", "add-dir", "clickhouse", "signoz", "chi-", "seaweedfs"}

func stIsGrowthClaim(name string) bool {
	l := strings.ToLower(name)
	for _, t := range stGrowthTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// stCandidates is the set storage.provision and the capacity checks act on:
// the classes this install will actually use. Probing every class in a cluster
// that has ten would create ten volumes to answer a question about one.
func stCandidates(classes []stClass, d stDemand) ([]stClass, string) {
	seen, out, reasons := map[string]bool{}, []stClass{}, []string{}
	for _, name := range Sorted(d.NamedList()) {
		if sc := stClassByName(classes, name); sc.Provisioner != "" && !seen[name] {
			seen[name] = true
			out = append(out, sc)
			reasons = append(reasons, name+" (named in "+d.Source+")")
		}
	}
	if len(d.DefaultUsers) > 0 {
		for _, sc := range classes {
			if sc.Default && !seen[sc.Name] {
				seen[sc.Name] = true
				out = append(out, sc)
				reasons = append(reasons, sc.Name+" (the default, relied on by "+fmt.Sprint(len(d.DefaultUsers))+" claims)")
			}
		}
	}
	if len(out) == 0 {
		// Nothing identifiable: test what the cluster has rather than nothing,
		// capped so a large cluster does not turn into a volume farm.
		for _, sc := range classes {
			if len(out) >= 3 {
				break
			}
			out = append(out, sc)
			reasons = append(reasons, sc.Name+" (no class is named and none is default; testing what exists)")
		}
	}
	if len(reasons) == 0 {
		return out, "no StorageClass in the cluster"
	}
	return out, strings.Join(reasons, "; ")
}

func stGrowthClasses(classes []stClass, d stDemand) ([]stClass, string) {
	seen, out, reasons := map[string]bool{}, []stClass{}, []string{}
	for name, claims := range d.Growth {
		if sc := stClassByName(classes, name); sc.Provisioner != "" && !seen[name] {
			seen[name] = true
			out = append(out, sc)
			reasons = append(reasons, name+" backs "+strings.Join(Sorted(claims), ", "))
		}
	}
	if len(d.GrowthOnDflt) > 0 {
		for _, sc := range classes {
			if sc.Default && !seen[sc.Name] {
				seen[sc.Name] = true
				out = append(out, sc)
				reasons = append(reasons, sc.Name+" is the default, which backs "+strings.Join(Sorted(d.GrowthOnDflt), ", "))
				d.Growth[sc.Name] = d.GrowthOnDflt
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, "no claim that grows maps to an existing class (source: " + d.Source + ")"
	}
	return out, strings.Join(reasons, "; ")
}

// ---------------------------------------------------------------------------
// CSI driver health
// ---------------------------------------------------------------------------

// stDriverPods finds the pods behind a provisioner without a per-driver table.
// The strong signal is the driver name appearing in a container's args or env
// (--driver-name=, --csi-address=, --provisioner=); the fallback is a
// distinctive token from the provisioner string in the pod name or image.
func stDriverPods(pods []adapters.Object, provisioner string) []adapters.Object {
	if provisioner == "" {
		return nil
	}
	tokens := stDistinctiveTokens(provisioner)
	out := []adapters.Object{}
	for _, p := range pods {
		if stPodMentions(p, provisioner) || stPodMatchesToken(p, tokens) {
			out = append(out, p)
		}
	}
	return out
}

// generic drops the parts of a provisioner name that every driver shares, so
// "local.csi.openebs.io" matches on "openebs" and not on "csi".
var stGenericTokens = map[string]bool{
	"csi": true, "io": true, "com": true, "org": true, "net": true, "sh": true,
	"k8s": true, "kubernetes": true, "sigs": true, "driver": true, "storage": true,
	"provisioner": true, "dev": true, "local": true, "cloud": true,
}

func stDistinctiveTokens(provisioner string) []string {
	out := []string{}
	for _, part := range strings.FieldsFunc(provisioner, func(r rune) bool { return r == '.' || r == '/' }) {
		if p := strings.ToLower(part); !stGenericTokens[p] && len(p) >= 3 {
			out = append(out, p)
		}
	}
	return out
}

func stPodMentions(p adapters.Object, needle string) bool {
	for _, ctr := range p.Containers() {
		for _, field := range []string{"command", "args"} {
			if list, ok := ctr[field].([]any); ok {
				for _, a := range list {
					if s, ok := a.(string); ok && strings.Contains(s, needle) {
						return true
					}
				}
			}
		}
		if env, ok := ctr["env"].([]any); ok {
			for _, e := range env {
				if em, ok := e.(map[string]any); ok {
					if s, ok := em["value"].(string); ok && strings.Contains(s, needle) {
						return true
					}
				}
			}
		}
	}
	return false
}

func stPodMatchesToken(p adapters.Object, tokens []string) bool {
	hay := strings.ToLower(p.Name())
	for _, ctr := range p.Containers() {
		if img, ok := ctr["image"].(string); ok {
			hay += " " + strings.ToLower(img)
		}
	}
	for _, t := range tokens {
		if stTokenIn(hay, t) {
			return true
		}
	}
	return false
}

// stTokenIn matches a token only where it stands as its own word. A plain
// substring match reads "ebs" (from ebs.csi.aws.com) out of the image
// "openebs/lvm-driver" and reports an unrelated driver's pods as this
// driver's — which, with the pod-health check above, is a fabricated blocker.
func stTokenIn(hay, token string) bool {
	for i := 0; i+len(token) <= len(hay); i++ {
		if hay[i:i+len(token)] != token {
			continue
		}
		if i > 0 && stIsAlnum(hay[i-1]) {
			continue
		}
		if end := i + len(token); end < len(hay) && stIsAlnum(hay[end]) {
			continue
		}
		return true
	}
	return false
}

func stIsAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// stPodTrouble returns "" for a healthy pod and the reason otherwise. A pod is
// healthy when it is Running with every container ready, or when it has
// Succeeded — a one-shot registrar job is not a fault.
//
// A pod that is merely young is starting, not broken: without the grace period
// a driver rollout that happens to be in flight would be reported as a blocker,
// and a check that is flaky in that direction gets ignored.
func stPodTrouble(p adapters.Object, now time.Time) string {
	phase := p.DigString("status", "phase")
	worst := ""
	notReady := 0
	total := 0
	for _, raw := range p.DigSlice("status", "containerStatuses") {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		cs := adapters.Object(m)
		total++
		if ready, ok := cs.Dig("ready").(bool); !ok || !ready {
			notReady++
		}
		if r := cs.DigString("state", "waiting", "reason"); r != "" && r != "ContainerCreating" && r != "PodInitializing" {
			worst = r + ": " + strings.TrimSpace(cs.DigString("state", "waiting", "message"))
		}
	}
	switch {
	case worst != "":
		return "is " + worst
	case phase == "Succeeded":
		return ""
	case stPodAge(p, now) < 2*time.Minute:
		return ""
	case phase != "Running":
		return "is " + stOrUnset(phase)
	case total > 0 && notReady > 0:
		return fmt.Sprintf("has %d/%d containers not ready", notReady, total)
	}
	return ""
}

func stPodAge(p adapters.Object, now time.Time) time.Duration {
	ts, err := time.Parse(time.RFC3339, p.DigString("metadata", "creationTimestamp"))
	if err != nil {
		return time.Hour
	}
	return now.Sub(ts)
}

func stPodTable(pods []adapters.Object, now time.Time) string {
	var b strings.Builder
	for _, p := range pods {
		state := stPodTrouble(p, now)
		if state == "" {
			state = "Running, ready"
		}
		fmt.Fprintf(&b, "%s/%s\t%s\n", p.Namespace(), p.Name(), state)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

type stCapacity struct {
	Bytes  float64
	MaxVol float64
	From   string
	What   string
	Output string
	// Segments holds each topology segment's free capacity, largest first,
	// when the source has segments at all. A claim binds from one of them, so
	// how MANY can hold the biggest claim is the margin the sum hides.
	Segments []float64
}

// stClassCapacity tries the three sources in the order of how directly they
// answer the question, and returns nil when none of them does. Nil becomes an
// explicit "unverified" result — never a pass.
func stClassCapacity(ctx context.Context, c *engine.Ctx, sc stClass) *stCapacity {
	if src := stCSICapacity(ctx, c, sc); src != nil {
		return src
	}
	if src := stDiskPoolCapacity(ctx, c, sc); src != nil {
		return src
	}
	return stNodeEphemeral(ctx, c, sc)
}

// stCSICapacity is the driver's own published figure. Objects are per
// (class, topology segment): summing is right for a driver whose segments are
// separate pools (per-node LVM, per-zone EBS) and over-reports for one that
// republishes a single shared pool per node, which the result's Bounds says.
func stCSICapacity(ctx context.Context, c *engine.Ctx, sc stClass) *stCapacity {
	if !c.Kube.HasResource(ctx, "csistoragecapacities.storage.k8s.io") {
		return nil
	}
	var total, maxVol, largestSegment float64
	var segments int
	var sizes []float64
	var lines []string
	for _, o := range c.Kube.List(ctx, "csistoragecapacities.storage.k8s.io", "") {
		if o.DigString("storageClassName") != sc.Name {
			continue
		}
		// An absent capacity means "currently unavailable", not zero, so an
		// entry without one contributes nothing rather than dragging the sum.
		b, ok := stBytes(o.Dig("capacity"))
		if !ok {
			continue
		}
		total += b
		segments++
		sizes = append(sizes, b)
		if b > largestSegment {
			largestSegment = b
		}
		mv, haveMV := stBytes(o.Dig("maximumVolumeSize"))
		if haveMV && mv > maxVol {
			maxVol = mv
		}
		shown := "(unpublished)"
		if haveMV {
			shown = HumanBytes(mv)
		}
		lines = append(lines, fmt.Sprintf("%s/%s\tcapacity=%s\tmaxVolumeSize=%s", o.Namespace(), o.Name(), HumanBytes(b), shown))
	}
	if len(lines) == 0 {
		return nil
	}
	// A single PVC draws from ONE topology segment, never from the sum: a
	// node-local class with 275 GiB on one node and 1345 GiB on another cannot
	// bind a 600 GiB claim on the first, however large the total looks. When the
	// driver publishes maximumVolumeSize that figure is authoritative; when it
	// does not — as OpenEBS LVM does not — the largest segment is the ceiling,
	// and inferring it is far better than leaving it at zero and judging only
	// the sum. This is the same failure shape as nodes.largest-pod.
	from := "CSIStorageCapacity published by the driver"
	if maxVol == 0 && segments > 1 {
		maxVol = largestSegment
		from += fmt.Sprintf(", across %d topology segments (largest %s — the ceiling for any ONE volume, since the driver publishes no maximumVolumeSize)",
			segments, HumanBytes(largestSegment))
	} else if segments > 1 {
		from += fmt.Sprintf(", across %d topology segments", segments)
	}
	return &stCapacity{
		Bytes: total, MaxVol: maxVol, From: from, Segments: sizes,
		What:   fmt.Sprintf("kubectl get csistoragecapacities -A (storageClassName=%s)", sc.Name),
		Output: strings.Join(lines, "\n"),
	}
}

// stSegmentFit says how much of the capacity can actually take the largest
// single claim. "2.4 TiB free" reads as comfort; "one of four nodes can hold
// it" is the fact an operator needs, because the scheduler must then place that
// pod on that node and nothing else may consume the space first.
func stSegmentFit(segments []float64, claim float64) string {
	if claim <= 0 || len(segments) < 2 {
		return ""
	}
	fits := 0
	for _, b := range segments {
		if b >= claim {
			fits++
		}
	}
	switch fits {
	case 0:
		return "" // the blocker above already says this
	case 1:
		return fmt.Sprintf("exactly one of the %d segments can hold the %s claim on its own — that claim can only bind on that node, and only while nothing else takes the space first",
			len(segments), HumanBytes(claim))
	default:
		return fmt.Sprintf("%d of the %d segments can hold the %s claim on their own", fits, len(segments), HumanBytes(claim))
	}
}

// stDiskPoolCapacity reads OpenEBS Mayastor's pools. It is one branch of a
// capability probe, not a dependency: it runs only when that CRD is served and
// the class is served by an OpenEBS provisioner.
func stDiskPoolCapacity(ctx context.Context, c *engine.Ctx, sc stClass) *stCapacity {
	prov := strings.ToLower(sc.Provisioner)
	if !strings.Contains(prov, "openebs") && !strings.Contains(prov, "mayastor") {
		return nil
	}
	if !c.Kube.HasResource(ctx, "diskpools.openebs.io") {
		return nil
	}
	var pooled float64
	var lines []string
	for _, o := range c.Kube.List(ctx, "diskpools.openebs.io", "") {
		avail, ok := stBytes(o.Dig("status", "available"))
		if !ok {
			total, okTotal := stBytes(o.Dig("status", "capacity"))
			used, _ := stBytes(o.Dig("status", "used"))
			if !okTotal {
				continue
			}
			avail = total - used
		}
		pooled += avail
		lines = append(lines, fmt.Sprintf("%s\tnode=%s\tavailable=%s", o.Name(), o.DigString("spec", "node"), HumanBytes(avail)))
	}
	if len(lines) == 0 {
		return nil
	}
	return &stCapacity{
		Bytes: pooled, From: "OpenEBS DiskPool status",
		What:   "kubectl get diskpool -A -o wide",
		Output: strings.Join(lines, "\n"),
	}
}

// stNodeEphemeral is the last resort, and only for a class that carves
// volumes out of the node filesystem. It is reported with the caveat that the
// same filesystem holds the image layers nodes.imagefs sizes: the two
// requirements come out of one disk.
func stNodeEphemeral(ctx context.Context, c *engine.Ctx, sc stClass) *stCapacity {
	if !stIsNodeLocal(sc) {
		return nil
	}
	var total, largest float64
	var lines []string
	nodes := c.Kube.List(ctx, "nodes", "")
	for i, n := range nodes {
		// Bounded: a large fleet would otherwise spend the whole check budget
		// proxying to kubelets one at a time.
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("(%d further nodes not sampled)", len(nodes)-i))
			break
		}
		st := c.Kube.NodeStats(ctx, n.Name())
		if st.Err != "" {
			lines = append(lines, fmt.Sprintf("%s\tstats unavailable: %s", n.Name(), st.Err))
			continue
		}
		total += float64(st.FsAvailableBytes)
		// One claim lives on one node, so the biggest volume this class can
		// ever produce is the free space on the roomiest node — not the sum.
		if a := float64(st.FsAvailableBytes); a > largest {
			largest = a
		}
		lines = append(lines, fmt.Sprintf("%s\tfs.available=%s of %s", n.Name(),
			HumanBytes(float64(st.FsAvailableBytes)), HumanBytes(float64(st.FsCapacityBytes))))
	}
	if total == 0 {
		return nil
	}
	return &stCapacity{
		Bytes: total, MaxVol: largest,
		From:   "node ephemeral filesystem (this class is node-local), shared with the image store",
		What:   "kubelet /stats/summary per node",
		Output: strings.Join(lines, "\n"),
	}
}

func stIsNodeLocal(sc stClass) bool {
	prov := strings.ToLower(sc.Provisioner)
	for _, t := range []string{"hostpath", "local-path", "localpv", "no-provisioner", "rancher.io/local"} {
		if strings.Contains(prov, t) {
			return true
		}
	}
	for k, v := range sc.Params {
		lk, lv := strings.ToLower(k), strings.ToLower(v)
		if lk == "storagetype" && (lv == "hostpath" || lv == "local") {
			return true
		}
		if lk == "basepath" || lk == "hostpath" {
			return true
		}
	}
	return false
}

func stBytes(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case float64:
		return t, true
	case string:
		// Quantities arrive as strings ("100Gi"); a plain number is bytes.
		if q := ParseQuantity(t); q > 0 {
			return q, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Host prerequisites implied by .parameters
// ---------------------------------------------------------------------------

// stHostRequirement translates one StorageClass parameter into the host-level
// fact it asserts. It keys off the parameter NAME, not the provisioner, because
// the parameter is what states the requirement whoever implements it: openebs
// lvm-localpv, TopoLVM and csi-lvm all spell the volume group differently but
// all of them mean "this volume group must exist on every node".
// stHostRequirement renders a StorageClass parameter as the host state it
// implies. The second return says whether published capacity can corroborate
// it: a driver reports a figure for a pool or volume group by reading it from
// the host, so capacity from a node is evidence that the pool is there. It says
// nothing about a filesystem type or a directory, which is why those stay
// unproven even on a cluster that is visibly working.
func stHostRequirement(key, value string) (string, bool) {
	k := strings.ToLower(key)
	switch {
	case strings.Contains(k, "volgroup") || strings.Contains(k, "volumegroup") || strings.Contains(k, "vgpattern") || k == "vg":
		return fmt.Sprintf("%s=%q: LVM volume group %q must exist on every node a workload can land on (`vgs`)", key, value, value), true
	case strings.Contains(k, "fstype"):
		return fmt.Sprintf("%s=%q: every node must support %s — the kernel module loaded and mkfs.%s present, or the volume formats and the mount fails", key, value, value, value), false
	case strings.Contains(k, "poolname") || k == "pool" || strings.Contains(k, "zpool"):
		return fmt.Sprintf("%s=%q: storage pool %q must already exist on the backend (`zpool list`, `ceph osd pool ls`)", key, value, value), true
	case k == "basepath" || k == "hostpath" || strings.HasSuffix(k, "path"):
		return fmt.Sprintf("%s=%q: that directory must exist and be writable on every node, and it shares the disk with the image store", key, value), false
	case strings.Contains(k, "nodeselector") || strings.Contains(k, "nodeaffinity"):
		return fmt.Sprintf("%s=%q: only nodes matching it can host a volume in this class, so the consuming pods must be schedulable there too", key, value), false
	case strings.Contains(k, "device") || strings.Contains(k, "disk"):
		return fmt.Sprintf("%s=%q: that device must be present and unused on every node", key, value), true
	}
	return "", false
}

// stCapacityNodes names the nodes a driver publishes capacity from for one
// class. Topology is matched the way the scheduler matches it — every label in
// the segment against the node's own labels — so it holds for any driver's
// choice of topology key rather than only for the hostname label.
func stCapacityNodes(ctx context.Context, c *engine.Ctx, sc stClass, nodes []nodeFacts) (map[string]bool, bool) {
	if c.Kube == nil || !c.Kube.HasResource(ctx, "csistoragecapacities.storage.k8s.io") {
		return nil, false
	}
	covered, published := map[string]bool{}, false
	for _, o := range c.Kube.List(ctx, "csistoragecapacities.storage.k8s.io", "") {
		if o.DigString("storageClassName") != sc.Name {
			continue
		}
		b, ok := stBytes(o.Dig("capacity"))
		if !ok || b <= 0 {
			continue
		}
		published = true
		match, _ := o.Dig("nodeTopology", "matchLabels").(map[string]any)
		if len(match) == 0 {
			continue
		}
		for _, n := range nodes {
			fits := true
			for k, raw := range match {
				v, _ := raw.(string)
				if n.Labels[k] != v {
					fits = false
					break
				}
			}
			if fits {
				covered[n.Name] = true
			}
		}
	}
	return covered, published
}

// stNodeNames is the set of node names a coverage map holds.

// ── access modes ────────────────────────────────────────────────────────────
//
// Two failures live here that a capacity figure cannot see: a ReadWriteMany
// claim on a driver that serves one node at a time, and a ReadWriteOnce claim
// several workloads mount — legal, but it pins all of them to one node.

type rwxVerdict int

const (
	rwxUnknown rwxVerdict = iota
	rwxYes
	rwxNo
)

// stRWXSupport classifies a provisioner rather than guessing. The API exposes
// no "supports RWX" field, so an unrecognised driver is unknown — never
// approved, and never accused.
func stRWXSupport(provisioner string) rwxVerdict {
	p := strings.ToLower(provisioner)
	for _, shared := range []string{"nfs", "cephfs", "seaweed", "juicefs", "azurefile", "efs", "glusterfs", "smb", "weka", "lustre", "filestore", "quobyte"} {
		if strings.Contains(p, shared) {
			return rwxYes
		}
	}
	for _, block := range []string{"lvm", "zfs", "hostpath", "local", "ebs.csi", "azuredisk", "pd.csi", "disk.csi", "rbd", "openebs.io/local"} {
		if strings.Contains(p, block) {
			return rwxNo
		}
	}
	return rwxUnknown
}

func stHasMode(modes []string, want string) bool {
	for _, m := range modes {
		if m == want {
			return true
		}
	}
	return false
}

// stClaimModes reads the access modes of every claim the chart creates, keyed
// by claim name. A StatefulSet's volumeClaimTemplate is one claim per replica
// and therefore never shared, so it is deliberately absent.
func stClaimModes(objs []adapters.Object) map[string][]string {
	out := map[string][]string{}
	for _, o := range objs {
		if o.Kind() != "PersistentVolumeClaim" {
			continue
		}
		modes := []string{}
		for _, raw := range o.DigSlice("spec", "accessModes") {
			if m, ok := raw.(string); ok {
				modes = append(modes, m)
			}
		}
		out[o.Name()] = modes
	}
	return out
}

func stClaimClass(objs []adapters.Object, claim string) string {
	for _, o := range objs {
		if o.Kind() == "PersistentVolumeClaim" && o.Name() == claim {
			return strings.TrimSpace(o.DigString("spec", "storageClassName"))
		}
	}
	return ""
}

// stClaimMounters maps each claim to the workloads that mount it. Workloads are
// counted, not pods: three replicas of one Deployment share a node constraint
// anyway, while three different Deployments are three independent scheduling
// decisions that a single ReadWriteOnce volume silently couples.
func stClaimMounters(objs []adapters.Object) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, o := range objs {
		switch o.Kind() {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
		case "CronJob":
		default:
			continue
		}
		vols := o.DigSlice("spec", "template", "spec", "volumes")
		if o.Kind() == "CronJob" {
			vols = o.DigSlice("spec", "jobTemplate", "spec", "template", "spec", "volumes")
		}
		for _, raw := range vols {
			v, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			pvc, ok := v["persistentVolumeClaim"].(map[string]any)
			if !ok {
				continue
			}
			name, _ := pvc["claimName"].(string)
			if name == "" {
				continue
			}
			if out[name] == nil {
				out[name] = map[string]bool{}
			}
			out[name][o.Kind()+"/"+o.Name()] = true
		}
	}
	return out
}

func stMountedClaims(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stNodeNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stParamKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stParamTable(sc stClass) string {
	var b strings.Builder
	for _, k := range Sorted(stParamKeys(sc.Params)) {
		fmt.Fprintf(&b, "%s\t%s=%s\n", sc.Name, k, sc.Params[k])
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---------------------------------------------------------------------------
// Probe support
// ---------------------------------------------------------------------------

// stPerClassTimeout divides what is left of the check budget between the
// candidate classes, so three classes do not each wait the full timeout and
// blow past the runner's deadline with nothing to report.
func stPerClassTimeout(ctx context.Context, n int) time.Duration {
	budget := 75 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		budget = time.Until(dl) - 10*time.Second
	}
	if n < 1 {
		n = 1
	}
	per := budget / time.Duration(n)
	if per > 60*time.Second {
		per = 60 * time.Second
	}
	if per < 15*time.Second {
		per = 15 * time.Second
	}
	return per.Round(time.Second)
}

// stSchedulingFailure separates "the consumer pod could not be placed" from
// "the provisioner did not provision". ProvisionPVC drops the consumer's
// outcome, so the pod's own Events are read back here — they outlive the pod.
//
// A FailedScheduling that blames the claim is the provisioning failure seen
// from the pod's side, not a scheduling failure of its own, so those two
// messages are excluded.
func stSchedulingFailure(ctx context.Context, c *engine.Ctx, pod string) bool {
	ns := c.Probes.Namespace()
	c.Kube.Invalidate("events", ns)
	for _, e := range c.Kube.List(ctx, "events", ns) {
		if e.DigString("involvedObject", "name") != pod || e.DigString("reason") != "FailedScheduling" {
			continue
		}
		msg := e.DigString("message")
		if strings.Contains(msg, "unbound immediate PersistentVolumeClaims") ||
			strings.Contains(msg, "waiting for first consumer") ||
			strings.Contains(msg, "had volume node affinity conflict") {
			continue
		}
		return true
	}
	return false
}

func stClassesInLines(groups ...[]string) []string {
	out := []string{}
	for _, g := range groups {
		for _, line := range g {
			name, _, _ := strings.Cut(line, " ")
			out = append(out, strings.TrimSuffix(name, ":"))
		}
	}
	return Sorted(out)
}

func stFirstEvent(events []string) string {
	for _, e := range events {
		if s := strings.TrimSpace(e); s != "" {
			return s
		}
	}
	return "no Event was recorded, which usually means nothing is watching the claim at all"
}

func stQuoteList(in []string) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return strings.Join(out, ", ")
}

func stOrUnset(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unset)"
	}
	return s
}
