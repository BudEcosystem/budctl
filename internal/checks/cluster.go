package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
)

// The cluster group asks whether the API server itself can host the install:
// the version, the built-in API surface the chart renders against, the apply
// semantics both ApplicationSets demand, the operator's own authority to
// bootstrap, and the admission layer that will judge every pod (FRD-020 §5.2).
//
// What it deliberately does NOT ask: whether Dapr, cert-manager or a database
// operator exist. Those are installed by the two ApplicationSets, so requiring
// them is requiring that the installer already ran (FRD-020 §3.1 / D9).

// The groupVersions the chart renders against. All are built-in — a missing one
// means an API server that was trimmed with --runtime-config, or one too old —
// so each carries what breaks rather than just its name.
var clusterRequiredAPIGroups = []struct {
	gv    string
	needs string
}{
	{"apps/v1", "every Deployment, StatefulSet and DaemonSet in the chart"},
	{"batch/v1", "the migration Jobs and the cron-driven CronJobs"},
	{"networking.k8s.io/v1", "the Ingress objects and the NetworkPolicies"},
	{"autoscaling/v2", "every HorizontalPodAutoscaler in the chart"},
	{"storage.k8s.io/v1", "StorageClass and CSI volume provisioning"},
	{"discovery.k8s.io/v1", "EndpointSlices — how ingress controllers and Dapr resolve services"},
	{"rbac.authorization.k8s.io/v1", "the ClusterRoles every bundled operator installs"},
	{"apiextensions.k8s.io/v1", "the CRDs Dapr, cert-manager, CNPG and ArgoCD register"},
}

// What the operator's identity must be able to create to bootstrap ArgoCD and
// let it sync. ArgoCD's OWN ServiceAccount is a different identity and a
// different check (argocd.rbac, §5.3) — it may not exist yet.
var clusterInstallerPermissions = []struct {
	group, resource, why string
	argoOnly             bool
}{
	{"", "namespaces", "every Application syncs with CreateNamespace=true", false},
	{"apiextensions.k8s.io", "customresourcedefinitions", "Dapr, cert-manager, CNPG and ArgoCD each register CRDs", false},
	{"rbac.authorization.k8s.io", "clusterroles", "the bundled operators install cluster-scoped RBAC", false},
	{"rbac.authorization.k8s.io", "clusterrolebindings", "the bundled operators bind that RBAC to their ServiceAccounts", false},
	{"argoproj.io", "applicationsets", "the install is two ApplicationSets applied by hand", true},
}

// Lowercased fragments that mark a policy as one that would reject the stack's
// pods: the OTel collector DaemonSet mounts hostPath, and the CSI node drivers
// run privileged. Matching is on the serialised rule, so a Pod Security profile
// ("restricted") and a hand-written pattern both land.
var clusterDenyKeywords = []string{
	"hostpath", "privileged", "hostnetwork", "hostpid", "hostipc",
	"allowprivilegeescalation", "runasnonroot", "podsecurity", "restricted", "baseline",
}

// Gatekeeper constraint kinds are free-form, so the templates are matched on
// name fragments drawn from the upstream PSP-replacement library.
var clusterGatekeeperKindHints = []string{
	"hostpath", "privileged", "psp", "hostnetwork", "hostnamespace",
	"securitycontext", "podsecurity", "volumetypes", "hostfilesystem", "capabilit",
}

func init() {
	engine.Register(&engine.Check{
		ID: "cluster.version", Group: "cluster", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("cluster.version")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the API server never answered, so its version is unknown")
			}
			// platform.distribution already read /version; reuse it so one run
			// makes one request, but stay standalone for --only cluster.
			got := c.Platform.Version
			if got == "" {
				v, err := c.Kube.ServerVersion()
				if err != nil {
					return ch.Skip("could not read the server version: " + err.Error())
				}
				got = v.GitVersion
			}
			floor := c.Profile.MinKubernetes
			if floor == "" {
				floor = "1.25"
			}
			ev := engine.Evidence{What: "GET /version", Output: got}
			if compareVersions(got, floor) < 0 {
				return ch.Fail(
					fmt.Sprintf("Kubernetes %s is below %s: the chart renders autoscaling/v2 and PodSecurity-era manifests this API server cannot accept, so the sync fails on apply", got, floor),
					fmt.Sprintf("upgrade the control plane to %s or newer before installing (managed clusters: `aws eks update-cluster-version`, `az aks upgrade`, `gcloud container clusters upgrade`)", floor),
				).WithEvidence(ev)
			}
			detail := []string{"api " + c.Kube.Host()}
			if c.Platform.IsOpenShift() && c.Platform.OpenShiftVersion != "" {
				detail = append(detail, "OpenShift "+c.Platform.OpenShiftVersion)
			}
			return ch.Pass(fmt.Sprintf("Kubernetes %s ≥ %s", got, floor), detail...).
				WithEvidence(ev).
				Bounds("a supported API version says nothing about the CNI, the CSI drivers or the container runtime on the nodes")
		},
	})

	engine.Register(&engine.Check{
		ID: "cluster.api-groups", Group: "cluster", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("cluster.api-groups")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: discovery could not be read")
			}
			served, missing := []string{}, []string{}
			for _, req := range clusterRequiredAPIGroups {
				if c.Kube.HasAPIVersion(ctx, req.gv) {
					served = append(served, req.gv)
				} else {
					missing = append(missing, fmt.Sprintf("%s — needed by %s", req.gv, req.needs))
				}
			}
			ev := engine.Evidence{
				What:   "GET /apis (discovery), filtered to the groupVersions the chart renders",
				Output: "served:\n  " + strings.Join(served, "\n  ") + "\nmissing:\n  " + strings.Join(missing, "\n  "),
			}
			if len(missing) > 0 {
				names := []string{}
				for _, req := range clusterRequiredAPIGroups {
					if !c.Kube.HasAPIVersion(ctx, req.gv) {
						names = append(names, req.gv)
					}
				}
				return ch.Fail(
					fmt.Sprintf("%s not served: every object the chart renders against %s is rejected at apply and those workloads never exist",
						strings.Join(names, ", "), Plural(len(names), "it", "them")),
					"these groups are all built-in — check the API server's --runtime-config for a group that was disabled, or upgrade the cluster; there is no chart value that works around a missing API group",
					missing...,
				).WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("all %d required API groups served", len(served)), served...).
				WithEvidence(ev).
				Bounds("discovery lists the groups; it does not prove the backing controllers are running — an HPA needs metrics-server (components.metrics-server), an Ingress needs a controller (components.ingress)")
		},
	})

	engine.Register(&engine.Check{
		ID: "cluster.server-side-apply", Group: "cluster", Severity: engine.Block,
		// Not a probe: dryRun=All runs the object through admission and
		// validation and then discards it. Nothing is persisted, so --no-probe
		// has no reason to skip this (FRD-020 §6).
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("cluster.server-side-apply")
			if c.Kube == nil || c.Kube.Clientset == nil {
				return ch.Skip("cluster unreachable: no API server to send an apply patch to")
			}
			ns := clusterApplyNamespace(ctx, c)
			name := "budctl-server-side-apply-probe"
			body := []byte(fmt.Sprintf(
				`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":%q,"namespace":%q},"data":{"probe":"server-side-apply"}}`,
				name, ns))
			force := true
			_, err := c.Kube.Clientset.CoreV1().ConfigMaps(ns).Patch(ctx, name, types.ApplyPatchType, body,
				metav1.PatchOptions{
					DryRun:       []string{metav1.DryRunAll},
					FieldManager: "budctl-readiness",
					Force:        &force,
				})
			ev := engine.Evidence{
				What: fmt.Sprintf("PATCH /api/v1/namespaces/%s/configmaps/%s?dryRun=All (Content-Type: application/apply-patch+yaml)", ns, name),
			}
			switch {
			case err == nil:
				ev.Output = "accepted; dry run, nothing was persisted"
				return ch.Pass("the API server accepts server-side apply", "both ApplicationSets set syncOptions ServerSideApply=true").
					WithEvidence(ev).
					Bounds("it proves the apply verb and media type for this identity on a ConfigMap; it does not prove ArgoCD's ServiceAccount may apply every kind, nor that admission accepts the real manifests")

			case apierrors.IsUnsupportedMediaType(err), apierrors.IsMethodNotSupported(err), clusterRejectsApplyPatch(err):
				ev.Output = err.Error()
				return ch.Fail(
					"the API server refuses application/apply-patch+yaml: both ApplicationSets sync with ServerSideApply=true, so every Application fails on its first apply and nothing installs",
					"use an API server that serves server-side apply (GA since 1.22, on by default); if the request is being rewritten by an API proxy in front of the cluster, point --kubeconfig at the API server directly",
				).WithEvidence(ev)

			case apierrors.IsForbidden(err):
				ev.Output = err.Error()
				return ch.Skip(fmt.Sprintf(
					"RBAC denied the dry-run apply of a ConfigMap in %s, so server-side apply support was not exercised — grant this identity patch+create on configmaps, or re-run as the identity that will perform the install", ns)).
					WithEvidence(ev)

			case apierrors.IsNotFound(err):
				ev.Output = err.Error()
				return ch.Skip(fmt.Sprintf("namespace %q does not exist, so there was nowhere to send a harmless dry-run apply; re-run with a kubeconfig whose context has a default namespace", ns)).
					WithEvidence(ev)

			default:
				ev.Output = err.Error()
				return ch.Skip("the dry-run apply did not complete, so server-side apply was neither proven nor disproven: " + err.Error()).
					WithEvidence(ev)
			}
		},
	})

	engine.Register(&engine.Check{
		ID: "cluster.installer-rbac", Group: "cluster", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("cluster.installer-rbac")
			if c.Kube == nil || c.Kube.Clientset == nil {
				return ch.Skip("cluster unreachable: SelfSubjectAccessReview could not be posted")
			}
			// ArgoCD is normally installed AFTER this check, so its CRD being
			// absent is expected; SelfSubjectAccessReview evaluates RBAC on the
			// group/resource strings whether or not the resource is served.
			argo := c.Opts.ArgoCDEnabled || c.Answers.UseArgoCD ||
				c.Kube.HasResource(ctx, "applicationsets.argoproj.io")

			allowed, denied, lines := []string{}, []string{}, []string{}
			for _, p := range clusterInstallerPermissions {
				if p.argoOnly && !argo {
					lines = append(lines, fmt.Sprintf("create %s: not checked (ArgoCD disabled for this install)", clusterQualify(p.group, p.resource)))
					continue
				}
				ok := c.Kube.CanI(ctx, "create", p.group, p.resource, "")
				verdict := "denied"
				if ok {
					verdict = "allowed"
					allowed = append(allowed, clusterQualify(p.group, p.resource))
				} else {
					denied = append(denied, fmt.Sprintf("%s — %s", clusterQualify(p.group, p.resource), p.why))
				}
				lines = append(lines, fmt.Sprintf("create %s: %s", clusterQualify(p.group, p.resource), verdict))
			}
			ev := engine.Evidence{
				What:   "SelfSubjectAccessReview for the current kubeconfig identity (the API behind `kubectl auth can-i`)",
				Output: strings.Join(lines, "\n"),
			}
			if len(denied) > 0 {
				short := []string{}
				for _, d := range denied {
					short = append(short, strings.SplitN(d, " — ", 2)[0])
				}
				return ch.Fail(
					fmt.Sprintf("this identity cannot create %s: the bootstrap stops at the first object it applies and nothing installs", strings.Join(short, ", ")),
					"bind the install identity to a role that grants them — for a POC, `kubectl create clusterrolebinding budctl-installer --clusterrole=cluster-admin --user=<identity>`; for a scoped role, grant create on namespaces, customresourcedefinitions, clusterroles, clusterrolebindings and applicationsets.argoproj.io",
					denied...,
				).WithEvidence(ev)
			}
			return ch.Pass("the install identity can create namespaces, CRDs and cluster-scoped RBAC", allowed...).
				WithEvidence(ev).
				Bounds("this is the OPERATOR's identity, the one that applies the two ApplicationSets. Whether ArgoCD's own application-controller ServiceAccount may sync them is argocd.rbac, and it can only be answered once ArgoCD exists")
		},
	})

	engine.Register(&engine.Check{
		ID: "cluster.admission-policy", Group: "cluster", Severity: engine.Risk,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("cluster.admission-policy")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the admission configuration could not be read")
			}
			if c.Platform.IsOpenShift() {
				return clusterAdmissionOpenShift(ctx, c, ch)
			}
			return clusterAdmissionVanilla(ctx, c, ch)
		},
	})
}

// clusterAdmissionOpenShift asks whether the installer MAY grant an SCC, not
// whether a permissive one already exists (FRD-020 §5.0 table). budcluster
// applies `privileged` per worker namespace from
// playbooks/apply_security_context.yaml at deploy time, and that playbook is
// state:present against the built-in `privileged` SCC — so update matters as
// much as create.
func clusterAdmissionOpenShift(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if c.Kube.Clientset == nil {
		return ch.Skip("SelfSubjectAccessReview could not be posted, so SCC authority is unknown")
	}
	const group, resource = "security.openshift.io", "securitycontextconstraints"
	canCreate := c.Kube.CanI(ctx, "create", group, resource, "")
	canUpdate := c.Kube.CanI(ctx, "update", group, resource, "")
	ev := engine.Evidence{
		What: "SelfSubjectAccessReview: create/update securitycontextconstraints.security.openshift.io",
		Output: fmt.Sprintf("create: %s\nupdate: %s",
			clusterAllowedWord(canCreate), clusterAllowedWord(canUpdate)),
	}
	remedy := "grant the install identity SCC authority: `oc create clusterrole budctl-scc --verb=create,get,list,update,patch --resource=securitycontextconstraints.security.openshift.io` then `oc adm policy add-cluster-role-to-user budctl-scc <identity>`"
	notChecked := "PodSecurity labels and Kyverno/Gatekeeper ClusterPolicies were not inspected: on OpenShift the SCC layer is authoritative and PSA runs in warn/audit"

	switch {
	case !canCreate:
		return ch.Fail(
			"the install identity may not create a SecurityContextConstraints: budcluster's apply_security_context step fails at deploy time and the runtime pods stay denied by the default restricted-v2 SCC",
			remedy, notChecked,
		).WithEvidence(ev)
	case !canUpdate:
		return ch.Fail(
			"the install identity may create an SCC but not update one: apply_security_context adds each worker namespace's ServiceAccount to the EXISTING `privileged` SCC, which is an update, so model deployments are denied at admission",
			remedy, notChecked,
		).WithEvidence(ev)
	}
	return ch.Pass("the install identity may create and update SecurityContextConstraints", notChecked).
		WithEvidence(ev).
		Bounds("it proves the authority to grant an SCC, not that any particular pod will be admitted: SCC selection happens per ServiceAccount at admission time, and budcluster grants the constraint per namespace as it deploys")
}

// clusterAdmissionVanilla inspects the two admission layers that actually
// reject this stack: PodSecurity, and Kyverno/Gatekeeper policies in enforce
// mode. Policies are INSPECTED for known conflicts, never simulated (§5.2).
func clusterAdmissionVanilla(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	restricted, baseline, total := clusterPSANamespaces(ctx, c)
	kyverno := clusterKyvernoConflicts(ctx, c)
	gatekeeper := clusterGatekeeperConflicts(ctx, c)

	psaLines := []string{}
	if len(restricted) > 0 {
		psaLines = append(psaLines, "enforce=restricted: "+strings.Join(Sorted(restricted), ", "))
	}
	if len(baseline) > 0 {
		psaLines = append(psaLines, "enforce=baseline: "+strings.Join(Sorted(baseline), ", "))
	}
	if len(psaLines) == 0 {
		psaLines = append(psaLines, "no namespace carries a pod-security.kubernetes.io/enforce label")
	}
	ev := engine.Evidence{
		What: fmt.Sprintf("namespace pod-security.kubernetes.io/enforce labels (%d %s), plus ClusterPolicies and Gatekeeper constraints in enforce mode",
			total, Plural(total, "namespace", "namespaces")),
		Output: strings.Join(append(psaLines, append(kyverno, gatekeeper...)...), "\n"),
	}
	notChecked := "SecurityContextConstraints were not inspected: they do not exist on this distribution"
	consequence := "the OpenTelemetry collector DaemonSet's hostPath mounts and the CSI node drivers' privileged containers are denied at admission, so those pods never start"
	bounds := "budctl reads namespace labels and policy objects; it cannot read the API server's AdmissionConfiguration file, so a cluster-wide PodSecurity default set in the API server flags and not mirrored onto namespaces stays invisible. Individual manifests are not simulated against admission"

	// A cluster-wide default shows up as the label on the namespaces that ship
	// with the cluster — `default` above all. One hardened namespace of many is
	// a local decision and cannot touch namespaces the install has yet to
	// create, so it is reported, not failed.
	clusterWide := clusterPSAIsClusterWide(restricted, total)

	switch {
	case clusterWide:
		return ch.Fail(
			fmt.Sprintf("PodSecurity `restricted` is enforced across the cluster (%d of %d namespaces, including the ones the cluster ships with): %s",
				len(restricted), total, consequence),
			"exempt the namespaces the install creates before syncing — `kubectl label ns <namespace> pod-security.kubernetes.io/enforce=privileged --overwrite` for each — or add them to the `exemptions.namespaces` list in the API server's PodSecurity AdmissionConfiguration",
			append([]string{notChecked}, psaLines...)...,
		).WithEvidence(ev).Bounds(bounds)

	case len(kyverno)+len(gatekeeper) > 0:
		conflicts := append(append([]string{}, kyverno...), gatekeeper...)
		return ch.Fail(
			fmt.Sprintf("%d admission %s in enforce mode would reject the stack's pods: %s",
				len(conflicts), Plural(len(conflicts), "policy", "policies"), consequence),
			"add an exclusion for the namespaces the install creates to each named policy (Kyverno: `spec.rules[].exclude.any[].resources.namespaces`; Gatekeeper: `spec.match.excludedNamespaces`), or move the policy to audit/dryrun until the install has converged",
			append([]string{notChecked}, conflicts...)...,
		).WithEvidence(ev).Bounds(bounds)
	}

	detail := append([]string{notChecked}, psaLines...)
	if len(restricted)+len(baseline) > 0 {
		detail = append(detail, "these are individually labelled namespaces, not a cluster-wide default; the namespaces the install creates are not among them")
	}
	return ch.Pass("no admission policy in enforce mode conflicts with the stack's hostPath and privileged pods", detail...).
		WithEvidence(ev).Bounds(bounds)
}

// clusterPSANamespaces returns the namespaces enforcing restricted and baseline
// Pod Security, and the total namespace count the ratio is taken against.
func clusterPSANamespaces(ctx context.Context, c *engine.Ctx) (restricted, baseline []string, total int) {
	for _, ns := range c.Kube.List(ctx, "namespaces", "") {
		total++
		switch strings.ToLower(ns.Labels()["pod-security.kubernetes.io/enforce"]) {
		case "restricted":
			restricted = append(restricted, ns.Name())
		case "baseline":
			baseline = append(baseline, ns.Name())
		}
	}
	return restricted, baseline, total
}

func clusterPSAIsClusterWide(restricted []string, total int) bool {
	if len(restricted) == 0 || total == 0 {
		return false
	}
	for _, n := range restricted {
		// A namespace the cluster created itself carrying the label means the
		// policy is being applied by default rather than per workload.
		if n == "default" || n == "kube-public" || n == "kube-system" {
			return true
		}
	}
	return len(restricted)*2 >= total
}

// clusterKyvernoConflicts names every ClusterPolicy in enforce mode whose rules
// mention what the stack needs. Kyverno moved the action from
// spec.validationFailureAction to per-rule validate.failureAction in 1.13, and
// clusters in the field run both, so both are read.
func clusterKyvernoConflicts(ctx context.Context, c *engine.Ctx) []string {
	out := []string{}
	for _, p := range c.Kube.List(ctx, "clusterpolicies.kyverno.io", "") {
		policyEnforce := strings.EqualFold(p.DigString("spec", "validationFailureAction"), "Enforce")
		hits := map[string]bool{}
		enforcing := false
		for _, raw := range p.DigSlice("spec", "rules") {
			rule, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			ruleEnforce := policyEnforce
			if v, ok := rule["validate"].(map[string]any); ok {
				if s, ok := v["failureAction"].(string); ok && s != "" {
					ruleEnforce = strings.EqualFold(s, "Enforce")
				}
			}
			if !ruleEnforce {
				continue
			}
			for _, kw := range clusterMatchedKeywords(rule) {
				hits[kw] = true
				enforcing = true
			}
		}
		if enforcing {
			out = append(out, fmt.Sprintf("Kyverno ClusterPolicy/%s (enforce) matches %s",
				p.Name(), strings.Join(Sorted(clusterKeys(hits)), ", ")))
		}
	}
	return Sorted(out)
}

// clusterGatekeeperConflicts walks ConstraintTemplates to learn which constraint
// kinds exist — they are CRDs generated per template, so there is no fixed list
// — then reads the constraints of the kinds that look like PSP replacements.
// Gatekeeper's default enforcementAction is deny, so an EMPTY field enforces.
func clusterGatekeeperConflicts(ctx context.Context, c *engine.Ctx) []string {
	out := []string{}
	for _, tpl := range c.Kube.List(ctx, "constrainttemplates.templates.gatekeeper.sh", "") {
		kind := tpl.DigString("spec", "crd", "spec", "names", "kind")
		if kind == "" || !clusterHintedKind(kind) {
			continue
		}
		fq := strings.ToLower(kind) + "s.constraints.gatekeeper.sh"
		for _, con := range c.Kube.List(ctx, fq, "") {
			action := strings.ToLower(con.DigString("spec", "enforcementAction"))
			if action != "" && action != "deny" {
				continue
			}
			out = append(out, fmt.Sprintf("Gatekeeper %s/%s (enforcementAction=%s) restricts %s",
				kind, con.Name(), clusterOrDefault(action, "deny"), strings.ToLower(kind)))
		}
	}
	return Sorted(out)
}

func clusterHintedKind(kind string) bool {
	lower := strings.ToLower(kind)
	for _, hint := range clusterGatekeeperKindHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// clusterMatchedKeywords serialises a rule and reports which of the stack's
// requirements it names. Serialising is the only honest way to cover both a
// Pod Security subrule and a hand-written pattern or CEL expression.
func clusterMatchedKeywords(rule map[string]any) []string {
	b, err := json.Marshal(rule)
	if err != nil {
		return nil
	}
	body := strings.ToLower(string(b))
	hits := []string{}
	for _, kw := range clusterDenyKeywords {
		if strings.Contains(body, kw) {
			hits = append(hits, kw)
		}
	}
	return hits
}

// clusterApplyNamespace picks somewhere harmless to send the dry-run apply.
// `default` is chosen first and unconditionally so the request is identical on
// every run: the probe namespace is created lazily and may not exist, and a
// varying target would make a recorded transcript non-deterministic.
func clusterApplyNamespace(ctx context.Context, c *engine.Ctx) string {
	for _, name := range []string{"default", "kube-public", "kube-system"} {
		if c.Kube.Get(ctx, "namespaces", "", name) != nil {
			return name
		}
	}
	return "default"
}

// clusterRejectsApplyPatch catches API proxies that answer with a 400 rather
// than the 415 an API server returns for an unknown patch media type.
func clusterRejectsApplyPatch(err error) bool {
	if err == nil || !apierrors.IsBadRequest(err) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "patch") &&
		(strings.Contains(msg, "unsupported") || strings.Contains(msg, "not supported") ||
			strings.Contains(msg, "content type") || strings.Contains(msg, "unknown"))
}

func clusterQualify(group, resource string) string {
	if group == "" {
		return resource
	}
	return resource + "." + group
}

func clusterAllowedWord(ok bool) string {
	if ok {
		return "allowed"
	}
	return "denied"
}

func clusterOrDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func clusterKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = adapters.Object{}
