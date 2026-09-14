package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The cluster group is the one group whose answers come from the API server's
// own authorization and admission machinery rather than from objects. The
// harness seeds objects; it does not seed an answer to
// SelfSubjectAccessReview, and the fake clientset denies everything by
// default. A suite built only on the harness would therefore be unable to
// distinguish "this identity may create CRDs" from "the fake said no", which
// is exactly the false assurance these checks exist to prevent. So the helpers
// below program the fake API server's authorization and apply behaviour, and
// every check in the group is driven to BOTH verdicts.

// ---------------------------------------------------------------------------
// Helpers. All prefixed `cluster` so they cannot collide with a sibling file.
// ---------------------------------------------------------------------------

// clusterAccess is the RBAC an identity has, as the API server would answer it.
type clusterAccess func(verb, group, resource, namespace string) bool

// clusterRun is run() plus a hook into the engine.Ctx, so a test can say what
// the API server answers before the check asks.
func clusterRun(t *testing.T, f *fakeCluster, id string, mutate ...func(*engine.Ctx)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	for _, m := range mutate {
		m(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

func clusterFakeClientset(t *testing.T, c *engine.Ctx) *k8sfake.Clientset {
	t.Helper()
	cs, ok := c.Kube.Clientset.(*k8sfake.Clientset)
	if !ok {
		t.Fatalf("harness clientset is not a *fake.Clientset (%T); the RBAC helpers cannot program it", c.Kube.Clientset)
	}
	return cs
}

// clusterWithRBAC answers SelfSubjectAccessReview the way a real API server
// would for the given grants. Without it the fake denies every verb, so a
// BLOCK would prove nothing about the check and a PASS would be unreachable.
func clusterWithRBAC(t *testing.T, allow clusterAccess) func(*engine.Ctx) {
	t.Helper()
	return func(c *engine.Ctx) {
		clusterFakeClientset(t, c).PrependReactor("create", "selfsubjectaccessreviews",
			func(a k8stesting.Action) (bool, runtime.Object, error) {
				create, ok := a.(k8stesting.CreateAction)
				if !ok {
					return false, nil, nil
				}
				rev, ok := create.GetObject().(*authzv1.SelfSubjectAccessReview)
				if !ok {
					return false, nil, nil
				}
				out := rev.DeepCopy()
				if ra := out.Spec.ResourceAttributes; ra != nil {
					out.Status.Allowed = allow(ra.Verb, ra.Group, ra.Resource, ra.Namespace)
				}
				return true, out, nil
			})
	}
}

func clusterAllowAll(verb, group, resource, namespace string) bool { return true }

// clusterDeny builds an allow-everything-except grant, so a test names only the
// permission it is taking away.
func clusterDeny(resources ...string) clusterAccess {
	return func(_, _, resource, _ string) bool {
		for _, r := range resources {
			if r == resource {
				return false
			}
		}
		return true
	}
}

// clusterWithApply decides what the dry-run server-side apply returns. err ==
// nil means the API server accepted it.
func clusterWithApply(t *testing.T, err error) func(*engine.Ctx) {
	t.Helper()
	return func(c *engine.Ctx) {
		clusterFakeClientset(t, c).PrependReactor("patch", "configmaps",
			func(a k8stesting.Action) (bool, runtime.Object, error) {
				if err != nil {
					return true, nil, err
				}
				patch, _ := a.(k8stesting.PatchAction)
				return true, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: patch.GetName(), Namespace: a.GetNamespace()},
				}, nil
			})
	}
}

// clusterUnreachable is the state every cluster check must degrade to when
// toolchain.kubeconfig blocked: a stated SKIP, never a pass.
func clusterUnreachable(c *engine.Ctx) { c.Kube = nil }

// clusterNoClientset models discovery answering while the typed client does
// not — the SelfSubjectAccessReview paths must skip, not assume.
func clusterNoClientset(c *engine.Ctx) { c.Kube.Clientset = nil }

// --- object builders -------------------------------------------------------

func clusterNamespace(name, enforce string) adapters.Object {
	labels := map[string]any{"kubernetes.io/metadata.name": name}
	if enforce != "" {
		labels["pod-security.kubernetes.io/enforce"] = enforce
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": name, "labels": labels},
	}
}

// clusterHostPathRule is a rule that denies what the OTel collector DaemonSet
// actually does, written the way Kyverno's own sample library writes it.
func clusterHostPathRule(name, failureAction string) map[string]any {
	rule := map[string]any{
		"name": name,
		"match": map[string]any{"any": []any{
			map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}}},
		}},
		"validate": map[string]any{
			"message": "hostPath volumes are forbidden",
			"pattern": map[string]any{"spec": map[string]any{
				"=(volumes)": []any{map[string]any{"X(hostPath)": "null"}},
			}},
		},
	}
	if failureAction != "" {
		rule["validate"].(map[string]any)["failureAction"] = failureAction
	}
	return rule
}

// clusterLabelRule enforces something the stack does not care about, so an
// enforcing policy that is irrelevant does not read as a conflict.
func clusterLabelRule(name string) map[string]any {
	return map[string]any{
		"name": name,
		"match": map[string]any{"any": []any{
			map[string]any{"resources": map[string]any{"kinds": []any{"Deployment"}}},
		}},
		"validate": map[string]any{
			"message": "every Deployment must carry a team label",
			"pattern": map[string]any{"metadata": map[string]any{
				"labels": map[string]any{"team": "?*"},
			}},
		},
	}
}

func clusterKyvernoPolicy(name, validationFailureAction string, rules ...map[string]any) adapters.Object {
	spec := map[string]any{}
	if validationFailureAction != "" {
		spec["validationFailureAction"] = validationFailureAction
	}
	raw := make([]any, 0, len(rules))
	for _, r := range rules {
		raw = append(raw, r)
	}
	spec["rules"] = raw
	return adapters.Object{
		"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
		"metadata": map[string]any{"name": name},
		"spec":     spec,
	}
}

func clusterConstraintTemplate(kind string) adapters.Object {
	return adapters.Object{
		"apiVersion": "templates.gatekeeper.sh/v1", "kind": "ConstraintTemplate",
		"metadata": map[string]any{"name": strings.ToLower(kind)},
		"spec": map[string]any{"crd": map[string]any{"spec": map[string]any{
			"names": map[string]any{"kind": kind},
		}}},
	}
}

func clusterGatekeeperConstraint(kind, name, enforcementAction string) adapters.Object {
	spec := map[string]any{"match": map[string]any{"kinds": []any{
		map[string]any{"apiGroups": []any{""}, "kinds": []any{"Pod"}},
	}}}
	if enforcementAction != "" {
		spec["enforcementAction"] = enforcementAction
	}
	return adapters.Object{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1", "kind": kind,
		"metadata": map[string]any{"name": name},
		"spec":     spec,
	}
}

// --- assertions ------------------------------------------------------------

func clusterAssertMentions(t *testing.T, r engine.Result, needles ...string) {
	t.Helper()
	body := strings.ToLower(strings.Join(append([]string{r.Summary, r.Remedy}, r.Detail...), "\n"))
	for _, n := range needles {
		if !strings.Contains(body, strings.ToLower(n)) {
			t.Fatalf("%s: result never mentions %q — an operator cannot act on it\n  summary: %s\n  remedy: %s\n  detail: %v",
				r.ID, n, r.Summary, r.Remedy, r.Detail)
		}
	}
}

func clusterAssertSummaryOmits(t *testing.T, r engine.Result, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(strings.ToLower(r.Summary), strings.ToLower(n)) {
			t.Fatalf("%s: summary mentions %q, which belongs to the other distribution's branch: %s",
				r.ID, n, r.Summary)
		}
	}
}

func clusterEvidence(r engine.Result) string {
	parts := []string{}
	for _, ev := range r.Evidence {
		parts = append(parts, ev.What, ev.Output)
	}
	return strings.Join(parts, "\n")
}

// ---------------------------------------------------------------------------
// cluster.version
// ---------------------------------------------------------------------------

// The floor exists because the chart renders autoscaling/v2 and PodSecurity-era
// manifests. A 1.24 control plane must be refused before anything is applied.
func TestClusterVersionBlocksBelowFloor(t *testing.T) {
	f := vanilla()
	f.platform.Version = "v1.24.17"
	r := clusterRun(t, f, "cluster.version")
	assertStatus(t, r, "BLOCK")
	clusterAssertMentions(t, r, "1.24.17", "1.25", "upgrade")
}

// Distribution suffixes are not part of the version. Treating "v1.30.8-eks-2d5f260"
// as unparseable would block every managed cluster in the field.
func TestClusterVersionToleratesDistributionSuffixes(t *testing.T) {
	cases := []struct {
		name, version, want string
	}{
		{"exactly at the floor is supported", "v1.25.0", "PASS"},
		{"a current release passes", "v1.30.0", "PASS"},
		{"an EKS build string still parses", "v1.30.8-eks-2d5f260", "PASS"},
		{"a k3s build string still parses", "v1.35.7+k3s1", "PASS"},
		{"the last patch below the floor is still below it", "v1.24.99+k3s1", "BLOCK"},
		{"a long-unsupported server blocks", "v1.21.14", "BLOCK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla()
			f.platform.Version = tc.version
			assertStatus(t, clusterRun(t, f, "cluster.version"), tc.want)
		})
	}
}

// On OpenShift the Kubernetes version alone does not identify the cluster an
// operator is looking at, so the pass has to name the OpenShift release too.
func TestClusterVersionPassNamesTheOpenShiftRelease(t *testing.T) {
	r := clusterRun(t, openShift(), "cluster.version")
	assertStatus(t, r, "PASS")
	clusterAssertMentions(t, r, "OpenShift 4.16.7")
	if r.DoesNotProve == "" {
		t.Fatalf("cluster.version passed without bounding the claim; a supported API version says nothing about the nodes")
	}
}

// An unreachable API server must never leave the impression the version was
// checked and found acceptable.
func TestClusterVersionSkipsWhenClusterUnreachable(t *testing.T) {
	assertSkipHasReason(t, clusterRun(t, vanilla(), "cluster.version", clusterUnreachable))
}

// ---------------------------------------------------------------------------
// cluster.api-groups
// ---------------------------------------------------------------------------

// A trimmed --runtime-config is invisible until apply time, when every HPA in
// the chart is rejected. The failure must name the group AND what breaks.
func TestClusterAPIGroupsBlocksWhenAutoscalingV2Absent(t *testing.T) {
	f := vanilla()
	delete(f.apiGroups, "autoscaling/v2")
	r := clusterRun(t, f, "cluster.api-groups")
	assertStatus(t, r, "BLOCK")
	clusterAssertMentions(t, r, "autoscaling/v2", "HorizontalPodAutoscaler")
	// The other seven must not be dragged into the message: an operator chasing
	// a phantom missing group loses the real one.
	clusterAssertSummaryOmits(t, r, "apps/v1", "batch/v1", "storage.k8s.io/v1")
}

// Every required group is required for a different reason; each must be
// individually detectable or the check only covers whichever one is listed first.
func TestClusterAPIGroupsNamesWhicheverGroupIsMissing(t *testing.T) {
	for _, req := range clusterRequiredAPIGroups {
		t.Run(req.gv, func(t *testing.T) {
			f := vanilla()
			delete(f.apiGroups, req.gv)
			r := clusterRun(t, f, "cluster.api-groups")
			assertStatus(t, r, "BLOCK")
			clusterAssertMentions(t, r, req.gv, req.needs)
		})
	}
}

func TestClusterAPIGroupsPassesWhenEveryGroupIsServed(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.api-groups")
	assertStatus(t, r, "PASS")
	// Discovery lists groups, not controllers. A pass that did not say so would
	// be read as "HPAs will work", which it does not prove.
	if !strings.Contains(r.DoesNotProve, "metrics-server") {
		t.Fatalf("cluster.api-groups passed without bounding the claim to discovery: %q", r.DoesNotProve)
	}
}

func TestClusterAPIGroupsSkipsWhenClusterUnreachable(t *testing.T) {
	assertSkipHasReason(t, clusterRun(t, vanilla(), "cluster.api-groups", clusterUnreachable))
}

// ---------------------------------------------------------------------------
// cluster.server-side-apply
// ---------------------------------------------------------------------------

func TestClusterServerSideApplyPassesWhenAccepted(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.server-side-apply", clusterWithApply(t, nil))
	assertStatus(t, r, "PASS")
	if !strings.Contains(clusterEvidence(r), "dryRun=All") {
		t.Fatalf("cluster.server-side-apply passed without recording that nothing was persisted: %q", clusterEvidence(r))
	}
}

// 415 (and 405) are what an API server that does not serve apply patches
// answers. Both ApplicationSets sync with ServerSideApply=true, so this is
// fatal, not a risk: every Application fails on its first apply.
func TestClusterServerSideApplyBlocksWhenApplyPatchIsRefused(t *testing.T) {
	gr := schema.GroupResource{Resource: "configmaps"}
	cases := []struct {
		name string
		err  error
	}{
		{"415 unsupported media type", apierrors.NewGenericServerResponse(
			415, "patch", gr, "budctl-server-side-apply-probe",
			"the body of the request was in an unknown format", 0, false)},
		{"405 method not supported", apierrors.NewMethodNotSupported(gr, "patch")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := clusterRun(t, vanilla(), "cluster.server-side-apply", clusterWithApply(t, tc.err))
			assertStatus(t, r, "BLOCK")
			clusterAssertMentions(t, r, "ServerSideApply", "apply-patch")
		})
	}
}

// An API proxy in front of the cluster rewrites the request and answers 400
// rather than 415. Reading that as "inconclusive" would let an install start
// that cannot apply a single object.
func TestClusterServerSideApplyBlocksWhenAProxyRejectsWithBadRequest(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.server-side-apply",
		clusterWithApply(t, apierrors.NewBadRequest("the patch content type is unsupported by this endpoint")))
	assertStatus(t, r, "BLOCK")
}

// ...but an unrelated 400 is not evidence of anything, and must not be dressed
// up as one. This is the discrimination clusterRejectsApplyPatch exists for.
func TestClusterServerSideApplySkipsOnAnUnrelatedBadRequest(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.server-side-apply",
		clusterWithApply(t, apierrors.NewBadRequest("metadata.name: Invalid value")))
	assertSkipHasReason(t, r)
}

// RBAC denying the dry run says nothing about whether apply is served, so it
// must read as "not exercised" rather than as a pass.
func TestClusterServerSideApplySkipsWhenRBACDeniesTheDryRun(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.server-side-apply",
		clusterWithApply(t, apierrors.NewForbidden(
			schema.GroupResource{Resource: "configmaps"}, "budctl-server-side-apply-probe",
			fmt.Errorf("configmaps is forbidden for user budctl"))))
	assertSkipHasReason(t, r)
	clusterAssertMentions(t, r, "RBAC")
}

func TestClusterServerSideApplySkipsWhenTheTargetNamespaceIsAbsent(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.server-side-apply",
		clusterWithApply(t, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "default")))
	assertSkipHasReason(t, r)
}

func TestClusterServerSideApplySkipsWhenClusterUnreachable(t *testing.T) {
	assertSkipHasReason(t, clusterRun(t, vanilla(), "cluster.server-side-apply", clusterNoClientset))
}

// ---------------------------------------------------------------------------
// cluster.installer-rbac
// ---------------------------------------------------------------------------

func TestClusterInstallerRBACPassesWhenTheIdentityMayBootstrap(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.installer-rbac", clusterWithRBAC(t, clusterAllowAll))
	assertStatus(t, r, "PASS")
	clusterAssertMentions(t, r, "namespaces", "customresourcedefinitions", "clusterroles",
		"clusterrolebindings", "applicationsets.argoproj.io")
	// The pass must not be read as "ArgoCD's own ServiceAccount can sync" —
	// that identity does not exist yet and is argocd.rbac's question.
	if !strings.Contains(r.DoesNotProve, "argocd.rbac") {
		t.Fatalf("cluster.installer-rbac passed without separating the operator identity from ArgoCD's: %q", r.DoesNotProve)
	}
}

// Each permission is a different first object the bootstrap applies; whichever
// one is missing has to be the one named, or the remedy points at the wrong role.
func TestClusterInstallerRBACBlocksOnEachMissingPermission(t *testing.T) {
	for _, p := range clusterInstallerPermissions {
		t.Run(clusterQualify(p.group, p.resource), func(t *testing.T) {
			r := clusterRun(t, vanilla(), "cluster.installer-rbac",
				clusterWithRBAC(t, clusterDeny(p.resource)))
			assertStatus(t, r, "BLOCK")
			clusterAssertMentions(t, r, clusterQualify(p.group, p.resource), p.why)
		})
	}
}

// The default answer of an unprogrammed API server is "denied". If the check
// could not fail here it would be reporting the fake, not the cluster.
func TestClusterInstallerRBACBlocksWhenEverythingIsDenied(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.installer-rbac")
	assertStatus(t, r, "BLOCK")
	clusterAssertMentions(t, r, "namespaces", "customresourcedefinitions")
}

// ArgoCD is optional. Demanding applicationsets rights from an install that
// will never create an ApplicationSet would block a supported configuration.
func TestClusterInstallerRBACDoesNotDemandApplicationSetsWhenArgoCDIsOff(t *testing.T) {
	f := vanilla().
		withAnswers(func(a *intake.Answers) { a.UseArgoCD = false }).
		withOpts(func(o *engine.Options) { o.ArgoCDEnabled = false })
	r := clusterRun(t, f, "cluster.installer-rbac",
		clusterWithRBAC(t, clusterDeny("applicationsets")))
	assertStatus(t, r, "PASS")
	// The skipped permission is recorded in the evidence rather than dropped:
	// a reader must be able to tell "allowed" from "never asked".
	if !strings.Contains(clusterEvidence(r), "not checked (ArgoCD disabled") {
		t.Fatalf("cluster.installer-rbac passed without recording that applicationsets was never asked about: %q",
			clusterEvidence(r))
	}
}

// ...unless the CRD is already served, in which case this install is going to
// use it whatever the answers file says.
func TestClusterInstallerRBACStillDemandsApplicationSetsWhenTheCRDIsServed(t *testing.T) {
	f := vanilla().
		withAnswers(func(a *intake.Answers) { a.UseArgoCD = false }).
		withOpts(func(o *engine.Options) { o.ArgoCDEnabled = false })
	f.apiGroups["applicationsets.argoproj.io"] = true
	r := clusterRun(t, f, "cluster.installer-rbac", clusterWithRBAC(t, clusterDeny("applicationsets")))
	assertStatus(t, r, "BLOCK")
	clusterAssertMentions(t, r, "applicationsets.argoproj.io")
}

// ApplicationSets are namespaced, but the review is posted with an empty
// namespace, which asks "in EVERY namespace". An operator granted the right in
// the argocd namespace alone is therefore reported as unable to install.
// Recorded as today's behaviour: it errs towards blocking, but it blocks a
// configuration that would in fact work.
func TestClusterInstallerRBACIgnoresANamespaceScopedApplicationSetGrant(t *testing.T) {
	namespacedOnly := func(_, _, resource, namespace string) bool {
		if resource == "applicationsets" {
			return namespace == "argocd"
		}
		return true
	}
	r := clusterRun(t, vanilla(), "cluster.installer-rbac", clusterWithRBAC(t, namespacedOnly))
	assertStatus(t, r, "BLOCK")
	clusterAssertMentions(t, r, "applicationsets.argoproj.io")
}

func TestClusterInstallerRBACSkipsWhenClusterUnreachable(t *testing.T) {
	assertSkipHasReason(t, clusterRun(t, vanilla(), "cluster.installer-rbac", clusterNoClientset))
}

// ---------------------------------------------------------------------------
// cluster.admission-policy — vanilla branch
// ---------------------------------------------------------------------------

// The label on the namespaces the cluster ships with is how a cluster-wide
// PodSecurity default becomes visible from outside the API server's config file.
func TestClusterAdmissionVanillaRisksOnClusterWideRestrictedPSA(t *testing.T) {
	f := vanilla().with("namespaces", "",
		clusterNamespace("default", "restricted"),
		clusterNamespace("kube-system", "restricted"),
		clusterNamespace("kube-public", "restricted"),
		clusterNamespace("team-a", ""))
	r := clusterRun(t, f, "cluster.admission-policy")
	assertStatus(t, r, "RISK")
	// The consequence, not just the label: which pods stop existing.
	clusterAssertMentions(t, r, "PodSecurity", "restricted", "hostPath", "OpenTelemetry", "privileged")
	clusterAssertMentions(t, r, "kubectl label ns")
	// SCCs do not exist here; claiming anything about them would be invented.
	clusterAssertSummaryOmits(t, r, "SecurityContextConstraints", "SCC")
}

// One hardened namespace is a local decision that cannot reach namespaces the
// install has yet to create. Failing on it would make budctl cry wolf on every
// cluster with a single locked-down tenant.
func TestClusterAdmissionVanillaPassesOnOneHardenedNamespace(t *testing.T) {
	f := vanilla().with("namespaces", "",
		clusterNamespace("default", ""),
		clusterNamespace("kube-system", ""),
		clusterNamespace("kube-public", ""),
		clusterNamespace("team-a", "restricted"),
		clusterNamespace("team-b", ""),
		clusterNamespace("team-c", ""))
	r := clusterRun(t, f, "cluster.admission-policy")
	assertStatus(t, r, "PASS")
	clusterAssertMentions(t, r, "individually labelled namespaces")
}

// The ratio rule: half the namespaces carrying `restricted`, even with none of
// the cluster's own among them, is read as a default rather than a decision.
func TestClusterAdmissionVanillaTreatsHalfTheClusterAsADefault(t *testing.T) {
	f := vanilla().with("namespaces", "",
		clusterNamespace("team-a", "restricted"),
		clusterNamespace("team-b", "restricted"),
		clusterNamespace("team-c", ""),
		clusterNamespace("team-d", ""))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "RISK")
}

// PodSecurity `baseline` forbids hostPath volumes and privileged containers
// just as `restricted` does, so a cluster-wide baseline default denies the OTel
// collector DaemonSet and the CSI node drivers exactly the same way.
// clusterPSAIsClusterWide only looks at `restricted`, so this cluster is
// reported as having no conflicting admission policy at all.
//
// This test asserts TODAY'S behaviour, not the desired one: it exists so the
// gap is visible rather than silent. When the check learns about baseline,
// flip the expectation to RISK.
func TestClusterAdmissionVanillaMissesAClusterWideBaselineDefault(t *testing.T) {
	f := vanilla().with("namespaces", "",
		clusterNamespace("default", "baseline"),
		clusterNamespace("kube-system", "baseline"),
		clusterNamespace("kube-public", "baseline"))
	r := clusterRun(t, f, "cluster.admission-policy")
	assertStatus(t, r, "PASS")
	if !strings.Contains(clusterEvidence(r), "enforce=baseline") {
		t.Fatalf("the baseline labels were not even recorded as evidence: %q", clusterEvidence(r))
	}
	if !strings.Contains(r.Summary, "no admission policy in enforce mode conflicts") {
		t.Fatalf("summary changed; re-examine whether baseline is now handled: %q", r.Summary)
	}
}

// Kyverno in enforce mode is the other layer that silently deletes the stack's
// pods at admission. The policy must be named, or the operator cannot find it.
func TestClusterAdmissionVanillaRisksOnKyvernoEnforcePolicy(t *testing.T) {
	f := vanilla().with("clusterpolicies.kyverno.io", "",
		clusterKyvernoPolicy("disallow-host-path", "Enforce", clusterHostPathRule("host-path", "")))
	r := clusterRun(t, f, "cluster.admission-policy")
	assertStatus(t, r, "RISK")
	clusterAssertMentions(t, r, "ClusterPolicy/disallow-host-path", "hostpath", "exclude")
	clusterAssertSummaryOmits(t, r, "SecurityContextConstraints")
}

// Audit mode reports, it does not reject. Treating it as a conflict would make
// the common "policies in audit while we roll out" posture unreadable.
func TestClusterAdmissionVanillaIgnoresKyvernoAuditPolicy(t *testing.T) {
	f := vanilla().with("clusterpolicies.kyverno.io", "",
		clusterKyvernoPolicy("disallow-host-path", "Audit", clusterHostPathRule("host-path", "")))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "PASS")
}

// Kyverno 1.13 moved the action onto the rule. A cluster running the new schema
// with no policy-level field would otherwise read as audit — a silent miss.
func TestClusterAdmissionVanillaReadsPerRuleFailureAction(t *testing.T) {
	f := vanilla().with("clusterpolicies.kyverno.io", "",
		clusterKyvernoPolicy("disallow-host-path", "", clusterHostPathRule("host-path", "Enforce")))
	r := clusterRun(t, f, "cluster.admission-policy")
	assertStatus(t, r, "RISK")
	clusterAssertMentions(t, r, "disallow-host-path")
}

// ...and the rule-level field wins in the other direction too, so a policy-wide
// Enforce with one audited rule is not reported as a conflict.
func TestClusterAdmissionVanillaPerRuleAuditOverridesPolicyEnforce(t *testing.T) {
	f := vanilla().with("clusterpolicies.kyverno.io", "",
		clusterKyvernoPolicy("disallow-host-path", "Enforce", clusterHostPathRule("host-path", "Audit")))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "PASS")
}

// An enforcing policy about something the stack does not do is not a conflict.
// Flagging every Kyverno policy would train operators to ignore this check.
func TestClusterAdmissionVanillaIgnoresEnforcePolicyThatDoesNotTouchTheStack(t *testing.T) {
	f := vanilla().with("clusterpolicies.kyverno.io", "",
		clusterKyvernoPolicy("require-team-label", "Enforce", clusterLabelRule("team-label")))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "PASS")
}

// Gatekeeper's default enforcementAction is deny, so an EMPTY field is the
// dangerous case. Reading "unset" as "not enforcing" would miss most installs.
func TestClusterAdmissionVanillaRisksOnGatekeeperConstraintWithNoExplicitAction(t *testing.T) {
	f := vanilla().
		with("constrainttemplates.templates.gatekeeper.sh", "", clusterConstraintTemplate("K8sPSPHostFilesystem")).
		with("k8spsphostfilesystems.constraints.gatekeeper.sh", "",
			clusterGatekeeperConstraint("K8sPSPHostFilesystem", "psp-host-filesystem", ""))
	r := clusterRun(t, f, "cluster.admission-policy")
	assertStatus(t, r, "RISK")
	clusterAssertMentions(t, r, "psp-host-filesystem", "enforcementAction=deny", "excludedNamespaces")
}

func TestClusterAdmissionVanillaIgnoresGatekeeperDryrunConstraint(t *testing.T) {
	f := vanilla().
		with("constrainttemplates.templates.gatekeeper.sh", "", clusterConstraintTemplate("K8sPSPHostFilesystem")).
		with("k8spsphostfilesystems.constraints.gatekeeper.sh", "",
			clusterGatekeeperConstraint("K8sPSPHostFilesystem", "psp-host-filesystem", "dryrun"))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "PASS")
}

// Gatekeeper generates one CRD per ConstraintTemplate and takes the resource
// name from the lowercased KIND — `K8sPSPHostFilesystem` is served at
// `k8spsphostfilesystem.constraints.gatekeeper.sh`. clusterGatekeeperConflicts
// appends an "s" to that, so on a real cluster it lists the wrong resource,
// finds nothing, and reports a cluster with enforcing PSP-replacement
// constraints as having none.
//
// Asserted as today's behaviour so the coupling is visible: the constraint
// below is seeded under the name Gatekeeper actually serves, and the check
// still passes.
func TestClusterAdmissionVanillaMissesGatekeeperConstraintsUnderTheServedName(t *testing.T) {
	f := vanilla().
		with("constrainttemplates.templates.gatekeeper.sh", "", clusterConstraintTemplate("K8sPSPHostFilesystem")).
		with("k8spsphostfilesystem.constraints.gatekeeper.sh", "",
			clusterGatekeeperConstraint("K8sPSPHostFilesystem", "psp-host-filesystem", ""))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "PASS")
}

// A ConstraintTemplate whose kind has nothing to do with pod security is not
// worth walking; the hint list is what keeps the check cheap and quiet.
func TestClusterAdmissionVanillaIgnoresUnrelatedConstraintTemplates(t *testing.T) {
	f := vanilla().
		with("constrainttemplates.templates.gatekeeper.sh", "", clusterConstraintTemplate("K8sRequiredLabels")).
		with("k8srequiredlabelss.constraints.gatekeeper.sh", "",
			clusterGatekeeperConstraint("K8sRequiredLabels", "ns-must-have-team", ""))
	assertStatus(t, clusterRun(t, f, "cluster.admission-policy"), "PASS")
}

// On vanilla there are no SCCs, and the pass has to say that rather than let a
// reader assume the SCC layer was found acceptable.
func TestClusterAdmissionVanillaSaysSCCsWereNotInspected(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.admission-policy")
	assertStatus(t, r, "PASS")
	clusterAssertMentions(t, r, "SecurityContextConstraints were not inspected")
	clusterAssertSummaryOmits(t, r, "SecurityContextConstraints")
}

func TestClusterAdmissionSkipsWhenClusterUnreachable(t *testing.T) {
	assertSkipHasReason(t, clusterRun(t, vanilla(), "cluster.admission-policy", clusterUnreachable))
}

// ---------------------------------------------------------------------------
// cluster.admission-policy — OpenShift branch
// ---------------------------------------------------------------------------

// On OpenShift the question is authority, not inventory: budcluster grants an
// SCC per worker namespace at deploy time, so an identity that cannot create
// one fails later, in the middle of a deployment.
func TestClusterAdmissionOpenShiftRisksWhenSCCCreateIsDenied(t *testing.T) {
	r := clusterRun(t, openShift(), "cluster.admission-policy",
		clusterWithRBAC(t, clusterDeny("securitycontextconstraints")))
	assertStatus(t, r, "RISK")
	clusterAssertMentions(t, r, "SecurityContextConstraints", "apply_security_context", "restricted-v2", "oc adm policy")
	// The vanilla branch must not be reported from here: no namespace in this
	// fixture was read for a PodSecurity label.
	clusterAssertSummaryOmits(t, r, "PodSecurity", "Kyverno", "Gatekeeper")
}

// create without update is the trap: the playbook adds each namespace's
// ServiceAccount to the EXISTING `privileged` SCC, which is an update.
func TestClusterAdmissionOpenShiftRisksWhenOnlyUpdateIsDenied(t *testing.T) {
	createOnly := func(verb, _, resource, _ string) bool {
		if resource == "securitycontextconstraints" {
			return verb == "create"
		}
		return true
	}
	r := clusterRun(t, openShift(), "cluster.admission-policy", clusterWithRBAC(t, createOnly))
	assertStatus(t, r, "RISK")
	clusterAssertMentions(t, r, "update", "apply_security_context", "privileged")
}

func TestClusterAdmissionOpenShiftPassesWithSCCAuthority(t *testing.T) {
	r := clusterRun(t, openShift(), "cluster.admission-policy", clusterWithRBAC(t, clusterAllowAll))
	assertStatus(t, r, "PASS")
	// A pass here must not be read as "the pods will be admitted": SCC
	// selection happens per ServiceAccount at admission time.
	if !strings.Contains(r.DoesNotProve, "admission") {
		t.Fatalf("cluster.admission-policy passed on OpenShift without bounding the claim: %q", r.DoesNotProve)
	}
	clusterAssertMentions(t, r, "PodSecurity labels and Kyverno/Gatekeeper ClusterPolicies were not inspected")
}

// The two branches must be mutually exclusive. An OpenShift cluster that also
// runs Kyverno and labels its namespaces `restricted` is still judged on SCC
// authority alone, because on OpenShift the SCC layer is the authoritative one
// and PSA runs in warn/audit.
func TestClusterAdmissionOpenShiftDoesNotEvaluateTheVanillaBranch(t *testing.T) {
	f := openShift().
		with("namespaces", "",
			clusterNamespace("default", "restricted"),
			clusterNamespace("kube-system", "restricted")).
		with("clusterpolicies.kyverno.io", "",
			clusterKyvernoPolicy("disallow-host-path", "Enforce", clusterHostPathRule("host-path", ""))).
		with("constrainttemplates.templates.gatekeeper.sh", "", clusterConstraintTemplate("K8sPSPPrivilegedContainer")).
		with("k8spspprivilegedcontainers.constraints.gatekeeper.sh", "",
			clusterGatekeeperConstraint("K8sPSPPrivilegedContainer", "no-privileged", ""))
	r := clusterRun(t, f, "cluster.admission-policy", clusterWithRBAC(t, clusterAllowAll))
	assertStatus(t, r, "PASS")
	clusterAssertSummaryOmits(t, r, "PodSecurity", "Kyverno", "Gatekeeper", "restricted")
}

// ...and the converse: a vanilla cluster whose identity has no SCC rights at
// all (there are no SCCs to have rights over) must not be failed for it.
func TestClusterAdmissionVanillaDoesNotEvaluateTheOpenShiftBranch(t *testing.T) {
	r := clusterRun(t, vanilla(), "cluster.admission-policy",
		clusterWithRBAC(t, func(_, _, _, _ string) bool { return false }))
	assertStatus(t, r, "PASS")
	clusterAssertSummaryOmits(t, r, "SecurityContextConstraints", "SCC")
}

func TestClusterAdmissionOpenShiftSkipsWhenAccessReviewCannotBePosted(t *testing.T) {
	assertSkipHasReason(t, clusterRun(t, openShift(), "cluster.admission-policy", clusterNoClientset))
}
