package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The charts group answers one question per hub: can the thing that resolves a
// chart reach the place the chart lives? It is deliberately separate from the
// registry group because the failures are different failures. A blocked
// registry shows up as ImagePullBackOff on a pod an operator can see; a blocked
// chart repository shows up as an ArgoCD Application that never produces a
// single object, or as `helm dependency update` failing on the repo-server —
// and nothing at all is created to look at (FRD-020 §5.5).
//
// Two of the four hubs are not reached at install time at all: budcluster pulls
// the NFD/HAMi/NGC charts and the Aibrix release manifests during *cluster
// onboarding*, which is why they are RISK. An install that succeeds today and
// an onboarding that fails next week is still a bad day, so they are checked.

const (
	chartsOCIRepo     = "oci://registry.bud.studio/charts"
	chartsOCIRegistry = "registry.bud.studio"

	// GitHub serves release assets with a 302 to a separate CDN host. An
	// egress allowlist that names github.com and stops there passes a manual
	// `curl -I` (which shows the 302) and fails the actual download.
	chartsGitHubAssetCDN = "objects.githubusercontent.com"

	chartsAibrixDependencyURL = "https://github.com/BudEcosystem/aibrix/releases/download/0.3.0/aibrix-dependency-v0.3.0.yaml"
)

// chartsOCIEntry is one chart published to the private OCI repository, with the pin
// this budctl release was built against (infra/appsets/*.yaml, and
// infra/charts/bud/Chart.yaml for the umbrella chart itself).
//
// The pins are embedded rather than read from the cluster because at the moment
// this check runs there is usually no ArgoCD yet to read them from — that is
// the whole point of the tool. `--chart-dir` overrides the umbrella entry, so
// an operator installing a version this binary predates is checked against the
// version they are actually installing rather than against a stale constant.
type chartsOCIEntry struct {
	name    string
	version string
	// required reports whether this chart is part of the install the operator
	// described. A chart nobody selected must never turn into a blocker.
	required func(c *engine.Ctx) bool
	// scope explains, in the report, why an unresolved chart matters or does not.
	scope string
}

func chartsScopeAlways(*engine.Ctx) bool { return true }

var chartsOCICatalogue = []chartsOCIEntry{
	{"bud", "1.2.8", chartsScopeAlways, "the platform itself"},
	{"keycloak", "0.2.1", chartsScopeAlways, "the identity provider every service authenticates against"},
	{"cert-manager", "0.1.3", func(c *engine.Ctx) bool {
		// Only ACME issuance needs the operator; a customer-provided certificate
		// is a Secret, and cert-manager is then an addon rather than a step in
		// the critical path.
		return strings.HasPrefix(string(c.Answers.TLS), "acme")
	}, "issues the certificate for every published hostname"},
	{"postgres", "0.1.1", chartsScopeInClusterData, "CloudNativePG cluster for every service database"},
	{"clickhouse", "0.1.1", chartsScopeInClusterData, "budmetrics and gateway analytics storage"},
	{"kafka", "0.1.1", chartsScopeInClusterData, "the event bus"},
	{"mongodb", "0.1.1", chartsScopeInClusterData, "Novu's datastore"},
	{"seaweedfs", "0.1.1", chartsScopeInClusterData, "the S3 object store the model registry writes to"},
	{"kyverno", "0.0.4", chartsScopeOptional, "policy addon, installed only when selected"},
	{"budagent", "0.3.6", chartsScopeOptional, "bud-studio addon, installed only when selected"},
}

func chartsScopeInClusterData(c *engine.Ctx) bool { return c.Answers.InClusterData }
func chartsScopeOptional(*engine.Ctx) bool        { return false }

func init() {
	engine.Register(&engine.Check{
		ID: "charts.oci", Group: "charts", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("charts.oci")
			if c.OCI == nil {
				return ch.Skip("no OCI adapter on this run: the chart repository was not contacted")
			}

			// Ask the registry API first. Separating "the host does not answer"
			// from "the chart is not there" is the difference between an egress
			// ticket and a release-pinning ticket, and the remedies share nothing.
			reach := c.OCI.Reachable(ctx, chartsOCIRegistry)
			if !reach.Reachable {
				return ch.Fail(
					"the OCI chart repository "+chartsOCIRepo+" does not answer, so every ApplicationSet source fails to resolve and nothing is installed at all",
					"allow HTTPS egress to registry.bud.studio:443 from this machine and from the ArgoCD repo-server, or mirror the charts and repoint the ApplicationSets at the mirror",
					"consequence: no Application produces a single object — there is no failing pod to diagnose",
				).WithEvidence(engine.Evidence{
					What:   "GET https://" + chartsOCIRegistry + "/v2/",
					Output: chartsHTTPNote(reach),
				})
			}

			var cred *adapters.Credential
			if cr, ok := c.Opts.RegistryCreds[chartsOCIRegistry]; ok {
				cred = &cr
			}
			overrideName, overrideVersion, overrideSource := chartsLocalChart(c)

			var (
				resolved     []string
				missingBlock []string
				missingRisk  []string
				unauthorized []string
				unreachable  []string
				evidence     []engine.Evidence
			)
			for _, entry := range chartsOCICatalogue {
				version, source := entry.version, "embedded pin"
				if overrideName == entry.name && overrideVersion != "" {
					version, source = overrideVersion, overrideSource
				}
				ref := chartsOCIRepo + "/" + entry.name
				status, note := c.OCI.ChartManifest(ctx, ref, version, cred)
				label := entry.name + ":" + version
				evidence = append(evidence, engine.Evidence{
					What:   "HEAD " + ref + " at " + version + " (" + source + ")",
					Output: string(status) + " — " + note,
				})

				switch status {
				case adapters.ManifestOK:
					resolved = append(resolved, label)
				case adapters.ManifestNotFound:
					if entry.required(c) {
						missingBlock = append(missingBlock, label+" ("+entry.scope+")")
					} else {
						missingRisk = append(missingRisk, label+" ("+entry.scope+")")
					}
				case adapters.ManifestUnauthorized:
					unauthorized = append(unauthorized, label)
				default:
					unreachable = append(unreachable, label+": "+note)
				}
			}

			if len(unreachable) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d chart %s in %s could not be reached, so the sync stalls with no objects created",
						len(unreachable), Plural(len(unreachable), "reference", "references"), chartsOCIRepo),
					"re-run once egress to registry.bud.studio:443 is stable; if a proxy terminates TLS, trust its CA on this machine and on the repo-server",
					Sorted(unreachable)...,
				).WithEvidence(evidence...)
			}

			// A 401 with credentials in hand is a different fact from a 401
			// without: ArgoCD will present this same credential, so a rejection
			// here is a rejection at sync time.
			if len(unauthorized) > 0 && cred != nil {
				return ch.Fail(
					"the supplied registry credential cannot read "+chartsOCIRepo+", so the ArgoCD repository Secret built from it will not resolve a single chart",
					"issue a robot account with pull rights on the charts/ path and re-run with --registry-credentials",
					Sorted(unauthorized)...,
				).WithEvidence(evidence...)
			}

			if len(missingBlock) > 0 {
				return ch.Fail(
					fmt.Sprintf("%s not published at the pinned %s, so %s Application never becomes healthy",
						Plural(len(missingBlock), "a required chart is", "required charts are"),
						Plural(len(missingBlock), "version", "versions"),
						Plural(len(missingBlock), "its", "their")),
					"publish the pinned version, or point the ApplicationSet targetRevision at a version that exists; pass --chart-dir <path> so budctl checks the version you will actually install",
					Sorted(missingBlock)...,
				).WithEvidence(evidence...)
			}

			if len(missingRisk) > 0 {
				return ch.FailAs(engine.Risk,
					"every required chart resolves, but an optional addon chart is absent at its pinned version and will fail if it is selected later",
					"pin the addon to a published version before enabling it",
					Sorted(missingRisk)...,
				).WithEvidence(evidence...)
			}

			if len(resolved) == 0 {
				// Everything answered 401 and no credential was supplied. The
				// repository is demonstrably live and authenticating, which is
				// the pre-credential question (FRD-020 D7) — but no version was
				// verified, and the bounds must say so rather than imply one was.
				return ch.Pass(
					chartsOCIRepo+" answers and authenticates; no credential was supplied, so no chart version was resolved",
					Sorted(unauthorized)...,
				).WithEvidence(evidence...).
					Bounds("that any chart exists at its pinned version — pass --registry-credentials to resolve the manifests")
			}

			res := ch.Pass(
				fmt.Sprintf("%d chart %s at %s", len(resolved), Plural(len(resolved), "version resolves", "versions resolve"), chartsOCIRepo),
				Sorted(resolved)...,
			).WithEvidence(evidence...)
			if len(unauthorized) > 0 {
				res = res.With("not resolved (HTTP 401, no credential for this path): " + strings.Join(Sorted(unauthorized), ", "))
			}
			return res.Bounds("that the chart archives download or render: only their manifests were requested, never a layer")
		},
	})

	engine.Register(&engine.Check{
		ID: "charts.classic", Group: "charts", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("charts.classic")
			if c.Net == nil {
				return ch.Skip("no network adapter on this run: the chart repositories were not contacted")
			}
			classic, _ := chartsRepoTargets(c.Profile)
			if len(classic) == 0 {
				return ch.Skip("the embedded chart-repository inventory names no classic repositories")
			}

			var (
				blockers []string
				risks    []string
				ok       []string
				evidence []engine.Evidence
			)
			for _, t := range classic {
				r := c.Net.Probe(ctx, t.URL)
				evidence = append(evidence, engine.Evidence{
					What:   "GET " + t.URL,
					Output: chartsHTTPNote(r),
				})
				if chartsIndexOK(r) {
					ok = append(ok, t.Label)
					continue
				}
				sev, note := chartsClassicSeverity(c, t)
				// The consequence line names the chart that needs the repo, which
				// is what makes the finding actionable: "bitnami unreachable" is
				// not the same problem as "the common library subchart is absent".
				line := fmt.Sprintf("%s (%s): %s — %s", t.Label, t.URL, chartsHTTPNote(r), t.Consequence)
				if note != "" {
					line += " [" + note + "]"
				}
				if sev == engine.Block {
					blockers = append(blockers, line)
				} else {
					risks = append(risks, line)
				}
			}

			switch {
			case len(blockers) > 0:
				return ch.Fail(
					fmt.Sprintf("%d chart %s in scope %s serve index.yaml, so the dependencies pinned against %s never resolve and those charts do not install",
						len(blockers), Plural(len(blockers), "repository", "repositories"),
						Plural(len(blockers), "does not", "do not"),
						Plural(len(blockers), "it", "them")),
					"allowlist these hosts on :443 from whatever runs the dependency resolve — this workstation for a direct `helm install`, the ArgoCD repo-server for a synced install — or mirror each repo and repoint the chart dependencies",
					append(Sorted(blockers), Sorted(risks)...)...,
				).WithEvidence(evidence...)
			case len(risks) > 0:
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("every in-scope chart repository answers; %d optional %s unreachable and the feature behind it cannot be installed later",
						len(risks), Plural(len(risks), "repository is", "repositories are")),
					"allowlist the host before enabling the feature that needs it, or drop the feature from the install",
					Sorted(risks)...,
				).WithEvidence(evidence...)
			default:
				return ch.Pass(
					fmt.Sprintf("all %d classic chart %s serve index.yaml", len(ok), Plural(len(ok), "repository", "repositories")),
					Sorted(ok)...,
				).WithEvidence(evidence...).
					Bounds("that each pinned dependency version exists inside the index, nor that the ArgoCD repo-server can reach these hosts — this fetch came from the workstation, and egress.* is what tests the cluster's own path")
			}
		},
	})

	engine.Register(&engine.Check{
		ID: "charts.runtime", Group: "charts", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("charts.runtime")
			if c.Net == nil {
				return ch.Skip("no network adapter on this run: the runtime chart repositories were not contacted")
			}
			_, runtime := chartsRepoTargets(c.Profile)
			if len(runtime) == 0 {
				return ch.Skip("the embedded chart-repository inventory names no runtime (onboarding-time) repositories")
			}

			gpu, gpuWhy := chartsGPUExpected(ctx, c)
			var (
				inScopeFail []string
				outOfScope  []string
				ok          []string
				evidence    []engine.Evidence
			)
			for _, t := range runtime {
				r := c.Net.Probe(ctx, t.URL)
				evidence = append(evidence, engine.Evidence{What: "GET " + t.URL, Output: chartsHTTPNote(r)})
				// NFD is installed on every cluster budcluster onboards; HAMi and
				// the NVIDIA operator only where GPUs are found. Reporting a host
				// nobody will contact as a finding trains operators to ignore the
				// report, so the GPU pair is scoped.
				inScope := !chartsIsGPURepo(t.URL) || gpu
				if chartsIndexOK(r) {
					ok = append(ok, t.Label)
					continue
				}
				line := fmt.Sprintf("%s (%s): %s — %s", t.Label, t.URL, chartsHTTPNote(r), t.Consequence)
				if inScope {
					inScopeFail = append(inScopeFail, line)
				} else {
					outOfScope = append(outOfScope, line)
				}
			}

			if len(inScopeFail) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d chart %s budcluster fetches during cluster onboarding %s answer, so onboarding a cluster fails later even though this install succeeds",
						len(inScopeFail), Plural(len(inScopeFail), "repository", "repositories"),
						Plural(len(inScopeFail), "does not", "do not")),
					"allowlist these hosts on :443 from the cluster network budcluster runs in — it is budcluster's pod, not this workstation, that runs `helm repo add` at onboarding",
					append(Sorted(inScopeFail), Sorted(outOfScope)...)...,
				).WithEvidence(evidence...).
					With("GPU scope: " + gpuWhy)
			}

			res := ch.Pass(
				fmt.Sprintf("%d onboarding-time chart %s answer", len(ok), Plural(len(ok), "repository", "repositories")),
				Sorted(ok)...,
			).WithEvidence(evidence...)
			if len(outOfScope) > 0 {
				res = res.With(append([]string{"unreachable but out of scope for this cluster (" + gpuWhy + "):"}, Sorted(outOfScope)...)...)
			}
			return res.Bounds("that the cluster itself can reach these repos: budcluster pulls them from inside the cluster at onboarding, and this was a workstation fetch")
		},
	})

	engine.Register(&engine.Check{
		ID: "charts.aibrix", Group: "charts", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("charts.aibrix")
			if c.Net == nil {
				return ch.Skip("no network adapter on this run: the Aibrix release manifests were not fetched")
			}
			dep := chartsAibrixManifest(c.Profile)
			core := strings.Replace(dep, "aibrix-dependency-", "aibrix-core-", 1)

			// The CDN is probed as a host, not as a document: its root serves no
			// index, so any HTTP answer proves DNS, routing and TLS — which is
			// the whole question for an allowlist entry.
			cdn := c.Net.Probe(ctx, "https://"+chartsGitHubAssetCDN)
			evidence := []engine.Evidence{{What: "GET https://" + chartsGitHubAssetCDN, Output: chartsHTTPNote(cdn)}}

			var failed []string
			var ok []string
			for _, u := range Sorted([]string{dep, core}) {
				r := c.Net.Probe(ctx, u)
				evidence = append(evidence, engine.Evidence{What: "GET " + u + " (302 → " + chartsGitHubAssetCDN + ")", Output: chartsHTTPNote(r)})
				if chartsIndexOK(r) {
					ok = append(ok, u)
					continue
				}
				failed = append(failed, u+": "+chartsHTTPNote(r))
			}

			if len(failed) > 0 {
				detail := Sorted(failed)
				remedy := "allowlist BOTH github.com and " + chartsGitHubAssetCDN + " on :443 from the cluster network — a release asset 302s to the CDN, so an allowlist naming github.com alone passes a manual curl and still fails the download"
				if !cdn.Reachable {
					detail = append(detail, "the asset CDN "+chartsGitHubAssetCDN+" is itself unreachable ("+chartsHTTPNote(cdn)+"), which is the usual shape of a github.com-only allowlist")
				}
				return ch.Fail(
					fmt.Sprintf("%d Aibrix release %s cannot be fetched, so budcluster cannot install the Aibrix data plane at cluster onboarding and model deployments have no gateway",
						len(failed), Plural(len(failed), "manifest", "manifests")),
					remedy, detail...,
				).WithEvidence(evidence...)
			}

			res := ch.Pass("both Aibrix release manifests fetch, redirect chain included", Sorted(ok)...).
				WithEvidence(evidence...).
				With("release assets redirect to " + chartsGitHubAssetCDN + ", so both hosts must be on any egress allowlist")
			if !cdn.Reachable {
				// A manifest that resolved while the CDN root refused is worth
				// saying out loud: the redirect may have been served from a
				// cache, and the next onboarding will not be.
				res = res.With("note: " + chartsGitHubAssetCDN + " did not answer directly (" + chartsHTTPNote(cdn) + ")")
			}
			return res.Bounds("that the cluster can fetch them: budcluster downloads these from inside the cluster at onboarding, and it does not prove the Aibrix images themselves pull from docker.io")
		},
	})
}

// chartRepoTargets splits the embedded egress inventory into the repositories an
// install resolves and the ones budcluster fetches later at cluster onboarding.
// They are the same kind of host and differ only in when they are needed, which
// is exactly the difference between BLOCK and RISK here.
func chartsRepoTargets(p intake.Profile) (classic, runtime []intake.EgressTarget) {
	for _, t := range p.Egress {
		if !strings.Contains(strings.ToLower(t.Label), "charts") || !strings.Contains(t.URL, "index.yaml") {
			continue
		}
		if chartsIsRuntimeRepo(t.URL) {
			runtime = append(runtime, t)
		} else {
			classic = append(classic, t)
		}
	}
	return classic, runtime
}

// chartsIsRuntimeRepo names the three hubs budcluster adds with `helm repo add`
// during cluster onboarding rather than at install time.
func chartsIsRuntimeRepo(u string) bool {
	return strings.Contains(u, "node-feature-discovery") || chartsIsGPURepo(u)
}

func chartsIsGPURepo(u string) bool {
	return strings.Contains(u, "project-hami.github.io") || strings.Contains(u, "helm.ngc.nvidia.com")
}

// chartsClassicSeverity decides whether an unreachable repo blocks THIS install.
// The inventory's `when` field carries the general answer; the intake answers
// narrow it, because a repo serving an operator the operator does not want is
// not a blocker for them.
func chartsClassicSeverity(c *engine.Ctx, t intake.EgressTarget) (engine.Severity, string) {
	if chartsIsDataStoreRepo(t.URL) && !c.Answers.InClusterData {
		return engine.Risk, "external data stores selected, so this operator is not installed"
	}
	if strings.Contains(t.URL, "argoproj.github.io") && !(c.Answers.UseArgoCD && c.Opts.ArgoCDEnabled) {
		return engine.Risk, "ArgoCD is not being bootstrapped from its Helm chart on this run"
	}
	if t.When == "install" {
		return engine.Block, ""
	}
	return engine.Risk, "optional: needed only if the feature behind it is enabled"
}

func chartsIsDataStoreRepo(u string) bool {
	for _, h := range []string{"cloudnative-pg.github.io", "docs.altinity.com", "percona.github.io"} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

// chartsIndexOK: an index.yaml is a document, not a registry endpoint, so the
// 401-is-a-pass rule that governs §5.4 does NOT apply here. A 403 or a 404 means
// the resolve fails, and calling that reachable would be a false pass.
func chartsIndexOK(r adapters.HTTPResult) bool {
	return r.Reachable && r.Status >= 200 && r.Status < 300
}

func chartsHTTPNote(r adapters.HTTPResult) string {
	switch {
	case !r.Reachable:
		if r.Err == "" {
			return "no response"
		}
		return r.Err
	case r.Status >= 400:
		return fmt.Sprintf("HTTP %d", r.Status)
	default:
		return fmt.Sprintf("HTTP %d in %s", r.Status, r.Latency.Round(time.Millisecond))
	}
}

// chartsLocalChart reads the chart the operator is actually holding. Checking a
// version nobody is installing is worse than not checking: it produces a
// confident BLOCK about a release that is not in play.
func chartsLocalChart(c *engine.Ctx) (name, version, source string) {
	if c.Helm == nil || c.Opts.ChartDir == "" {
		return "", "", ""
	}
	lc, err := c.Helm.LoadChart(c.Opts.ChartDir)
	if err != nil || lc == nil || lc.Metadata == nil {
		return "", "", ""
	}
	return lc.Metadata.Name, lc.Metadata.Version, "--chart-dir " + c.Opts.ChartDir
}

// chartsGPUExpected answers whether the GPU-only onboarding path is in play. The
// intake answer is the operator's intent; the node labels are the cluster's
// reality, and either one puts the path in scope. This does not use
// engine.KeyGPUNodes: the gpu group runs after charts, so that key is empty here.
func chartsGPUExpected(ctx context.Context, c *engine.Ctx) (bool, string) {
	if c.Answers.GPU {
		return true, "intake says this is a GPU cluster"
	}
	if c.Kube == nil {
		return false, "intake says no GPU and the cluster is unreachable, so no node could be inspected"
	}
	for _, n := range c.Kube.List(ctx, "nodes", "") {
		if n.Dig("status", "allocatable", "nvidia.com/gpu") != nil {
			return true, "node " + n.Name() + " advertises nvidia.com/gpu even though intake said no GPU"
		}
		if n.Labels()["nvidia.com/gpu.present"] == "true" {
			return true, "node " + n.Name() + " is labelled nvidia.com/gpu.present"
		}
	}
	return false, "intake says no GPU and no node advertises nvidia.com/gpu"
}

// chartsAibrixManifest prefers the inventory's URL so the version bumps in one
// place, and falls back to the pinned constant when the inventory is trimmed.
func chartsAibrixManifest(p intake.Profile) string {
	for _, t := range p.Egress {
		if strings.Contains(strings.ToLower(t.Label), "aibrix") && strings.Contains(t.URL, "releases/download/") {
			return t.URL
		}
	}
	return chartsAibrixDependencyURL
}
