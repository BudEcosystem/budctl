package checks

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// ArgoCD is deliberately OPTIONAL (FRD-020 §5.3). It is itself an element of the
// cluster-addons ApplicationSet and the documented flow bootstraps it *after*
// deciding the cluster is suitable, so its absence is never a blocker. The group
// therefore runs in one of two modes and says which:
//
//	absent  — check the INPUTS ArgoCD will need. Those are required whether or
//	          not ArgoCD exists yet, so they stay BLOCK; argocd.installed is INFO.
//	present — additionally check ArgoCD's own state, at RISK throughout: a
//	          misconfigured existing ArgoCD is something the operator fixes
//	          during the install, not a reason the cluster is unfit.

const (
	// The OCI chart repository every ApplicationSet element sources from
	// (infra/appsets/*.yaml: `repoURL: registry.bud.studio/charts`).
	argocdChartRegistry = "registry.bud.studio"
	argocdChartRepo     = "charts"
	argocdUmbrellaChart = "bud"

	// Multi-source Applications with a `$values` ref landed in Argo CD 2.6.
	// Both ApplicationSets depend on it — cluster-addons references
	// "$values/infra/values/dapr/values.yaml" — so an older ArgoCD renders the
	// value files as literal paths and every Application fails to generate.
	// This floor is a property of the appsets, not of the cluster, which is why
	// it is a constant here rather than a field in profiles/defaults.yaml.
	argocdMinVersion = "2.6"

	// The repo-server initContainer in infra/charts/argocd/values.yaml fetches
	// its tooling from these hosts on EVERY restart. GitHub release assets
	// redirect to a second CDN host, so an allowlist naming only github.com
	// fails at the redirect.
	argocdToolsProbeScript = `urls="https://github.com https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64 https://dl.k8s.io/release/stable.txt"
for u in $urls; do
  code=$(curl -sS -L -I -o /dev/null -w '%{http_code}' --max-time 20 "$u" 2>&1) || code="error: $code"
  echo "$u $code"
done`
)

func init() {
	engine.Register(&engine.Check{
		ID: "argocd.installed", Group: "argocd", Severity: engine.Info,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.installed")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: cannot tell whether ArgoCD is installed")
			}
			inst := argocdDetect(ctx, c)
			if !inst.present {
				// INFO, never BLOCK: argocd is in the appset component list
				// (FRD-020 §3.1), so requiring it here would be requiring that
				// the installer has already run.
				return ch.Infof("ArgoCD is not installed; install it after this check — it is not a prerequisite").
					With(
						"only the input checks run in this mode: argocd.chart-repo-reachable and argocd.config-repo-reachable",
						"to install: kubectl create namespace argocd && kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml",
						"looked in namespace "+argocdNamespace(c)+" and cluster-wide for workloads labelled app.kubernetes.io/part-of=argocd")
			}
			detail := []string{"namespace " + inst.namespace}
			detail = append(detail, inst.workloadNames()...)
			ver := inst.version
			if ver == "" {
				ver = "version undetermined"
			}
			return ch.Infof("ArgoCD (%s) is already installed in namespace %s — checking its state as well as its inputs", ver, inst.namespace).
				With(detail...).
				Bounds("presence is not health: whether the control plane is Available is argocd.healthy, and whether it can sync is argocd.rbac")
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.chart-repo-reachable", Group: "argocd", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.chart-repo-reachable")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.OCI == nil {
				return ch.Skip("no registry client available, so oci://" + argocdChartRegistry + "/" + argocdChartRepo + " was not contacted")
			}

			// Reachability first, and a 401 counts: it proves DNS, routing, TLS
			// and a live registry, which is the whole question before a robot
			// account has been issued (FRD-020 §5.4).
			reach := c.OCI.Reachable(ctx, argocdChartRegistry)
			ev := engine.Evidence{
				What:   "GET https://" + argocdChartRegistry + "/v2/",
				Output: argocdHTTPSummary(reach),
			}
			if !reach.Reachable {
				return ch.Fail(
					fmt.Sprintf("%s does not answer, so ArgoCD can never pull the %s chart and every Application stays Unknown", argocdChartRegistry, argocdUmbrellaChart),
					"allowlist https://"+argocdChartRegistry+" for egress (and for the repo-server pod, not just this workstation), then re-run: curl -sS -o /dev/null -w '%{http_code}\\n' https://"+argocdChartRegistry+"/v2/",
					"error: "+reach.Err).WithEvidence(ev)
			}
			if reach.Status != 200 && reach.Status != 401 {
				return ch.Fail(
					fmt.Sprintf("https://%s/v2/ answered HTTP %d instead of 200 or 401 — something other than an OCI registry is on this address, and chart pulls will fail", argocdChartRegistry, reach.Status),
					"check whether an egress proxy or captive portal is intercepting the host; the registry API must answer /v2/ with 200 or 401").
					WithEvidence(ev)
			}

			chartRef := "oci://" + argocdChartRegistry + "/" + argocdChartRepo + "/" + argocdUmbrellaChart
			version := argocdTargetChartVersion(c)
			cred := argocdRegistryCredential(c, argocdChartRegistry)
			if version == "" {
				// No --chart-dir: there is no version to resolve against, and
				// inventing one would manufacture a false BLOCK.
				return ch.Pass(fmt.Sprintf("%s answers (HTTP %d) — the chart repo ArgoCD will pull from is reachable", argocdChartRegistry, reach.Status)).
					With("no --chart-dir was given, so no chart version was resolved").
					WithEvidence(ev).
					Bounds("the registry answers; that the " + argocdUmbrellaChart + " chart exists at the version the ApplicationSet pins was not checked, and workstation reachability is not repo-server reachability")
			}

			status, msg := c.OCI.ChartManifest(ctx, chartRef, version, cred)
			manEv := engine.Evidence{
				What:   fmt.Sprintf("HEAD https://%s/v2/%s/%s/manifests/%s", argocdChartRegistry, argocdChartRepo, argocdUmbrellaChart, version),
				Output: string(status) + ": " + msg,
			}
			switch status {
			case adapters.ManifestOK:
				return ch.Pass(fmt.Sprintf("%s resolves at %s", chartRef, version)).
					WithEvidence(ev, manEv).
					Bounds("the manifest resolves for this identity from this workstation; it does not prove the repo-server pod can reach the registry, nor that the chart's own dependencies resolve (charts.classic)")
			case adapters.ManifestNotFound:
				return ch.Fail(
					fmt.Sprintf("the %s chart is not published at %s: ArgoCD will report 'chart not found' and the Application never renders", argocdUmbrellaChart, version),
					"pin targetRevision in the ApplicationSet to a version that exists — list them with: helm show chart "+chartRef+" --version <version>",
					"version came from "+c.Opts.ChartDir+"/Chart.yaml").
					WithEvidence(manEv)
			case adapters.ManifestUnauthorized:
				if cred == nil {
					// Expected before the robot account is issued: an auth
					// challenge still proves the repository is being served.
					return ch.Pass(fmt.Sprintf("%s answers and demands credentials (HTTP 401), which is the expected answer before a robot account exists", chartRef)).
						WithEvidence(ev, manEv).
						Bounds("no credentials were supplied, so the " + argocdUmbrellaChart + " chart's existence at " + version + " was not verified — registry.auth covers the credential itself")
				}
				return ch.Fail(
					fmt.Sprintf("the supplied credentials are rejected for %s, so ArgoCD's repository Secret will be rejected the same way and no Application syncs", chartRef),
					"re-issue the registry robot account with pull on "+argocdChartRepo+"/*, then verify with: helm registry login "+argocdChartRegistry+" -u 'robot$yourname'",
					msg).
					WithEvidence(manEv)
			default:
				return ch.Fail(
					fmt.Sprintf("%s could not be resolved (%s), so ArgoCD has no chart to sync", chartRef, msg),
					"check egress to https://"+argocdChartRegistry+" and any intercepting proxy, then re-run: helm show chart "+chartRef+" --version "+version).
					WithEvidence(ev, manEv)
			}
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.config-repo-reachable", Group: "argocd", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.config-repo-reachable")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Net == nil {
				return ch.Skip("no network client available, so the config repo was not contacted")
			}
			repo := strings.TrimSpace(c.Answers.ConfigRepo)
			if repo == "" {
				// Not a skip. The ApplicationSets take their values and secrets
				// from this repo; without one there is nothing for ArgoCD to
				// sync, so an unstated config repo is a missing prerequisite
				// rather than a question budctl chose not to ask.
				return ch.Fail(
					"no config repo is configured, and the ApplicationSets have nowhere to read values or secrets from — ArgoCD would sync an empty configuration",
					"set the git repo holding your values.yaml and secrets.yaml (--config-repo, or the guided form): "+
						"https://... for token auth, ssh://git@... for key auth on port 22")
			}

			host, port, transport := argocdRepoTransport(repo)
			switch transport {
			case "ssh":
				// Port 22, not 443. A 443-only egress allowlist is the single
				// likeliest way for every Application to stop syncing silently.
				ok, why := c.Net.TCP(ctx, host, port)
				ev := engine.Evidence{What: fmt.Sprintf("TCP connect %s:%d", host, port), Output: argocdTCPSummary(ok, why)}
				if !ok {
					return ch.Fail(
						fmt.Sprintf("%s:%d does not accept a connection, so ArgoCD can never fetch %s and every Application stays Unknown with no values to render", host, port, repo),
						fmt.Sprintf("open outbound TCP to %s:%d — git over SSH uses port %d, NOT 443, and a 443-only egress policy blocks it silently. If only 443 may leave the network, switch the repoURL to https:// (GitHub also serves SSH on ssh.github.com:443).", host, port, port),
						"error: "+why).
						WithEvidence(ev)
				}
				return ch.Pass(fmt.Sprintf("%s:%d accepts connections", host, port)).
					WithEvidence(ev).
					Bounds("the port is open from this workstation; the deploy key's authorization, the repository's existence and egress from the repo-server pod were not tested")

			case "http":
				// The git dumb/smart-HTTP discovery endpoint: what ArgoCD's
				// repo-server itself requests first.
				infoRefs := strings.TrimSuffix(repo, "/") + "/info/refs?service=git-upload-pack"
				res := c.Net.Probe(ctx, infoRefs)
				ev := engine.Evidence{What: "GET " + infoRefs, Output: argocdHTTPSummary(res)}
				if !res.Reachable {
					return ch.Fail(
						fmt.Sprintf("%s does not answer, so ArgoCD cannot fetch the values the ApplicationSets reference and no Application renders", repo),
						"fix DNS/egress for "+host+" (allowlist it, or point the repoURL at a mirror the cluster can reach), then re-run: git ls-remote "+repo,
						"error: "+res.Err).
						WithEvidence(ev)
				}
				switch {
				case res.Status >= 200 && res.Status < 300:
					return ch.Pass(fmt.Sprintf("%s serves git-upload-pack (HTTP %d)", repo, res.Status)).
						WithEvidence(ev).
						Bounds("the endpoint answers; the branch or path the Applications reference, and ArgoCD's own credentials, were not tested")
				case res.Status == 401 || res.Status == 403:
					return ch.Pass(fmt.Sprintf("%s answers and demands credentials (HTTP %d), which ArgoCD supplies from its repository Secret", repo, res.Status)).
						WithEvidence(ev).
						Bounds("a " + fmt.Sprint(res.Status) + " does not distinguish a private repository from one that does not exist — most hosts hide both behind the same answer — and the credential itself was not tested")
				case res.Status == 404:
					return ch.Fail(
						fmt.Sprintf("there is no git repository at %s (HTTP 404), so every $values source in the ApplicationSets fails to resolve", repo),
						"correct answers.configRepo to the repository's real URL; if it is private, create the ArgoCD repository Secret for it so the host stops hiding it: kubectl apply -n "+argocdNamespace(c)+" -f - (label argocd.argoproj.io/secret-type: repository)").
						WithEvidence(ev)
				default:
					return ch.Fail(
						fmt.Sprintf("%s answered HTTP %d instead of serving git-upload-pack, so ArgoCD cannot clone it", repo, res.Status),
						"check whether a proxy or gateway is intercepting the host, then verify by hand: git ls-remote "+repo).
						WithEvidence(ev)
				}

			default:
				return ch.Fail(
					fmt.Sprintf("config repo %q has no recognisable git transport, so ArgoCD will reject the repoURL and generate no Applications", repo),
					"set answers.configRepo to a full URL — https://host/org/repo(.git) or ssh://git@host/org/repo")
			}
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.healthy", Group: "argocd", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.healthy")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: ArgoCD's control plane was not inspected")
			}
			inst := argocdDetect(ctx, c)
			if !inst.present {
				return ch.Skip("ArgoCD is not installed yet (argocd.installed), so there is no control plane to health-check")
			}

			problems, healthy := []string{}, []string{}
			for _, comp := range argocdComponents {
				o := inst.find(comp.match)
				if o == nil {
					problems = append(problems, fmt.Sprintf("no %s workload exists — %s", comp.match, comp.consequence))
					continue
				}
				ready, desired := argocdReplicas(o)
				if ready < 1 {
					problems = append(problems, fmt.Sprintf("%s has %d/%d available — %s", o.Name(), ready, desired, comp.consequence))
					continue
				}
				healthy = append(healthy, fmt.Sprintf("%s %d/%d available", o.Name(), ready, desired))
			}

			if len(problems) > 0 {
				summary := "ArgoCD is installed but " + problems[0]
				if len(problems) > 1 {
					summary += fmt.Sprintf(" (and %d other %s)", len(problems)-1, Plural(len(problems)-1, "component", "components"))
				}
				// RISK, not BLOCK: the cluster is still fit to host Bud — the
				// operator repairs or reinstalls ArgoCD during the install.
				return ch.Fail(summary,
					"kubectl -n "+inst.namespace+" get pods -l app.kubernetes.io/part-of=argocd, then describe the unready pod: an unavailable repo-server is usually an image it cannot pull (ArgoCD's bundled Redis comes from ecr-public.aws.com) or the missing helm-secrets-private-age-keys Secret the download-tools initContainer mounts",
					append(problems, healthy...)...)
			}
			return ch.Pass("ArgoCD's application-controller, repo-server and applicationset-controller are all Available").
				With(healthy...).
				Bounds("Available replicas are not a working sync: whether the controller identity may create the objects is argocd.rbac, and whether it can pull the charts is argocd.chart-repo-credential")
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.version", Group: "argocd", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.version")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: ArgoCD's version was not read")
			}
			inst := argocdDetect(ctx, c)
			if !inst.present {
				return ch.Skip("ArgoCD is not installed yet (argocd.installed); whatever is installed later will be current enough for multi-source Applications")
			}
			if inst.version == "" {
				// Never a pass: an unread version is not a supported version.
				return ch.Skip("ArgoCD is installed but its version could not be read from app.kubernetes.io/version or from the container image tags in namespace " + inst.namespace)
			}
			ev := engine.Evidence{
				What:   "ArgoCD version in namespace " + inst.namespace,
				Output: inst.version + " (from " + inst.versionFrom + ")",
			}
			if compareVersions(inst.version, argocdMinVersion) < 0 {
				return ch.Fail(
					fmt.Sprintf("ArgoCD %s predates multi-source Applications, so the $values references in both ApplicationSets resolve to nothing and every Application fails to generate manifests", inst.version),
					"upgrade ArgoCD to ≥ "+argocdMinVersion+" before applying the ApplicationSets (infra/charts/argocd pins the argo-cd chart at 9.5.15), or flatten the sources so no Application uses a $values ref",
					"both infra/appsets/cluster-addons.yaml and infra/appsets/stage-app.yaml reference \"$values/infra/values/...\"").
					WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("ArgoCD %s supports multi-source Applications with $values (≥ %s)", inst.version, argocdMinVersion)).
				WithEvidence(ev).
				Bounds("the version supports the feature; it does not prove the applicationset-controller is enabled, nor that its RBAC covers what the sources reference")
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.chart-repo-credential", Group: "argocd", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.chart-repo-credential")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: ArgoCD's repository Secrets were not inspected")
			}
			inst := argocdDetect(ctx, c)
			if !inst.present {
				return ch.Skip("ArgoCD is not installed yet, so it has no repository Secret — create it when you install it (installation.mdx Step 2)")
			}
			secrets := c.Kube.List(ctx, "secrets", inst.namespace)
			// A denied LIST comes back as an empty slice, which would otherwise
			// read as "no repository Secret exists" — the one input that turns
			// this check into a false RISK. Only an empty result needs the
			// extra question.
			if len(secrets) == 0 && !c.Kube.CanI(ctx, "list", "", "secrets", inst.namespace) {
				return ch.Skip("this identity may not list Secrets in " + inst.namespace + ", so the OCI repository credential could not be inspected")
			}

			var match adapters.Object
			seen := []string{}
			for _, s := range secrets {
				st := s.Labels()["argocd.argoproj.io/secret-type"]
				if st != "repository" && st != "repo-creds" {
					continue
				}
				repoURL := argocdSecretField(s, "url")
				seen = append(seen, s.Name()+" -> "+repoURL)
				if argocdRepoHost(repoURL) == argocdChartRegistry {
					match = s
					break
				}
			}
			ev := engine.Evidence{
				What:   "Secrets labelled argocd.argoproj.io/secret-type in " + inst.namespace,
				Output: strings.Join(Sorted(seen), "\n"),
			}
			if match == nil {
				return ch.Fail(
					fmt.Sprintf("no ArgoCD repository Secret covers %s/%s, so every Application sourcing the %s chart fails its first pull with 401 unauthorized", argocdChartRegistry, argocdChartRepo, argocdUmbrellaChart),
					"kubectl apply -n "+inst.namespace+" -f - <<'EOF'\napiVersion: v1\nkind: Secret\nmetadata:\n  name: bud-charts-repo\n  labels:\n    argocd.argoproj.io/secret-type: repository\nstringData:\n  type: helm\n  url: "+argocdChartRegistry+"/"+argocdChartRepo+"\n  enableOCI: \"true\"\n  username: robot$yourname\n  password: <token>\nEOF").
					WithEvidence(ev)
			}

			name := match.Name()
			repoType := argocdSecretField(match, "type")
			enableOCI := argocdSecretField(match, "enableOCI")
			switch {
			case !strings.EqualFold(enableOCI, "true"):
				return ch.Fail(
					fmt.Sprintf("repository Secret %s sets enableOCI=%q, so ArgoCD treats %s as a classic Helm repository, asks it for index.yaml and never resolves the chart", name, enableOCI, argocdChartRegistry),
					"kubectl patch secret "+name+" -n "+inst.namespace+" --type merge -p '{\"stringData\":{\"enableOCI\":\"true\"}}'").
					WithEvidence(ev)
			case repoType != "helm":
				return ch.Fail(
					fmt.Sprintf("repository Secret %s declares type=%q rather than helm, so ArgoCD tries to clone %s as a git repository and the chart source fails to resolve", name, repoType, argocdChartRegistry),
					"kubectl patch secret "+name+" -n "+inst.namespace+" --type merge -p '{\"stringData\":{\"type\":\"helm\"}}'").
					WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("repository Secret %s registers %s as an OCI Helm repository (type=helm, enableOCI=true)", name, argocdSecretField(match, "url"))).
				WithEvidence(ev).
				Bounds("the Secret exists and is shaped correctly; whether the credential inside it is accepted by the registry is argocd.chart-repo-reachable with --registry-credentials, and this check never reads the password")
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.rbac", Group: "argocd", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.rbac")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: ArgoCD's ServiceAccount permissions were not tested")
			}
			inst := argocdDetect(ctx, c)
			if !inst.present {
				// cluster.installer-rbac already covers the identity that
				// bootstraps ArgoCD; this check is about ArgoCD's own identity,
				// which does not exist yet.
				return ch.Skip("ArgoCD is not installed yet, so it has no ServiceAccount — cluster.installer-rbac covers the identity that will bootstrap it")
			}
			sa := inst.controllerServiceAccount()
			if sa == "" {
				return ch.Skip("the application-controller's ServiceAccount could not be resolved from its pod template in " + inst.namespace + ", and guessing an identity would test the wrong subject")
			}

			denied, allowed := []string{}, []string{}
			for _, want := range argocdSyncPermissions {
				ok, err := c.Kube.CanServiceAccount(ctx, sa, inst.namespace, "create", want.group, want.resource)
				if err != nil {
					return ch.Skip("this identity may not create SubjectAccessReviews, so ArgoCD's own permissions could not be tested: " + err.Error())
				}
				if ok {
					allowed = append(allowed, "create "+want.label)
					continue
				}
				denied = append(denied, fmt.Sprintf("create %s — %s", want.label, want.consequence))
			}
			ev := engine.Evidence{
				What:   fmt.Sprintf("SubjectAccessReview for system:serviceaccount:%s:%s", inst.namespace, sa),
				Output: strings.Join(append(append([]string{}, allowed...), denied...), "\n"),
			}
			if len(denied) > 0 {
				return ch.Fail(
					fmt.Sprintf("ArgoCD's %s may not %s, so the cluster-addons sync fails at the first object of that kind and the Applications stop half-applied", sa, denied[0]),
					"kubectl create clusterrolebinding argocd-application-controller-cluster-admin --clusterrole=cluster-admin --serviceaccount="+inst.namespace+":"+sa+"  # or bind a role that covers namespaces, CRDs, ClusterRoles and ClusterRoleBindings",
					denied...).
					WithEvidence(ev)
			}
			return ch.Pass(fmt.Sprintf("%s may create namespaces, CRDs, ClusterRoles and ClusterRoleBindings", sa)).
				With(allowed...).
				WithEvidence(ev).
				Bounds("SubjectAccessReview answers for this identity against THIS cluster: an Application whose destination is a remote cluster Secret runs as that cluster's credential instead, and an admission webhook can still reject an object the RBAC allows")
		},
	})

	engine.Register(&engine.Check{
		ID: "argocd.repo-server-egress", Group: "argocd", Severity: engine.Risk,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("argocd.repo-server-egress")
			if reason := argocdOff(c); reason != "" {
				return ch.Skip(reason)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the repo-server's tool downloads were not verified")
			}
			inst := argocdDetect(ctx, c)
			if !inst.present {
				return ch.Skip("ArgoCD is not installed yet, so there is no repo-server whose initContainer downloads could be verified")
			}
			repo := inst.find("repo-server")
			if repo == nil || !argocdHasInitContainer(repo, "download-tools") {
				// Only the chart in infra/charts/argocd wires this initContainer
				// in; a stock ArgoCD carries its tools in the image and has no
				// per-restart egress at all.
				return ch.Skip("this ArgoCD's repo-server has no download-tools initContainer, so it does not fetch sops, vals, helm-secrets, age, curl and kubectl on every restart")
			}
			if c.Probes == nil || c.Opts.NoProbe {
				return ch.Skip("--no-probe: egress to github.com and dl.k8s.io from inside the cluster was NOT verified, and the repo-server refetches its tooling on every restart")
			}

			image := c.Opts.ProbeImage
			if image == "" {
				image = "curlimages/curl:8.11.1"
			}
			outcome, err := c.Probes.RunPod(ctx, probes.PodSpec{
				Name:    "argocd-repo-server-egress",
				Image:   image,
				Command: []string{"sh", "-c", argocdToolsProbeScript},
				Timeout: 2 * time.Minute,
			})
			if err != nil {
				return ch.Skip("the egress probe pod could not be run in " + c.Probes.Namespace() + ": " + err.Error())
			}
			if !outcome.Scheduled {
				return ch.Skip(fmt.Sprintf("the egress probe pod never scheduled in %s (%s), so the repo-server's downloads were not verified: %s",
					c.Probes.Namespace(), outcome.Phase, strings.Join(outcome.Events, "; ")))
			}
			if !outcome.Started {
				// Per FRD-020 §6 an unpullable probe image IS the egress answer:
				// the download-tools initContainer pulls alpine from Docker Hub
				// on the same path.
				return ch.Fail(
					fmt.Sprintf("the probe image %s could not be started inside the cluster (%s), which is itself the answer: the repo-server pulls alpine and then six tools over the same egress path on every restart", image, outcome.Reason),
					"allowlist the image registry for cluster nodes, or set --probe-image to an image the cluster can already pull",
					outcome.Events...)
			}

			ok, bad := argocdParseEgress(outcome.Logs)
			ev := engine.Evidence{
				What:   "probe pod in " + c.Probes.Namespace() + ": curl -I -L each download-tools URL",
				Output: strings.TrimSpace(outcome.Logs),
			}
			detail := append([]string{}, ok...)
			if c.Platform != nil && c.Platform.ClusterProxy != "" {
				detail = append(detail, "cluster-wide egress proxy in effect ("+c.Platform.ClusterProxy+"): the download-tools initContainer sets no HTTP(S)_PROXY of its own, so unless the proxy is transparent its wget calls hang regardless of this result")
			}
			if len(bad) > 0 || len(ok) == 0 {
				if len(bad) == 0 {
					return ch.Skip(fmt.Sprintf("the probe pod ran but produced no readable output (phase %s, reason %s) — --probe-image must be an image carrying sh and curl", outcome.Phase, outcome.Reason))
				}
				return ch.Fail(
					fmt.Sprintf("the repo-server cannot fetch %s, so it never becomes Ready after a restart and every Application stops rendering", strings.Join(argocdHostsOf(bad), " and ")),
					"allowlist github.com, objects.githubusercontent.com (every github.com release asset redirects there), dl.k8s.io and cdn.dl.k8s.io for cluster egress — or bake sops, vals, helm-secrets, age, curl and kubectl into a custom repo-server image and drop the initContainer",
					append(bad, detail...)...).
					WithEvidence(ev)
			}
			return ch.Pass("the repo-server's download-tools hosts are reachable from inside the cluster").
				With(detail...).
				WithEvidence(ev).
				Bounds("the probe ran from a pod in " + c.Probes.Namespace() + ": the repo-server pod may sit under a different NetworkPolicy, ServiceAccount or node pool, and the tool versions the initContainer pins were not fetched")
		},
	})
}

// argocdOff reports why the whole group does not apply. ArgoCD is optional by
// design, and --no-argocd (a direct-Helm install) removes the question entirely
// rather than answering it (FRD-020 §5.3).
func argocdOff(c *engine.Ctx) string {
	if !c.Opts.ArgoCDEnabled {
		return "--no-argocd: this is a direct-Helm install, so neither ArgoCD nor the inputs it would need are checked"
	}
	return ""
}

func argocdNamespace(c *engine.Ctx) string {
	if c.Opts.ArgoCDNamespace != "" {
		return c.Opts.ArgoCDNamespace
	}
	return "argocd"
}

// argocdComponents are the three workloads FRD-020 §5.3 names, each with what
// its absence costs — a summary must state the consequence, not the observation.
var argocdComponents = []struct {
	match       string
	consequence string
}{
	{"application-controller", "nothing reconciles, so every Application stays OutOfSync and no sync ever starts"},
	{"repo-server", "no Application can render its chart, so every sync fails at 'failed to generate manifests'"},
	{"applicationset-controller", "the two ApplicationSets generate no Applications at all, and the install silently appears to do nothing"},
}

// argocdSyncPermissions is what the cluster-addons sync actually needs from
// ArgoCD's own identity: both ApplicationSets set CreateNamespace=true, and
// Dapr, CloudNativePG, Kyverno and the operators all ship CRDs and cluster RBAC.
var argocdSyncPermissions = []struct {
	group       string
	resource    string
	label       string
	consequence string
}{
	{"", "namespaces", "namespaces", "CreateNamespace=true is set on both ApplicationSets, so the very first sync fails"},
	{"apiextensions.k8s.io", "customresourcedefinitions", "customresourcedefinitions", "Dapr, CloudNativePG, Strimzi and the operators all ship CRDs"},
	{"rbac.authorization.k8s.io", "clusterroles", "clusterroles", "every operator in cluster-addons installs cluster-scoped RBAC"},
	{"rbac.authorization.k8s.io", "clusterrolebindings", "clusterrolebindings", "an operator without its binding never gets permission to run"},
}

// argocdInstall is what one detection pass found. Checks in a group run
// concurrently, so each one detects for itself; the Kube adapter caches the
// LISTs, so the repeat cost is a map lookup.
type argocdInstall struct {
	present     bool
	namespace   string
	version     string
	versionFrom string
	workloads   map[string]adapters.Object
}

func argocdDetect(ctx context.Context, c *engine.Ctx) argocdInstall {
	out := argocdInstall{namespace: argocdNamespace(c), workloads: map[string]adapters.Object{}}
	if c.Kube == nil {
		return out
	}
	kinds := []string{"deployments.apps", "statefulsets.apps"}
	for _, fq := range kinds {
		for _, o := range c.Kube.List(ctx, fq, out.namespace) {
			if argocdOwned(o) {
				out.workloads[o.Name()] = o
			}
		}
	}
	// ArgoCD is often installed somewhere other than "argocd". Reporting a
	// non-default namespace as "not installed" would silently skip every check
	// below, which reads as a clean run.
	if len(out.workloads) == 0 {
		byNS := map[string][]adapters.Object{}
		for _, fq := range kinds {
			for _, o := range c.Kube.List(ctx, fq, "") {
				if argocdOwned(o) {
					byNS[o.Namespace()] = append(byNS[o.Namespace()], o)
				}
			}
		}
		best := ""
		for _, ns := range Sorted(argocdKeys(byNS)) {
			if best == "" || len(byNS[ns]) > len(byNS[best]) {
				best = ns
			}
		}
		if best != "" {
			out.namespace = best
			for _, o := range byNS[best] {
				out.workloads[o.Name()] = o
			}
		}
	}
	out.present = len(out.workloads) > 0
	out.version, out.versionFrom = out.detectVersion()
	return out
}

func argocdKeys(m map[string][]adapters.Object) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// argocdOwned recognises ArgoCD's workloads by the label the upstream chart and
// the plain install manifest both set, falling back to the name prefix that
// every ArgoCD component carries.
func argocdOwned(o adapters.Object) bool {
	if o.Labels()["app.kubernetes.io/part-of"] == "argocd" {
		return true
	}
	return strings.HasPrefix(o.Name(), "argocd-")
}

func (i argocdInstall) workloadNames() []string {
	out := []string{}
	for name, o := range i.workloads {
		ready, desired := argocdReplicas(o)
		out = append(out, fmt.Sprintf("%s/%s %d/%d", strings.ToLower(o.Kind()), name, ready, desired))
	}
	return Sorted(out)
}

// find returns the workload whose name contains match, deterministically when
// more than one does.
func (i argocdInstall) find(match string) adapters.Object {
	names := make([]string, 0, len(i.workloads))
	for name := range i.workloads {
		names = append(names, name)
	}
	for _, name := range Sorted(names) {
		if strings.Contains(name, match) {
			return i.workloads[name]
		}
	}
	return nil
}

// detectVersion prefers the standard version label and falls back to the image
// tag, because a hand-applied install.yaml sets one or the other but rarely both.
func (i argocdInstall) detectVersion() (string, string) {
	names := make([]string, 0, len(i.workloads))
	for name := range i.workloads {
		names = append(names, name)
	}
	names = Sorted(names)
	for _, name := range names {
		if v := i.workloads[name].Labels()["app.kubernetes.io/version"]; v != "" {
			return strings.TrimPrefix(v, "v"), "label app.kubernetes.io/version on " + name
		}
	}
	for _, name := range names {
		for _, ct := range i.workloads[name].Containers() {
			image, _ := ct["image"].(string)
			if !strings.Contains(image, "argocd") {
				continue
			}
			_, _, ref := adapters.ImageRef(image)
			// A digest pin carries no version; treating "sha256" as one would
			// compare as 0.0.0 and fail the floor for no reason.
			if ref == "" || ref == "latest" || strings.HasPrefix(ref, "sha256:") {
				continue
			}
			return strings.TrimPrefix(ref, "v"), "image " + image
		}
	}
	return "", ""
}

// controllerServiceAccount is the identity the sync actually runs as. FRD-020
// R4: when it cannot be resolved the check SKIPs rather than guessing, because
// a SubjectAccessReview for the wrong subject answers a different question.
func (i argocdInstall) controllerServiceAccount() string {
	o := i.find("application-controller")
	if o == nil {
		return ""
	}
	ps := o.PodSpec()
	if ps == nil {
		return ""
	}
	if sa, ok := ps["serviceAccountName"].(string); ok && sa != "" && sa != "default" {
		return sa
	}
	return ""
}

// argocdReplicas reads readiness from whichever status field the kind uses: the
// application-controller is a StatefulSet in the upstream chart, the other two
// are Deployments.
func argocdReplicas(o adapters.Object) (ready, desired int) {
	if o.Kind() == "StatefulSet" {
		ready = argocdInt(o.Dig("status", "readyReplicas"))
	} else {
		ready = argocdInt(o.Dig("status", "availableReplicas"))
	}
	desired = 1
	if v := o.Dig("spec", "replicas"); v != nil {
		desired = argocdInt(v)
	}
	return ready, desired
}

func argocdInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

func argocdHasInitContainer(o adapters.Object, name string) bool {
	ps := o.PodSpec()
	if ps == nil {
		return false
	}
	list, ok := ps["initContainers"].([]any)
	if !ok {
		return false
	}
	for _, raw := range list {
		if cm, ok := raw.(map[string]any); ok {
			if n, _ := cm["name"].(string); n == name {
				return true
			}
		}
	}
	return false
}

// argocdSecretField reads one field of a Secret. A Secret read back from the API
// carries base64 in data; a fixture may carry plaintext in stringData, so both
// are accepted. Only non-secret fields are ever passed in here.
func argocdSecretField(o adapters.Object, key string) string {
	if v := o.DigString("stringData", key); v != "" {
		return v
	}
	enc := o.DigString("data", key)
	if enc == "" {
		return ""
	}
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(dec))
}

// argocdRepoHost extracts the registry host from an ArgoCD repository URL. OCI
// repository Secrets carry a bare "registry.bud.studio/charts" with no scheme,
// which url.Parse reads as a path rather than a host.
func argocdRepoHost(repoURL string) string {
	s := strings.TrimSpace(repoURL)
	for _, scheme := range []string{"oci://", "https://", "http://"} {
		s = strings.TrimPrefix(s, scheme)
	}
	host, _, _ := strings.Cut(s, "/")
	host, _, _ = strings.Cut(host, ":")
	return host
}

// argocdRepoTransport classifies a git repoURL the way ArgoCD's repo-server
// does. The scp-like "git@host:org/repo" form is SSH too, and it is the form
// most likely to be typed by hand.
func argocdRepoTransport(repo string) (host string, port int, transport string) {
	switch {
	case strings.HasPrefix(repo, "ssh://"):
		u, err := url.Parse(repo)
		if err != nil || u.Hostname() == "" {
			return "", 0, ""
		}
		port = 22
		if p := u.Port(); p != "" {
			fmt.Sscanf(p, "%d", &port)
		}
		return u.Hostname(), port, "ssh"
	case strings.HasPrefix(repo, "https://"), strings.HasPrefix(repo, "http://"):
		u, err := url.Parse(repo)
		if err != nil || u.Hostname() == "" {
			return "", 0, ""
		}
		return u.Hostname(), 0, "http"
	case strings.Contains(repo, "@") && strings.Contains(repo, ":") && !strings.Contains(repo, "://"):
		_, rest, _ := strings.Cut(repo, "@")
		host, _, _ = strings.Cut(rest, ":")
		if host == "" {
			return "", 0, ""
		}
		return host, 22, "ssh"
	}
	return "", 0, ""
}

// argocdRegistryCredential finds the credential for a registry host, preferring
// an explicit --registry-credentials entry over the intake answers.
func argocdRegistryCredential(c *engine.Ctx, host string) *adapters.Credential {
	if cred, ok := c.Opts.RegistryCreds[host]; ok && cred.Username != "" {
		return &cred
	}
	if c.Answers.RegistryUser != "" && host == argocdChartRegistry {
		return &adapters.Credential{Username: c.Answers.RegistryUser, Password: c.Answers.RegistryPass}
	}
	return nil
}

// argocdTargetChartVersion is the version the operator is about to install,
// read from the chart they pointed budctl at. There is no --chart-version flag,
// and inventing a version would manufacture a false BLOCK, so an unknown
// version bounds the result instead of failing it.
func argocdTargetChartVersion(c *engine.Ctx) string {
	if c.Helm == nil || c.Opts.ChartDir == "" {
		return ""
	}
	ch, err := c.Helm.LoadChart(c.Opts.ChartDir)
	if err != nil || ch == nil || ch.Metadata == nil {
		return ""
	}
	return ch.Metadata.Version
}

func argocdHTTPSummary(r adapters.HTTPResult) string {
	if !r.Reachable {
		return "unreachable: " + r.Err
	}
	return fmt.Sprintf("HTTP %d in %s", r.Status, r.Latency.Round(time.Millisecond))
}

func argocdTCPSummary(ok bool, why string) string {
	if ok {
		return "connected"
	}
	return "refused: " + why
}

// argocdParseEgress splits the probe's "<url> <code>" lines into reachable and
// not. Anything that is not a 2xx/3xx is a failure: the initContainer wgets the
// file itself, so a 403 from a CDN is as fatal as a timeout.
func argocdParseEgress(logs string) (ok, bad []string) {
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, code, found := strings.Cut(line, " ")
		if !found || !strings.HasPrefix(u, "http") {
			continue
		}
		code = strings.TrimSpace(code)
		if len(code) == 3 && (code[0] == '2' || code[0] == '3') {
			ok = append(ok, u+" -> HTTP "+code)
			continue
		}
		bad = append(bad, u+" -> "+code)
	}
	return ok, bad
}

// argocdHostsOf names the hosts behind failed URLs, because the remedy is an
// allowlist entry per host rather than per URL.
func argocdHostsOf(lines []string) []string {
	hosts := []string{}
	for _, l := range lines {
		u, _, _ := strings.Cut(l, " ")
		if parsed, err := url.Parse(u); err == nil && parsed.Hostname() != "" {
			hosts = append(hosts, parsed.Hostname())
		}
	}
	return Sorted(hosts)
}
