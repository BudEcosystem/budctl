package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
)

// The config group answers a different question from every other group: not
// "can this cluster host Bud" but "will the values the operator is about to
// hand ArgoCD actually install". It is inert without --values, because
// rendering the chart's own defaults would test this repository rather than
// the operator's intent (FRD-020 §5.11).
//
// Two things make the group worth having. The chart carries hard `fail` guards
// that only fire at render time, which under GitOps means at sync time in a
// cluster nobody is watching; and several credentials have no guard at all —
// a blank RSA key renders an empty Secret and fails hours later, in a service
// log, as a decryption error.

// The ApplicationSets install the umbrella chart as release "bud" in namespace
// "bud" (infra/appsets/*.yaml). Every resource name, and every fullname-derived
// reference between services, is derived from those two strings, so rendering
// under anything else would validate a manifest that will never be applied.
const (
	cfgRelease   = "bud"
	cfgNamespace = "bud"
)

func init() {
	engine.Register(&engine.Check{
		ID: "config.render", Group: "config", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.render")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			if c.Opts.ChartDir == "" {
				return ch.Skip("no --chart: there is no chart to render the values against")
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Fail(
					"the supplied values cannot be parsed, so nothing downstream can be judged: "+err.Error(),
					"fix the YAML in the file named above and re-run")
			}
			if len(vs.Cipher) > 0 {
				return ch.Skip(cfgCipherReason(vs))
			}
			chart, err := c.Helm.LoadChart(c.Opts.ChartDir)
			if err != nil {
				return ch.Fail(
					"the chart at "+c.Opts.ChartDir+" cannot be loaded, so the values were never rendered: "+err.Error(),
					"point --chart at infra/charts/bud (or a packaged .tgz) and run `helm dependency update` there first")
			}

			res, rerr := c.Helm.Render(chart, vs.User, cfgRelease, cfgNamespace, c.Platform.Version)
			if rerr != nil {
				raw := rerr.Error()
				ev := engine.Evidence{
					What:   fmt.Sprintf("helm template %s %s %s", cfgRelease, c.Opts.ChartDir, cfgFlagEcho(c)),
					Output: raw,
				}
				// The chart's own `fail`/`required` string is the only actionable
				// part of a Helm template error; the rest is template path and
				// line noise. Both are reported: the guard leads, the raw error
				// is kept verbatim so the operator can grep the chart for it.
				if guard := cfgGuardText(raw); guard != "" {
					return ch.Fail(
						"the chart refuses to render with these values, so the ApplicationSet sync fails before one object is applied: "+cfgFirstSentence(guard),
						"supply the value the chart names, in the SOPS-encrypted secrets file the environment loads (infra/values/bud/secrets.<env>.yaml), then re-run",
						guard).WithEvidence(ev)
				}
				return ch.Fail(
					"the chart does not template with these values, so the ApplicationSet sync fails before one object is applied",
					"read the template error below; it names the template and the value that produced it").
					WithEvidence(ev)
			}

			// Everything that inspects what will actually be installed — the
			// image inventory, component resource requests, ingress hosts —
			// reads these two keys rather than re-rendering.
			c.Set(engine.KeyRenderedObjects, res.Objects)
			images := adapters.Images(res.Objects)
			c.Set(engine.KeyImages, images)

			kinds := map[string]int{}
			for _, o := range res.Objects {
				kinds[o.Kind()]++
			}
			detail := []string{
				fmt.Sprintf("%d %s, %d distinct %s",
					len(res.Objects), Plural(len(res.Objects), "object", "objects"),
					len(images), Plural(len(images), "image", "images")),
				"rendered as release " + cfgRelease + " in namespace " + cfgNamespace + ", matching infra/appsets",
				cfgKindSummary(kinds),
			}
			if !vs.Defaults {
				detail = append(detail, "the chart's own values.yaml was layered in by Helm, not by budctl")
			}
			return ch.Pass("the chart templates cleanly with the supplied values", detail...).
				Bounds("client-side templating only: an object the API server rejects, or a webhook that denies the apply, is caught by config.dry-run and not here")
		},
	})

	engine.Register(&engine.Check{
		ID: "config.dry-run", Group: "config", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.dry-run")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			if c.Opts.ChartDir == "" {
				return ch.Skip("no --chart: there is no chart to dry-run")
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: a server-side dry run is validated by the API server, and there is none to ask")
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Skip("the supplied values cannot be parsed (config.render carries the detail)")
			}
			if len(vs.Cipher) > 0 {
				return ch.Skip(cfgCipherReason(vs))
			}
			chart, err := c.Helm.LoadChart(c.Opts.ChartDir)
			if err != nil {
				return ch.Skip("the chart at " + c.Opts.ChartDir + " cannot be loaded (config.render carries the detail)")
			}

			res, rerr := c.Helm.RenderServerSide(ctx, c.Kube, chart, vs.User, cfgRelease, cfgNamespace)
			if rerr != nil {
				raw := rerr.Error()
				ev := engine.Evidence{
					What:   fmt.Sprintf("helm install --dry-run=server %s %s %s", cfgRelease, c.Opts.ChartDir, cfgFlagEcho(c)),
					Output: raw,
				}
				switch cfgDryRunFailure(raw) {
				case cfgDryTemplate:
					// The template never reached the API server, so this check
					// has no independent finding to report — config.render owns it.
					return ch.Skip("the chart does not template with these values, so the API server was never asked (config.render carries the detail)")
				case cfgDryNoNamespace:
					return ch.Skip("namespace " + cfgNamespace + " does not exist yet, so the API server cannot validate namespaced objects; create it (kubectl create ns " + cfgNamespace + ") and re-run")
				case cfgDryForbidden:
					return ch.Skip("this kubeconfig may not create objects here, so the dry run was refused rather than rejected: " + cfgFirstSentence(raw))
				case cfgDryConflict:
					return ch.Fail(
						"an object in the chart already exists and is not owned by a Helm release, so the sync will fail at apply time even though the template is valid: "+cfgFirstSentence(raw),
						"delete the conflicting object, or label and annotate it for adoption (app.kubernetes.io/managed-by=Helm, meta.helm.sh/release-name="+cfgRelease+", meta.helm.sh/release-namespace="+cfgNamespace+")").
						WithEvidence(ev)
				case cfgDryWebhook:
					return ch.Fail(
						"an admission webhook denies part of this manifest, so the sync will fail at apply time even though the template is valid: "+cfgFirstSentence(raw),
						"the webhook's own message below names the policy; exempt the namespace or adjust the values it objects to").
						WithEvidence(ev)
				default:
					return ch.Fail(
						"the API server rejects this manifest, so the sync will fail at apply time even though the template is valid: "+cfgFirstSentence(raw),
						"read the API server's reason below and fix the object it names").
						WithEvidence(ev)
				}
			}
			return ch.Pass(
				fmt.Sprintf("the API server accepts all %d rendered %s", len(res.Objects), Plural(len(res.Objects), "object", "objects")),
				"validated against "+c.Kube.Host(),
				"release "+cfgRelease+", namespace "+cfgNamespace).
				Bounds("a server-side dry run resolves `lookup`, which ArgoCD's `helm template` does not: a value the chart can read out of an existing Secret passes here and still fails an ArgoCD sync. It also does not prove the objects become Healthy, only that they are admitted")
		},
	})

	engine.Register(&engine.Check{
		ID: "config.required-values", Group: "config", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.required-values")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Skip("the supplied values cannot be parsed: " + err.Error())
			}
			o := adapters.Object(vs.Effective)

			var bad, ciphered, ok []string

			// budevent's credential-vault key. The chart guard has a `lookup`
			// fallback onto an existing in-cluster Secret, which is why this is
			// checked separately from config.render: under ArgoCD the chart is
			// rendered with `helm template`, where `lookup` returns empty and
			// the guard always fires.
			if cfgEnabled(o, true, "microservices", "budevent", "enabled") {
				key := o.DigString("daprExtra", "crypto", "budeventCryptoKey")
				switch {
				case cfgIsCipher(key):
					ciphered = append(ciphered, "daprExtra.crypto.budeventCryptoKey")
				case key == "":
					bad = append(bad, "daprExtra.crypto.budeventCryptoKey is empty — budevent's credential vault has no AES-256 key and the chart fails the render outright")
				case len(key) != 32:
					bad = append(bad, fmt.Sprintf("daprExtra.crypto.budeventCryptoKey is %d bytes, not 32 — the chart fails the render on the length guard", len(key)))
				default:
					ok = append(ok, "daprExtra.crypto.budeventCryptoKey (32 bytes)")
				}
			}

			// The RSA keypair has NO chart guard: a blank value renders an empty
			// Secret, every service starts, and the first attempt to decrypt a
			// stored provider credential fails at runtime. That silence is the
			// reason this check exists at all.
			for _, f := range []struct{ path, cost string }{
				{"privateKey", "no service can decrypt a stored provider credential; the Secret renders empty and nothing fails at sync time"},
				{"publicKey", "no service can encrypt a new provider credential"},
				{"privateKeyPassword", "the private key cannot be opened, so credential decryption fails on every service"},
			} {
				v := o.DigString("microservices", "rsaKeys", f.path)
				switch {
				case cfgIsCipher(v):
					ciphered = append(ciphered, "microservices.rsaKeys."+f.path)
				case strings.TrimSpace(v) == "":
					bad = append(bad, "microservices.rsaKeys."+f.path+" is empty — "+f.cost)
				default:
					ok = append(ok, "microservices.rsaKeys."+f.path)
				}
			}

			// The onboarding token is only required when the feature is on, and
			// the chart's guard says so in as many words.
			if cfgEnabled(o, true, "microservices", "budcluster", "registerDefaultCluster", "enabled") {
				tok := o.DigString("microservices", "budcluster", "registerDefaultCluster", "token")
				switch {
				case cfgIsCipher(tok):
					ciphered = append(ciphered, "microservices.budcluster.registerDefaultCluster.token")
				case tok == "":
					bad = append(bad, "microservices.budcluster.registerDefaultCluster.token is empty while registerDefaultCluster.enabled is true — the chart fails the render, and the cluster the platform runs on is never registered")
				default:
					ok = append(ok, "microservices.budcluster.registerDefaultCluster.token")
				}
			} else {
				ok = append(ok, "registerDefaultCluster is disabled, so its token is not required")
			}

			res := ch.Pass(fmt.Sprintf("all %d values with no safe default are supplied", len(ok)), Sorted(ok)...)
			if len(bad) > 0 {
				res = ch.Fail(
					fmt.Sprintf("%d %s with no safe default %s missing, and the install stops on the first one",
						len(bad), Plural(len(bad), "value", "values"), Plural(len(bad), "is", "are")),
					"generate a stable value for each and set it per-environment in the SOPS-encrypted secrets file (infra/values/bud/secrets.<env>.yaml). These must NOT be re-minted per render: the budevent key is the credential vault's, and rotating it orphans every stored connector credential",
					Sorted(bad)...)
			}
			if len(ciphered) > 0 {
				res = res.With("still SOPS ciphertext, so present but not inspectable: " + strings.Join(Sorted(ciphered), ", ")).
					Bounds("values still held as SOPS ciphertext were confirmed present but not measured — the chart's 32-byte length guard is judged against the decrypted value, not this one")
			}
			return res
		},
	})

	engine.Register(&engine.Check{
		ID: "config.fail-closed", Group: "config", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.fail-closed")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Skip("the supplied values cannot be parsed: " + err.Error())
			}
			o := adapters.Object(vs.Effective)

			var blank, set []string
			for _, f := range cfgFailClosed {
				v := o.DigString(f.path...)
				name := strings.Join(f.path, ".")
				if strings.TrimSpace(v) == "" {
					blank = append(blank, name+" is blank — "+f.cost)
					continue
				}
				set = append(set, name)
			}
			if len(blank) == 0 {
				return ch.Pass("every fail-closed secret is provisioned", Sorted(set)...).
					Bounds("a non-empty token is not proof it matches the one the consuming service was configured with; only exercising the feature shows that")
			}
			// Blank is the chart's deliberate default and the install still
			// succeeds — which is exactly why it needs naming. The value used to
			// ship as a placeholder, and that is how every environment ended up
			// guarded by a token published in this repository.
			return ch.Fail(
				fmt.Sprintf("%d %s blank, so %s silently disabled while the install still reports success",
					len(blank), Plural(len(blank), "secret is", "secrets are"),
					Plural(len(blank), "one feature is", "those features are")),
				"mint a random value for each in the SOPS-encrypted secrets file the environment loads, or accept that the named feature stays off — blank is a valid choice, but it must be a choice",
				Sorted(blank)...).
				With(cfgSetLine(set))
		},
	})

	engine.Register(&engine.Check{
		ID: "config.public-defaults", Group: "config", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.public-defaults")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Skip("the supplied values cannot be parsed: " + err.Error())
			}
			o := adapters.Object(vs.Effective)

			var hit, ciphered []string
			var ev []engine.Evidence
			for _, d := range cfgPublicDefaults {
				name := strings.Join(d.path, ".")
				v := o.DigString(d.path...)
				if cfgIsCipher(v) {
					ciphered = append(ciphered, name)
					continue
				}
				if v != d.value {
					continue
				}
				hit = append(hit, name+" — still the published value; it controls "+d.controls)
				ev = append(ev, engine.Evidence{
					What:   name + " in the merged values",
					Output: cfgElide(v) + "  (byte-identical to infra/charts/bud/values.yaml, a public git repository)",
				})
			}
			if len(hit) == 0 {
				res := ch.Pass(fmt.Sprintf("none of the %d credentials published in this repository is still in use", len(cfgPublicDefaults))).
					Bounds("an overridden credential is not necessarily a strong or unique one, and this does not detect a value reused from another environment")
				if len(ciphered) > 0 {
					res = res.With("still SOPS ciphertext, so not compared: " + strings.Join(Sorted(ciphered), ", "))
				}
				return res
			}
			res := ch.Fail(
				fmt.Sprintf("%d %s still at the value published in this public repository, so anyone with the git URL holds %s",
					len(hit), Plural(len(hit), "credential is", "credentials are"), Plural(len(hit), "it", "them")),
				"generate a fresh value for each in the SOPS-encrypted secrets file the environment loads (infra/values/bud/secrets.<env>.yaml), and rotate anything already issued under the old one",
				Sorted(hit)...).
				WithEvidence(ev...)
			if len(ciphered) > 0 {
				res = res.With("still SOPS ciphertext, so not compared: " + strings.Join(Sorted(ciphered), ", "))
			}
			return res
		},
	})

	engine.Register(&engine.Check{
		ID: "config.placeholders", Group: "config", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.placeholders")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Skip("the supplied values cannot be parsed: " + err.Error())
			}

			// Exhaustive rather than a fixed key list: the placeholders that
			// matter are buried in microservices.global.env and in the per-host
			// registries map, and an enumerated list would miss the next one
			// somebody adds to values.yaml.
			var registry, other []string
			var ev []engine.Evidence
			cfgWalk(vs.Effective, "", func(path, value string) {
				marker := cfgPlaceholderIn(value)
				if marker == "" {
					return
				}
				line := path + " = " + value
				if strings.HasPrefix(path, "registries.") {
					registry = append(registry, line)
				} else {
					other = append(other, line)
				}
				ev = append(ev, engine.Evidence{What: path, Output: value})
			})

			if len(registry) == 0 && len(other) == 0 {
				return ch.Pass("no placeholder values remain").
					Bounds("only the two markers this repository ships (<change_me>, getmefrombud) are searched; a stand-in the operator invented is indistinguishable from a real credential")
			}
			if len(registry) > 0 {
				// A placeholder registry login is a blocker on its own: the pull
				// secret renders, every first-party image 401s, and each pod sits
				// in ImagePullBackOff rather than reporting a credential problem.
				all := append(Sorted(registry), Sorted(other)...)
				return ch.Fail(
					fmt.Sprintf("the registry login is still a placeholder, so every first-party image fails to pull and every pod stays in ImagePullBackOff (%d placeholder %s in total)",
						len(registry)+len(other), Plural(len(registry)+len(other), "value", "values")),
					"put the real registry.bud.studio credentials in the SOPS-encrypted secrets file the environment loads, and replace every other placeholder below",
					all...).
					WithEvidence(ev...)
			}
			return ch.FailAs(engine.Risk,
				fmt.Sprintf("%d placeholder %s reach the install, so the feature behind each is configured with a string that is not a credential",
					len(other), Plural(len(other), "value", "values")),
				"replace each with a real value, or remove the key so the feature is plainly off rather than misconfigured",
				Sorted(other)...).
				WithEvidence(ev...)
		},
	})

	engine.Register(&engine.Check{
		ID: "config.valkey-indexes", Group: "config", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("config.valkey-indexes")
			if why := cfgInactive(c); why != "" {
				return ch.Skip(why)
			}
			vs, err := cfgLoadValues(c)
			if err != nil {
				return ch.Skip("the supplied values cannot be parsed: " + err.Error())
			}
			raw, ok := adapters.Object(vs.Effective).Dig("externalServices", "valkey", "databases").(map[string]any)
			if !ok || len(raw) == 0 {
				return ch.Skip("externalServices.valkey.databases is absent from the merged values, so there are no index assignments to compare")
			}

			// The collision that matters is never visible in one file. An
			// environment file that renumbers only the uses it cares about
			// leaves every other consumer at the chart default, and two of them
			// land on one database — where they share a keyspace and quietly
			// evict each other.
			byIndex := map[int][]string{}
			var unparsed, outOfRange []string
			for name, v := range raw {
				idx, ok := cfgIndex(v)
				if !ok {
					unparsed = append(unparsed, fmt.Sprintf("%s = %v (not an integer index)", name, v))
					continue
				}
				byIndex[idx] = append(byIndex[idx], name)
				if idx < 0 || idx > 15 {
					outOfRange = append(outOfRange, fmt.Sprintf("%s = %d", name, idx))
				}
			}

			var clashes []string
			for idx, names := range byIndex {
				if len(names) < 2 {
					continue
				}
				clashes = append(clashes, fmt.Sprintf("index %d is shared by %s", idx, strings.Join(Sorted(names), " and ")))
			}
			ev := engine.Evidence{What: "externalServices.valkey.databases (chart defaults with every --values file layered on top)", Output: cfgIndexTable(byIndex)}

			if len(clashes) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d Valkey %s two logical uses, so those consumers share one keyspace and overwrite each other's keys",
						len(clashes), Plural(len(clashes), "index carries", "indexes each carry")),
					"give every entry in externalServices.valkey.databases its own index, in the same file. Overriding only some of them leaves the rest at the chart default, which is how the collision appears",
					Sorted(clashes)...).
					WithEvidence(ev)
			}
			if len(outOfRange) > 0 {
				// Valkey ships 16 databases (0-15); SELECT on anything higher is
				// refused at connect time. Reported as a risk rather than a
				// blocker because a customer's managed Valkey may be configured
				// with more.
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("%d Valkey %s outside the default 0-15 range, so SELECT is refused at connect time unless the server was configured with more databases",
						len(outOfRange), Plural(len(outOfRange), "index is", "indexes are")),
					"renumber these into 0-15, or confirm the Valkey deployment sets `databases` higher",
					Sorted(outOfRange)...).
					WithEvidence(ev)
			}
			res := ch.Pass(
				fmt.Sprintf("all %d Valkey logical uses are on distinct indexes", len(byIndex)),
				cfgIndexTable(byIndex)).
				WithEvidence(ev)
			if len(unparsed) > 0 {
				res = res.With("not comparable: " + strings.Join(Sorted(unparsed), ", "))
			}
			if !vs.Defaults {
				res = res.Bounds("the chart's own values.yaml could not be read, so an index left at a chart default was not compared against the overrides — the partial-override collision this check exists for would be invisible")
			}
			return res
		},
	})
}

// cfgFailClosed are the secrets the chart deliberately ships blank. Blank is
// safe: the feature fails closed instead of shipping a credential published in
// a public repository. It is also silent, so each is named with what it costs.
var cfgFailClosed = []struct {
	path []string
	cost string
}{
	{[]string{"realtimeGrantSecret"},
		"live workflow progress stops: budapp signs the HS256 room grant and budnotify verifies it, so with no key no viewer is admitted to a room and every deployment, run and simulation progress view stays empty"},
	{[]string{"widgetInternalToken"},
		"the embedded chat widget (FRD-015) cannot start a session: budapp answers 403 \"Widget sessions are not configured\" on POST /playground/initialize-widget-session"},
	{[]string{"resolveInternalToken"},
		"budgateway's pre-authentication proxy-cache resolve path (FRD-016 WS10) is off: budapp answers 403 and an auth miss stays a plain 401, so nothing is served from the proxy cache on that path"},
}

// cfgPublicDefaults are credentials whose values.yaml value is published in a
// public git repository. Each names what it controls, because "rotate this" is
// weighed very differently for a Novu admin login and for the token that gates
// budapp's credential minter.
var cfgPublicDefaults = []struct {
	path     []string
	value    string
	controls string
}{
	{[]string{"appApiToken"}, "PRAJKQIzAsDNvHIrYALkTiwm5t6VNmnW",
		"every /internal/* route on budapp, including the full-project credential minter"},
	{[]string{"microservices", "budcache", "apiKey"}, "bud_budcache_dev",
		"every BudCache lookup and store budgateway performs"},
	{[]string{"microservices", "budcache", "adminKey"}, "bud_budcache_dev_admin",
		"BudCacheAdmin/EraseTenant — the GDPR purge budapp runs before deleting a project"},
	{[]string{"novu", "store", "encryption-key"}, "bud-gUXY7j0k14yinhZm4w!eSqBGlexz",
		"the key Novu encrypts stored provider credentials at rest with"},
	{[]string{"microservices", "rsaKeys", "privateKeyPassword"}, "ccHGQlmO8HcUqOjU2kUh4PFmoSuxzY0Z",
		"the passphrase on the RSA key every service decrypts stored provider credentials with"},
	{[]string{"novuExtra", "password"}, "fomah4OiKaesh6azChoh7uoM",
		"the Novu admin account"},
	{[]string{"microservices", "global", "env", "PASSWORD_SALT"}, "pL4eVOkzsLEKc25T69UCvjXvK0BxgghwzSpEE9wBbUMNezEODv0s7tWcrhEeQyCh",
		"the salt every stored password hash is derived with — a shared salt makes one rainbow table work against every install"},
	{[]string{"microservices", "global", "env", "SUPER_USER_PASSWORD"}, "root@example.com",
		"the first administrator login, which owns every project"},
}

// cfgValueSet separates the two value trees a check may need. User is exactly
// what --values/--secrets supply and is what Helm must be handed, because Helm
// coalesces the chart's defaults underneath itself and a pre-merged tree would
// defeat null-overrides. Effective is what the install will actually see, and
// is the only tree in which a partial override is visible.
type cfgValueSet struct {
	User      map[string]any
	Effective map[string]any
	Defaults  bool     // the chart's values.yaml was layered underneath
	Cipher    []string // dotted paths still holding SOPS ciphertext
}

// cfgInactive returns the reason the whole group has nothing to judge. Without
// --values there are no operator values, and rendering the chart's defaults
// would only re-test this repository.
func cfgInactive(c *engine.Ctx) string {
	if len(c.Opts.ValuesFiles) == 0 {
		return "no --values: this group judges the values the operator will hand ArgoCD, and none were supplied"
	}
	if c.Helm == nil {
		return "no Helm renderer on this run, so the values cannot be merged"
	}
	return ""
}

// cfgFiles lists the values files in the order ArgoCD layers them: the
// SOPS-encrypted secrets file first, then each --values file, exactly as
// infra/appsets/*.yaml orders them. Reversing it would judge a value the
// install never sees.
// cfgFiles delegates to the shared definition so the config group and every
// other values-reading group can never disagree about what the install loads.
func cfgFiles(c *engine.Ctx) []string { return EffectiveValuesFiles(c) }

// cfgLoadValues builds both trees. The chart's own values.yaml is read as a
// plain file rather than through LoadChart: the content checks need only the
// defaults, and loading the umbrella chart with its dependencies for each of
// five checks would cost far more than one file read.
func cfgLoadValues(c *engine.Ctx) (*cfgValueSet, error) {
	user, err := c.Helm.MergeValues(cfgFiles(c))
	if err != nil {
		return nil, err
	}
	vs := &cfgValueSet{User: user, Effective: user}
	if c.Opts.ChartDir != "" {
		if base, berr := c.Helm.MergeValues([]string{filepath.Join(c.Opts.ChartDir, "values.yaml")}); berr == nil {
			vs.Effective = cfgMerge(base, user)
			vs.Defaults = true
		}
	}
	cfgWalk(user, "", func(path, value string) {
		if cfgIsCipher(value) {
			vs.Cipher = append(vs.Cipher, path)
		}
	})
	vs.Cipher = Sorted(vs.Cipher)
	return vs, nil
}

// cfgCipherReason explains why a check refuses to judge ciphertext. A SOPS file
// is valid YAML, so it merges without complaint and every value becomes an
// ENC[...] string — which would fail the chart's 32-byte guard, and pass every
// "is it still the published default" comparison, for reasons that have nothing
// to do with the cluster.
func cfgCipherReason(vs *cfgValueSet) string {
	return fmt.Sprintf("the supplied values are still SOPS ciphertext (%d %s, e.g. %s): decrypt them first, or the chart's guards fire on base64 rather than on the real credentials",
		len(vs.Cipher), Plural(len(vs.Cipher), "value", "values"), vs.Cipher[0])
}

func cfgIsCipher(v string) bool { return strings.HasPrefix(v, "ENC[") }

// cfgMerge layers over on top of base the way Helm coalesces a values file over
// the chart's defaults: maps merge key by key, everything else replaces.
func cfgMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if vm, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = cfgMerge(bm, vm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// cfgWalk visits every string leaf as a dotted path, keys sorted so two runs
// over the same values produce the same report.
func cfgWalk(v any, path string, fn func(path, value string)) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			cfgWalk(t[k], child, fn)
		}
	case []any:
		for i, e := range t {
			cfgWalk(e, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	case string:
		fn(path, t)
	}
}

// cfgPlaceholderIn returns the marker a value carries, or "". Both markers are
// matched as substrings: values.yaml ships them as "<change_me>", as a bare
// "getmefrombud", and once as "change_me_4HCz..." — an enumerated list of exact
// strings would miss the third.
func cfgPlaceholderIn(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range []string{"change_me", "getmefrombud"} {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	return ""
}

// cfgEnabled reads a feature flag, falling back to the chart's default when the
// key is absent — which happens when --chart was not given and the defaults
// could not be layered underneath.
func cfgEnabled(o adapters.Object, fallback bool, path ...string) bool {
	switch v := o.Dig(path...).(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return fallback
	}
}

// cfgIndex reads a Valkey database index. sigs.k8s.io/yaml decodes through
// JSON, so an integer in a values file arrives as float64.
func cfgIndex(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		if t != float64(int(t)) {
			return 0, false
		}
		return int(t), true
	case string:
		n := ParseQuantity(strings.TrimSpace(t))
		if n == 0 && strings.TrimSpace(t) != "0" {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

func cfgIndexTable(byIndex map[int][]string) string {
	idxs := make([]int, 0, len(byIndex))
	for i := range byIndex {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	parts := make([]string, 0, len(idxs))
	for _, i := range idxs {
		parts = append(parts, fmt.Sprintf("%d=%s", i, strings.Join(Sorted(byIndex[i]), "+")))
	}
	return strings.Join(parts, " ")
}

// cfgGuardText pulls the chart's own message out of Helm's wrapped template
// error. `fail` and `required` are how the chart states a prerequisite, and
// that sentence is the only actionable part of the error Helm returns.
func cfgGuardText(err string) string {
	for _, marker := range []string{"error calling fail: ", "error calling required: "} {
		if i := strings.LastIndex(err, marker); i >= 0 {
			return strings.TrimSpace(err[i+len(marker):])
		}
	}
	return ""
}

// cfgFirstSentence keeps a summary to one line while the full text stays in
// detail and evidence; the chart's guards run to several sentences of remedy.
func cfgFirstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i]
	}
	if len(s) > 220 {
		return s[:217] + "..."
	}
	return s
}

type cfgDryRunClass int

const (
	cfgDryOther cfgDryRunClass = iota
	cfgDryTemplate
	cfgDryNoNamespace
	cfgDryForbidden
	cfgDryConflict
	cfgDryWebhook
)

// cfgDryRunFailure separates "the API server rejected this manifest" — the one
// finding this check owns — from the three ways a dry run fails without
// answering the question. Reporting a refused dry run as a blocker would be a
// lie about the cluster.
func cfgDryRunFailure(err string) cfgDryRunClass {
	lower := strings.ToLower(err)
	switch {
	case cfgGuardText(err) != "":
		return cfgDryTemplate
	case strings.Contains(lower, "namespaces \""+cfgNamespace+"\" not found") || strings.Contains(lower, "namespace not found"):
		return cfgDryNoNamespace
	case strings.Contains(lower, "is forbidden") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "cannot create"):
		return cfgDryForbidden
	case strings.Contains(lower, "already exists") || strings.Contains(lower, "cannot be imported") || strings.Contains(lower, "invalid ownership metadata"):
		return cfgDryConflict
	case strings.Contains(lower, "admission webhook") || strings.Contains(lower, "denied the request"):
		return cfgDryWebhook
	// Last, and only as a prefix: a Helm template error opens with
	// "template: bud/templates/...", while an API server message that merely
	// mentions a pod template must not be mistaken for one.
	case strings.HasPrefix(lower, "template:"):
		return cfgDryTemplate
	}
	return cfgDryOther
}

// cfgFlagEcho reproduces the -f arguments so the operator can re-run the same
// render by hand from the evidence line.
func cfgFlagEcho(c *engine.Ctx) string {
	parts := make([]string, 0, len(c.Opts.ValuesFiles)+1)
	for _, f := range cfgFiles(c) {
		parts = append(parts, "-f "+f)
	}
	return strings.Join(parts, " ")
}

func cfgKindSummary(kinds map[string]int) string {
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if kinds[names[i]] != kinds[names[j]] {
			return kinds[names[i]] > kinds[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > 6 {
		names = names[:6]
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%d %s", kinds[n], n))
	}
	return strings.Join(parts, ", ")
}

func cfgSetLine(set []string) string {
	if len(set) == 0 {
		return "none of the three is provisioned"
	}
	return "provisioned: " + strings.Join(Sorted(set), ", ")
}

// cfgElide shortens a credential for display. The values compared here are
// already public, but a report is pasted into tickets and chat, and a full
// credential in a transcript is a habit worth not forming.
func cfgElide(v string) string {
	if len(v) <= 8 {
		return v
	}
	return v[:8] + "..." + fmt.Sprintf("(%d chars)", len(v))
}
