package components

import (
	"strings"
	"testing"

	"github.com/BudEcosystem/budctl/install/spec"
)

func validSpec() spec.Spec {
	s := spec.Defaults()
	s.Environment = "production"
	s.TargetRepo = "https://github.com/example/bud-config.git"
	s.Domain = "bud.example.com"
	s.IngressClass = "nginx"
	s.StorageClass = "standard"
	s.TLS = spec.TLSSelfSigned
	s.RegistryUser = "robot"
	s.RegistryPassword = "registry-secret"
	s.AdminEmail = "admin@example.com"
	s.Normalize()
	return s
}

func TestTableIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	waves := map[int]string{}
	for _, c := range All {
		if seen[c.Name] {
			t.Errorf("component %s is listed twice", c.Name)
		}
		seen[c.Name] = true
		if other, dup := waves[c.SyncWave]; dup {
			t.Errorf("%s and %s share sync wave %d, so their order is undefined", c.Name, other, c.SyncWave)
		}
		waves[c.SyncWave] = c.Name
		helm := c.Source.Chart != ""
		git := c.Source.GitPath != ""
		if helm == git {
			t.Errorf("%s must have exactly one source, Helm chart or Git path", c.Name)
		}
		if helm && (c.Source.RepoURL == "" || c.Source.Version == "") {
			t.Errorf("%s has a chart without a repository or version", c.Name)
		}
		if _, err := c.Base(validSpec()); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

// Every shared layer embedded in the binary must be referenced by some
// component under some Spec, or it is dead weight that reads as if it applied.
func TestEveryLayerIsUsed(t *testing.T) {
	layers, err := Layers()
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, tls := range []spec.TLSMode{spec.TLSACMEDNS01, spec.TLSACMEHTTP01, spec.TLSSelfSigned, spec.TLSInternalCA, spec.TLSExternal} {
		s := validSpec()
		s.TLS = tls
		for _, c := range All {
			if c.BaseFiles == nil {
				continue
			}
			for _, f := range c.BaseFiles(s) {
				used["values/"+c.Name+"/"+f] = true
			}
		}
	}
	for path := range layers {
		if !used[path] {
			t.Errorf("%s is embedded but no component reads it", path)
		}
	}
}

func TestBootstrapSyncOrder(t *testing.T) {
	s := validSpec()
	s.BudStudio = true
	var names []string
	for _, c := range BySyncWave(Enabled(s)) {
		names = append(names, c.Name)
	}
	want := "argocd cert-manager kyverno dapr kafka mongodb clickhouse postgres seaweedfs valkey keycloak opensandbox bud bud-studio"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("sync order:\n got %s\nwant %s", got, want)
	}
}

func TestEnabledFollowsTLSAndStudio(t *testing.T) {
	names := func(s spec.Spec) string {
		var out []string
		for _, c := range Enabled(s) {
			out = append(out, c.Name)
		}
		return strings.Join(out, " ")
	}
	s := validSpec()
	s.TLS = spec.TLSExternal
	if got := names(s); strings.Contains(got, "cert-manager") || strings.Contains(got, "kyverno") || strings.Contains(got, "bud-studio") {
		t.Fatalf("external TLS without Studio enabled %s", got)
	}
	s.TLS = spec.TLSInternalCA
	s.BudStudio = true
	if got := names(s); !strings.Contains(got, "cert-manager") || !strings.Contains(got, "kyverno") || !strings.Contains(got, "bud-studio") {
		t.Fatalf("internal CA with Studio enabled only %s", got)
	}
}

func TestMergeKeepsNullAndReplacesLists(t *testing.T) {
	base := map[string]any{"a": map[string]any{"keep": 1, "drop": 2}, "list": []any{1, 2}}
	over := map[string]any{"a": map[string]any{"drop": nil}, "list": []any{3}}
	got := Merge(base, over)
	a := got["a"].(map[string]any)
	if a["keep"] != 1 {
		t.Fatal("a key absent from the overlay was lost")
	}
	if v, ok := a["drop"]; !ok || v != nil {
		t.Fatal("an explicit null must survive the merge so Helm removes the chart default")
	}
	if l := got["list"].([]any); len(l) != 1 || l[0] != 3 {
		t.Fatalf("lists must be replaced, not merged: %v", l)
	}
	if base["a"].(map[string]any)["drop"] != 2 {
		t.Fatal("Merge modified its input")
	}
}

func TestBudValuesEnableOnlyDefaultOffServices(t *testing.T) {
	services := budValues(validSpec())["microservices"].(map[string]any)
	for _, service := range []string{"budeval", "budcodeinterpreter"} {
		if services[service].(map[string]any)["enabled"] != true {
			t.Errorf("chart-default-off service %s was not enabled", service)
		}
	}
	for _, service := range []string{"askbud", "budadmin", "budcustomer", "buddoc", "budpipeline", "budsentinel", "semanticRouter"} {
		if _, present := services[service]; present {
			t.Errorf("chart-default-on service %s was redundantly overridden", service)
		}
	}
	if _, present := services["budapp"].(map[string]any)["enabled"]; present {
		t.Fatal("budapp enabled flag was redundantly overridden")
	}
}

func TestBudValuesIncludeReferenceRedirectFlow(t *testing.T) {
	services := budValues(validSpec())["microservices"].(map[string]any)
	clients := services["budapp"].(map[string]any)["redirectFlow"].(map[string]any)["clientsByHost"].(map[string]any)
	for _, name := range []string{"budadmin", "budcustomer", "budplayground"} {
		client := clients[name].(map[string]any)
		hosts := client["hosts"].([]any)
		origins := client["allowedReturnUrlOrigins"].([]any)
		if len(hosts) != 1 || len(origins) != 1 || !strings.Contains(hosts[0].(string), "bud.ingress.hosts."+name) || !strings.Contains(origins[0].(string), "bud.ingress.url."+name) {
			t.Fatalf("redirect flow for %s does not match the infra reference: %#v", name, client)
		}
	}
}

func TestOpenSandboxAndCodeInterpreterShareAPIKey(t *testing.T) {
	s := validSpec()
	generated := spec.GeneratedSecrets{Values: map[string]string{"opensandbox-api": "shared-key"}}
	interpreter := budSecrets(s, generated)["microservices"].(map[string]any)["budcodeinterpreter"].(map[string]any)
	if interpreter["env"].(map[string]any)["SECRETS_OPENSANDBOX_API_KEY"] != "shared-key" {
		t.Fatal("Bud code interpreter does not receive the OpenSandbox API key")
	}
	server := openSandboxSecrets(s, generated)["opensandbox"].(map[string]any)["opensandbox-server"].(map[string]any)["server"].(map[string]any)
	if server["env"].([]any)[0].(map[string]any)["value"] != "shared-key" {
		t.Fatal("OpenSandbox server does not receive the shared API key")
	}
}

func TestArgoCDReceivesPrivateOCIRepositoryCredentials(t *testing.T) {
	s := validSpec()
	values := argocdSecrets(s, spec.GeneratedSecrets{AgeIdentity: "AGE-SECRET-KEY-TEST"})
	repository := values["argo-cd"].(map[string]any)["configs"].(map[string]any)["repositories"].(map[string]any)["bud-charts"].(map[string]any)
	if repository["url"] != "registry.bud.studio/charts" || repository["enableOCI"] != "true" {
		t.Fatalf("unexpected OCI repository configuration: %#v", repository)
	}
	if repository["username"] != s.RegistryUser || repository["password"] != s.RegistryPassword {
		t.Fatal("OCI repository does not use the selected registry credentials")
	}
}

func TestKeycloakOverridesAllEnvironmentURLs(t *testing.T) {
	clients := keycloakValues(validSpec())["realms"].(map[string]any)["keycloak-bud-keycloak-realm"].(map[string]any)["clients"].(map[string]any)
	redirects := clients["budcustomer-web"].(map[string]any)["redirectUris"].([]any)
	found := false
	for _, r := range redirects {
		found = found || r == "https://customer.bud.example.com/*"
	}
	if !found {
		t.Fatalf("customer wildcard redirect is absent: %#v", redirects)
	}
	for _, client := range []string{"budadmin-web", "budcustomer-web", "budplayground-web", "mcp-gateway"} {
		logout, _ := clients[client].(map[string]any)["attributes"].(map[string]any)["post.logout.redirect.uris"].(string)
		if logout == "" || strings.Contains(logout, "bud.lan") {
			t.Fatalf("%s retains an invalid logout URL: %q", client, logout)
		}
	}
}

func TestCertificateModesMatchInstallationContract(t *testing.T) {
	dns := validSpec()
	dns.TLS = spec.TLSACMEDNS01
	acme := certManagerValues(dns)["issuers"].(map[string]any)["letsencrypt-dns01"].(map[string]any)["acme"].(map[string]any)
	if acme["profile"] != "tlsserver" {
		t.Fatalf("DNS issuer profile = %#v", acme["profile"])
	}
	internal := validSpec()
	internal.TLS = spec.TLSInternalCA
	issuer := certManagerValues(internal)["issuers"].(map[string]any)["bud-internal-ca"].(map[string]any)
	if issuer["ca"].(map[string]any)["secretName"] != "bud-internal-ca" {
		t.Fatalf("internal issuer does not reference encrypted CA Secret: %#v", issuer)
	}
	if certManagerSecrets(validSpec(), spec.GeneratedSecrets{}) != nil {
		t.Fatal("self-signed TLS should need no cert-manager secret")
	}
}

// Off OpenShift, images whose USER is a name get the numeric user they run
// as; on OpenShift the platform assigns one and the charts' nulls stand.
func TestNonOpenShiftGetsNumericUsers(t *testing.T) {
	s := validSpec()
	redis := argocdValues(s)["argo-cd"].(map[string]any)["redis"].(map[string]any)["securityContext"].(map[string]any)
	if redis["runAsUser"] != redisUID {
		t.Errorf("argocd redis runAsUser = %v", redis["runAsUser"])
	}
	prom := budValues(s)["prometheus"].(map[string]any)["server"].(map[string]any)["securityContext"].(map[string]any)
	if prom["runAsUser"] != nobodyUID || prom["fsGroup"] != nobodyUID {
		t.Errorf("bud prometheus securityContext = %v", prom)
	}
	webhook := seaweedValues(s)["seaweedfs-operator"].(map[string]any)["webhook"].(map[string]any)
	if webhook["certManager"].(map[string]any)["enabled"] != true {
		t.Errorf("seaweedfs webhook = %v", webhook)
	}
	s.IsOpenShift = true
	if _, ok := argocdValues(s)["argo-cd"].(map[string]any)["redis"]; ok {
		t.Error("OpenShift got a fixed redis user")
	}
	if _, ok := budValues(s)["prometheus"]; ok {
		t.Error("OpenShift got a fixed prometheus user")
	}
}

func TestOpenShiftAddsSeaweedFSWebhookOverride(t *testing.T) {
	s := validSpec()
	s.IsOpenShift = true
	webhook := seaweedValues(s)["seaweedfs-operator"].(map[string]any)["webhook"].(map[string]any)
	if value, present := webhook["podSecurityContext"]; !present || value != nil {
		t.Fatalf("OpenShift webhook podSecurityContext override = %#v", webhook)
	}
}
