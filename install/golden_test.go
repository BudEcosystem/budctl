package install

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/getsops/sops/v3/decrypt"
	"gopkg.in/yaml.v3"
)

// The golden tests pin what an installation produces, across the matrix of
// decisions that change it. Two files are recorded per case:
//
//   - <case>.artifacts.yaml: every file the installer commits, secrets
//     decrypted. It changes whenever the repository layout changes.
//   - <case>.effective.yaml: what each ArgoCD Application actually receives,
//     its valueFiles merged in order, plus the AppSet template and the root
//     Application. This is the contract. A refactor of how the files are laid
//     out must leave it unchanged.
//
// Run `go test ./install -run Golden -update` to rewrite them, and
// review the diff.

var update = flag.Bool("update", false, "rewrite the golden files")

// A fixed identity makes the SOPS files decryptable in the test and the
// rendered argocd secrets (which embed the identity) stable.
const (
	goldenAgeIdentity  = "AGE-SECRET-KEY-19LCLPSGZL57K7TDN9CPH4H734VZN3JY0EAT60SG5W2QSK68F6A8QQPTQSL"
	goldenAgeRecipient = "age1xtn2pyh4mweknx7ppg3ndxeurvjwsv99r6ev9xdve94eqhq7e3ws7ej7j8"
)

type goldenCase struct {
	tls       spec.TLSMode
	studio    bool
	openShift bool
}

func (c goldenCase) name() string {
	name := string(c.tls)
	if c.studio {
		name += "-studio"
	}
	if c.openShift {
		name += "-openshift"
	}
	return name
}

func goldenCases() []goldenCase {
	var cases []goldenCase
	for _, tls := range []spec.TLSMode{spec.TLSACMEDNS01, spec.TLSACMEHTTP01, spec.TLSSelfSigned, spec.TLSInternalCA, spec.TLSExternal} {
		for _, studio := range []bool{false, true} {
			for _, openShift := range []bool{false, true} {
				cases = append(cases, goldenCase{tls, studio, openShift})
			}
		}
	}
	return cases
}

func goldenSpec(t *testing.T, c goldenCase) spec.Spec {
	t.Helper()
	s := spec.Defaults()
	s.Environment = "production"
	s.TargetRepo = "https://github.com/example/bud-config.git"
	s.Domain = "bud.example.com"
	s.StorageClass = "standard"
	s.RegistryUser = "robot"
	s.RegistryPassword = "registry-secret"
	s.AdminEmail = "admin@example.com"
	s.TLS = c.tls
	s.IngressClass = "traefik"
	if c.openShift {
		s.IsOpenShift = true
		s.IngressClass = "openshift-default"
	}
	switch c.tls {
	case spec.TLSACMEDNS01:
		s.CloudflareToken = "cloudflare-token"
	case spec.TLSInternalCA:
		s.IssuerCACertPEM = string(readTestdata(t, "ca.crt"))
		s.IssuerCAKeyPEM = string(readTestdata(t, "ca.key"))
	}
	if c.studio {
		s.BudStudio = true
		s.StudioModel = "qwen3-8b"
	}
	s.Normalize()
	return s
}

// goldenSecrets keeps every generated name, so a new secret shows up in the
// golden, but replaces each value with a readable constant.
func goldenSecrets(t *testing.T) spec.GeneratedSecrets {
	t.Helper()
	g, err := spec.GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	for name := range g.Values {
		g.Values[name] = "golden-" + name
	}
	g.AgeIdentity = goldenAgeIdentity
	g.AgeRecipient = goldenAgeRecipient
	g.AdminPassword = "golden-admin-password"
	g.RSAPrivate = "golden-rsa-private"
	g.RSAPublic = "golden-rsa-public"
	return g
}

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// renderedRepository is everything an installation produces.
type renderedRepository struct {
	// files is every file ArgoCD reads for the environment, by repository path.
	files map[string][]byte
	// generated names the files the installer itself writes.
	generated map[string]bool
	// bootstrap is the in-memory ArgoCD values used for the first Helm install.
	bootstrap map[string]any
}

// renderRepository lays out the installation exactly as it is committed: every
// file is one the installer generates.
func renderRepository(t *testing.T, s spec.Spec, generated spec.GeneratedSecrets) renderedRepository {
	t.Helper()
	bundle, err := Render(s, generated)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	ours := map[string]bool{}
	for _, a := range bundle.Artifacts {
		files[a.Path] = a.Data
		ours[a.Path] = true
	}
	return renderedRepository{files, ours, bundle.BootstrapValues}
}

// decodeValues parses a values file, decrypting it first when it is SOPS.
func decodeValues(body []byte) (map[string]any, error) {
	if bytes.Contains(body, []byte("\nsops:")) {
		plain, err := decrypt.Data(body, "yaml")
		if err != nil {
			return nil, err
		}
		body = plain
	}
	out := map[string]any{}
	if err := yaml.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	delete(out, "sops")
	return out, nil
}

// effective resolves the repository the way ArgoCD and Helm do: for each
// ApplicationSet element, the $values files are merged in list order. Files
// that live inside the chart are recorded by name, since they are not ours.
func effective(t *testing.T, env string, files map[string][]byte, bootstrap map[string]any) map[string]any {
	t.Helper()
	var appset map[string]any
	if err := yaml.Unmarshal(files["appsets/"+env+".yaml"], &appset); err != nil {
		t.Fatalf("appset: %v", err)
	}
	spec := appset["spec"].(map[string]any)
	generators := spec["generators"].([]any)
	elements := generators[0].(map[string]any)["list"].(map[string]any)["elements"].([]any)
	byName := map[string]any{}
	for _, raw := range elements {
		el := raw.(map[string]any)
		values := map[string]any{}
		var chartFiles []any
		for _, f := range el["valueFiles"].([]any) {
			path, ok := strings.CutPrefix(f.(string), "$values/")
			if !ok {
				chartFiles = append(chartFiles, f)
				continue
			}
			body, exists := files[path]
			if !exists {
				t.Fatalf("%s references %s, which the repository does not contain", el["name"], path)
			}
			layer, err := decodeValues(body)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			values = components.Merge(values, layer)
		}
		source := map[string]any{}
		for _, key := range []string{"repoURL", "chart", "targetRevision", "gitRepoURL", "gitRevision", "gitPath"} {
			if v, ok := el[key]; ok && v != "" {
				source[key] = v
			}
		}
		byName[el["name"].(string)] = map[string]any{
			"namespace":       el["namespace"],
			"source":          source,
			"chartValueFiles": chartFiles,
			"values":          values,
		}
	}
	delete(spec, "generators")
	var root map[string]any
	if err := yaml.Unmarshal(files["apps/"+env+".yaml"], &root); err != nil {
		t.Fatalf("root application: %v", err)
	}
	return map[string]any{
		"applicationSet":        appset,
		"components":            byName,
		"rootApplication":       root,
		"argocdBootstrapValues": bootstrap,
	}
}

func artifactsDocument(t *testing.T, r renderedRepository) map[string]any {
	t.Helper()
	out := map[string]any{}
	for path := range r.generated {
		body := r.files[path]
		var doc any
		if strings.HasSuffix(path, ".yaml") {
			values, err := decodeValues(body)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			doc = values
		} else {
			doc = string(body)
		}
		out[path] = doc
	}
	return out
}

func assertGolden(t *testing.T, name string, doc any) {
	t.Helper()
	got, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file:\n%s", name, lineDiff(string(want), string(got)))
	}
}

// lineDiff reports the first differing lines, which is enough to find the
// change; `-update` and git diff show the rest.
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	shown := 0
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl == gl {
			continue
		}
		fmt.Fprintf(&b, "  line %d\n    - %s\n    + %s\n", i+1, wl, gl)
		if shown++; shown == 10 {
			b.WriteString("  …\n")
			break
		}
	}
	return b.String()
}

func TestGoldenInstall(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", goldenAgeIdentity)
	generated := goldenSecrets(t)
	for _, c := range goldenCases() {
		t.Run(c.name(), func(t *testing.T) {
			s := goldenSpec(t, c)
			r := renderRepository(t, s, generated)
			assertGolden(t, c.name()+".artifacts.yaml", artifactsDocument(t, r))
			assertGolden(t, c.name()+".effective.yaml", effective(t, s.Environment, r.files, r.bootstrap))
		})
	}
}
