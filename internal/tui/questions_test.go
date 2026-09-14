package tui

import (
	"strings"
	"testing"
)

func TestQuestionsRequireADomain(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	for _, bad := range []string{"", "   ", "example", "has space.com", "https://bud.example.com"} {
		if q.validateDomain(bad) == nil {
			t.Errorf("accepted %q as a domain", bad)
		}
	}
	if err := q.validateDomain("bud.example.com"); err != nil {
		t.Errorf("rejected a valid domain: %v", err)
	}
}

// ArgoCD cannot sync without a values source, so the repo is mandatory under
// ArgoCD and irrelevant without it.
func TestQuestionsConfigRepoIsMandatoryOnlyUnderArgoCD(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	q.ArgoCD = true
	if q.validateConfigRepo("") == nil {
		t.Fatal("empty config repo accepted with ArgoCD on")
	}
	if q.validateConfigRepo("github.com/acme/cfg") == nil {
		t.Fatal("a non-git URL was accepted")
	}
	for _, ok := range []string{"https://github.com/acme/cfg", "ssh://git@github.com/acme/cfg", "git@github.com:acme/cfg"} {
		if err := q.validateConfigRepo(ok); err != nil {
			t.Errorf("rejected %q: %v", ok, err)
		}
	}
	q.ArgoCD = false
	if err := q.validateConfigRepo(""); err != nil {
		t.Fatalf("demanded a config repo for a direct-Helm install: %v", err)
	}
}

func TestQuestionsOfferTheOpenShiftAppsDomainButPreferAnExplicitOne(t *testing.T) {
	if q := newQuestions(testCtx(t), "apps.ocp.example.com"); q.Domain != "apps.ocp.example.com" {
		t.Fatalf("apps domain not offered: %q", q.Domain)
	}
	c := testCtx(t)
	c.Answers.Domain = "bud.customer.com"
	if q := newQuestions(c, "apps.ocp.example.com"); q.Domain != "bud.customer.com" {
		t.Fatalf("explicit domain overridden: %q", q.Domain)
	}
}

// The storage line is the one operators question, so it shows its working. The
// terms also pin the constants: the data-store figure was once 190 GiB, which
// understated the requirement by 79 GiB.
func TestQuestionsStorageConsequenceShowsItsArithmetic(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	q.ModelStorage, q.Retention, q.DataStores = "600", "30", "in-cluster"
	line := q.storageConsequence()
	for _, want := range []string{
		"600 GiB model weights", "58 GiB platform claims", "269 GiB in-cluster data stores",
		"30 GiB traces and metrics (30d retention), estimated", "957 GiB",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("storage line omits %q\n  got: %s", want, line)
		}
	}
	q.DataStores = "external"
	if strings.Contains(q.storageConsequence(), "data stores") {
		t.Error("external data stores still counted in the storage requirement")
	}
	q.ModelStorage = ""
	if blank := q.storageConsequence(); !strings.Contains(blank, "before any model weights") {
		t.Errorf("a blank size reads as a minimum rather than a floor: %s", blank)
	}
}

func TestQuestionsConsequencesFollowTheAnswer(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	q.TLS = "acme-http01"
	if !strings.Contains(q.tlsConsequence(), "port 80") {
		t.Error("HTTP-01 does not warn about inbound :80")
	}
	q.TLS = "acme-dns01"
	if strings.Contains(q.tlsConsequence(), "BLOCKER") {
		t.Error("DNS-01 still claims :80 is a blocker")
	}
	q.Probe = false
	if !strings.Contains(q.probeConsequence(), "NOT VERIFIED") {
		t.Error("read-only mode does not say probe checks go unverified")
	}
	q.OpenSandbox = true
	if !strings.Contains(q.sandboxConsequence(), "aliyuncs.com") {
		t.Error("OpenSandbox does not name the Alibaba registry it requires")
	}
}

func TestQuestionsHideWhatTheAnswersMakeIrrelevant(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	q.ArgoCD, q.RegistryUser, q.ValuesFile = false, "", ""
	if !q.hideConfigRepo() || !q.hideRegistryToken() || !q.hideChartFiles() {
		t.Fatal("irrelevant pages are shown")
	}
	q.ArgoCD, q.RegistryUser, q.ValuesFile = true, "robot$acme", "values.yaml"
	if q.hideConfigRepo() || q.hideRegistryToken() || q.hideChartFiles() {
		t.Fatal("relevant pages are hidden")
	}
}

func TestQuestionsApplyOntoTheContext(t *testing.T) {
	c := testCtx(t)
	q := newQuestions(c, "")
	q.Domain, q.ModelStorage, q.Deployments = " bud.example.com ", "600", "7"
	q.GPU, q.Probe, q.DataStores = true, false, "external"
	q.RegistryUser, q.RegistryPass = "robot$acme", "tok"
	q.ValuesFile, q.ChartDir = "", "ignored"
	q.apply(c)

	a := c.Answers
	if a.Domain != "bud.example.com" || a.ModelStorageGi != 600 || a.Deployments != 7 || !a.GPU || a.InClusterData {
		t.Fatalf("answers not applied: %+v", a)
	}
	if !c.Opts.NoProbe {
		t.Error("probing off did not reach Opts.NoProbe")
	}
	if cred, ok := c.Opts.RegistryCreds["registry.bud.studio"]; !ok || cred.Password != "tok" {
		t.Error("registry credentials not applied")
	}
	if c.Opts.ValuesFiles != nil {
		t.Error("no values file answered, but ValuesFiles is set")
	}
}
