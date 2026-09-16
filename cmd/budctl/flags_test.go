package main

import (
	"testing"

	installer "github.com/BudEcosystem/budctl/internal/install"
)

func TestParseInstallFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"install", "--repo", "https://example.com/config.git", "--environment", "prod", "--tls", "internal-ca", "--ca-bundle", "/tmp/trust.pem", "--issuer-ca-cert", "/tmp/issuer.crt", "--issuer-ca-key", "/tmp/issuer.key", "--bud-studio", "--state", "/tmp/budctl-state", "--fresh", "--plan"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.command != "install" || cfg.installRepo == "" || cfg.environment != "prod" || cfg.tls != "internal-ca" || cfg.caBundle != "/tmp/trust.pem" || cfg.issuerCACert != "/tmp/issuer.crt" || cfg.issuerCAKey != "/tmp/issuer.key" || !cfg.budStudio || cfg.statePath != "/tmp/budctl-state" || !cfg.fresh || !cfg.plan {
		t.Fatalf("install flags not retained: %+v", cfg)
	}
	for _, name := range []string{"repo", "environment", "tls", "ca-bundle", "issuer-ca-cert", "issuer-ca-key", "bud-studio", "state", "fresh", "plan"} {
		if !cfg.isSet(name) {
			t.Errorf("explicit flag %q was not tracked", name)
		}
	}
}

func TestParseRejectsFlagsFromAnotherCommand(t *testing.T) {
	if _, err := parseFlags([]string{"check", "--bud-studio"}); err == nil {
		t.Fatal("check accepted an install-only flag")
	}
	if _, err := parseFlags([]string{"install", "--external-datastores"}); err == nil {
		t.Fatal("install accepted a check-only flag")
	}
}

func TestResumeAdvancesOnlyMaintainedTemplatePin(t *testing.T) {
	spec := installer.Spec{TemplateRepo: installer.DefaultTemplateRepo, TemplateRef: "old-default-ref"}
	upgradeCachedTemplateRef(&spec, true, false)
	if spec.TemplateRef != installer.DefaultTemplateRef {
		t.Fatalf("cached default template ref = %q, want %q", spec.TemplateRef, installer.DefaultTemplateRef)
	}

	legacy := installer.Spec{TemplateRepo: installer.LegacyTemplateRepo, TemplateRef: "7d512146093aa77c8186aa330a27991add2d59ae"}
	upgradeCachedTemplateRef(&legacy, true, false)
	if legacy.TemplateRepo != installer.DefaultTemplateRepo || legacy.TemplateRef != installer.DefaultTemplateRef {
		t.Fatalf("legacy infra template was not migrated: %#v", legacy)
	}

	custom := installer.Spec{TemplateRepo: "https://example.com/custom-template.git", TemplateRef: "custom-ref"}
	upgradeCachedTemplateRef(&custom, true, false)
	if custom.TemplateRef != "custom-ref" {
		t.Fatal("custom template pin was changed during resume")
	}

	explicit := installer.Spec{TemplateRepo: installer.DefaultTemplateRepo, TemplateRef: "operator-pin"}
	upgradeCachedTemplateRef(&explicit, true, true)
	if explicit.TemplateRef != "operator-pin" {
		t.Fatal("explicit template pin was changed during resume")
	}
}
