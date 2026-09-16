package tui

import (
	"github.com/charmbracelet/huh"

	"github.com/BudEcosystem/budctl/internal/intake"
)

// intakePages is the number of pages the form can show. Two are conditional
// (config repository, registry token, chart files), so a given run may see fewer.
const intakePages = 8

// buildIntakeForm lays the questions out as a paged wizard. Every consequence
// line is a DescriptionFunc bound to the value it explains: huh writes an
// input's bound value on every keystroke and re-evaluates a description when
// its bindings change, so the line updates as the operator types.
func buildIntakeForm(q *questions, width int) *huh.Form {
	form := huh.NewForm(
		// 1 ── where it lives
		huh.NewGroup(
			huh.NewInput().
				Title("Root domain").
				Placeholder("bud.example.com").
				Value(&q.Domain).
				Validate(q.validateDomain).
				DescriptionFunc(q.domainConsequence, &q.Domain),
			huh.NewSelect[string]().
				Title("How TLS certificates are obtained").
				Options(
					huh.NewOption("ACME HTTP-01 — cert-manager, needs inbound :80", string(intake.TLSACMEHTTP01)),
					huh.NewOption("ACME DNS-01 — cert-manager, validates through DNS", string(intake.TLSACMEDNS01)),
					huh.NewOption("A certificate you provide", string(intake.TLSProvided)),
					huh.NewOption("No TLS", string(intake.TLSNone)),
				).
				Value(&q.TLS).
				DescriptionFunc(q.tlsConsequence, &q.TLS),
		).
			Title("1 · Where Bud will live").
			Description("The domain the install publishes, and how its certificates are issued."),
		huh.NewGroup(
			huh.NewInput().
				Title("Internal CA bundle (optional)").
				Placeholder("/etc/pki/ca-trust/internal-root.pem").
				Value(&q.CABundle).
				Validate(q.validateCABundle).
				DescriptionFunc(q.caBundleConsequence, &q.CABundle),
		).
			Title("1 · Where Bud will live").
			Description("Your certificate is inspected where it is served; budctl never needs the key.").
			WithHideFunc(q.hideCABundle),

		// 2 ── what it holds
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Data stores").
				Options(
					huh.NewOption("In-cluster — installed by the ApplicationSet", "in-cluster"),
					huh.NewOption("External — managed Postgres, ClickHouse, Kafka, …", "external"),
				).
				Value(&q.DataStores).
				DescriptionFunc(q.dataStoresConsequence, &q.DataStores),
			huh.NewInput().
				Title("Model storage (GiB)").
				Placeholder("600").
				Value(&q.ModelStorage).
				Validate(q.validateStorage).
				DescriptionFunc(q.storageConsequence, []any{&q.ModelStorage, &q.Retention, &q.DataStores}),
			huh.NewInput().
				Title("How many models").
				Placeholder("8").
				Value(&q.Models).
				Validate(validateWhole("model count")).
				Description("Roughly how many models are held at once."),
			huh.NewInput().
				Title("Observability retention (days)").
				Placeholder("30").
				Value(&q.Retention).
				Validate(validateWhole("retention")).
				Description("How long traces and metrics are kept. The per-day volume is an estimate."),
		).
			Title("2 · What it needs to hold").
			Description("Storage is the single largest requirement, and it is derived from these answers."),

		// 3 ── what it runs
		huh.NewGroup(
			huh.NewInput().
				Title("Concurrent deployments").
				Placeholder("4").
				Value(&q.Deployments).
				Validate(validateWhole("deployments")).
				DescriptionFunc(q.deploymentsConsequence, &q.Deployments),
			huh.NewConfirm().
				Title("GPU deployments expected?").
				Affirmative("Yes").Negative("No").
				Value(&q.GPU).
				DescriptionFunc(q.gpuConsequence, &q.GPU),
		).
			Title("3 · What it will run"),

		// 4 ── GitOps repository (ArgoCD is the sole delivery mode)
		huh.NewGroup(
			huh.NewInput().
				Title("Config repository URL").
				Placeholder("ssh://git@github.com/acme/bud-config").
				Value(&q.ConfigRepo).
				Validate(q.validateConfigRepo).
				DescriptionFunc(q.configRepoConsequence, &q.ConfigRepo),
		).
			Title("4 · Where ArgoCD reads configuration").
			Description("The repository holding your values.yaml and SOPS secrets."),

		// 5 ── registry access
		huh.NewGroup(
			huh.NewInput().
				Title("registry.bud.studio username").
				Placeholder("robot$acme (optional)").
				Value(&q.RegistryUser).
				DescriptionFunc(q.registryConsequence, &q.RegistryUser),
		).
			Title("5 · Registry access").
			Description("Optional at this stage."),
		huh.NewGroup(
			huh.NewInput().
				Title("registry.bud.studio token").
				EchoMode(huh.EchoModePassword).
				Value(&q.RegistryPass).
				Description("Not echoed, and never written to the saved report."),
		).
			Title("5 · Registry access").
			WithHideFunc(q.hideRegistryToken),

		// 6 ── deeper checks
		huh.NewGroup(
			huh.NewInput().
				Title("Values file").
				Placeholder("infra/values/bud/values.prod.yaml (optional)").
				Value(&q.ValuesFile).
				DescriptionFunc(q.valuesConsequence, &q.ValuesFile),
		).
			Title("6 · Your configuration").
			Description("Optional, but it unlocks the strongest checks."),
		huh.NewGroup(
			huh.NewInput().
				Title("Chart directory").
				Placeholder("infra/charts/bud").
				Value(&q.ChartDir).
				Description("Required to render the values above."),
			huh.NewInput().
				Title("SOPS secrets file").
				Placeholder("infra/values/bud/secrets.prod.yaml (optional)").
				Value(&q.SecretsFile).
				Description("Decrypted in-process — no sops binary needed."),
		).
			Title("6 · Your configuration").
			WithHideFunc(q.hideChartFiles),

		// 7 ── run
		huh.NewGroup(
			huh.NewConfirm().
				Title("Probe from inside the cluster?").
				Affirmative("Yes, probe").Negative("No, read-only").
				Value(&q.Probe).
				DescriptionFunc(q.probeConsequence, &q.Probe),
		).
			Title("7 · Ready to check"),
	).
		WithTheme(intakeTheme()).
		WithShowHelp(true).
		WithShowErrors(true)

	if width > 0 {
		w := width - 6
		if w > 96 {
			w = 96
		}
		form = form.WithWidth(w)
	}
	return form
}
