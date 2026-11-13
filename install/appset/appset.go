// Package appset builds the two ArgoCD objects an environment is rooted in:
// the ApplicationSet with one element per component, and the root Application
// that syncs it from the GitOps repository.
//
// They are Go structs marshalled to YAML. ArgoCD's own {{ }} expressions are
// ordinary strings here, so budctl never runs a template engine over a file
// that another template engine will read.
package appset

import (
	"bytes"
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Element is one generator element: the variables the ApplicationSet template
// turns into a component's Application. A Helm chart sets RepoURL, Chart and
// TargetRevision; a chart in a Git repository sets the Git fields. GitPath is
// always present because the template branches on it under
// missingkey=error.
type Element struct {
	Name           string   `yaml:"name"`
	Namespace      string   `yaml:"namespace"`
	GitPath        string   `yaml:"gitPath"`
	GitRepoURL     string   `yaml:"gitRepoURL,omitempty"`
	GitRevision    string   `yaml:"gitRevision,omitempty"`
	RepoURL        string   `yaml:"repoURL,omitempty"`
	Chart          string   `yaml:"chart,omitempty"`
	TargetRevision string   `yaml:"targetRevision,omitempty"`
	ValueFiles     []string `yaml:"valueFiles"`
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type ApplicationSet struct {
	APIVersion string             `yaml:"apiVersion"`
	Kind       string             `yaml:"kind"`
	Metadata   Metadata           `yaml:"metadata"`
	Spec       ApplicationSetSpec `yaml:"spec"`
}

type ApplicationSetSpec struct {
	GoTemplate        bool        `yaml:"goTemplate"`
	GoTemplateOptions []string    `yaml:"goTemplateOptions"`
	Generators        []Generator `yaml:"generators"`
	Template          Template    `yaml:"template"`
	TemplatePatch     string      `yaml:"templatePatch"`
}

type Generator struct {
	List ListGenerator `yaml:"list"`
}

type ListGenerator struct {
	Elements []Element `yaml:"elements"`
}

type Template struct {
	Metadata Metadata        `yaml:"metadata"`
	Spec     ApplicationSpec `yaml:"spec"`
}

type ApplicationSpec struct {
	Project     string      `yaml:"project"`
	Source      *Source     `yaml:"source,omitempty"`
	Destination Destination `yaml:"destination"`
	SyncPolicy  SyncPolicy  `yaml:"syncPolicy"`
}

type Source struct {
	RepoURL        string     `yaml:"repoURL"`
	TargetRevision string     `yaml:"targetRevision"`
	Path           string     `yaml:"path"`
	Directory      *Directory `yaml:"directory,omitempty"`
}

type Directory struct {
	Include string `yaml:"include"`
}

type Destination struct {
	Server    string `yaml:"server"`
	Namespace string `yaml:"namespace"`
}

type SyncPolicy struct {
	SyncOptions []string  `yaml:"syncOptions"`
	Automated   Automated `yaml:"automated"`
}

// Automated sync is declared but disabled: the installer syncs each component
// in dependency order, and selfHeal keeps them converged after that.
type Automated struct {
	Enabled  bool `yaml:"enabled"`
	SelfHeal bool `yaml:"selfHeal"`
}

type Application struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   Metadata        `yaml:"metadata"`
	Spec       ApplicationSpec `yaml:"spec"`
}

const (
	argoAPIVersion = "argoproj.io/v1alpha1"
	argoNamespace  = "argocd"
	inCluster      = "https://kubernetes.default.svc"
)

// RootName is the root Application every environment's ApplicationSet is
// synced through.
const RootName = "bootstrap"

// templatePatch belongs to ArgoCD's template engine: it picks a Helm or Git
// source per element and adds the GitOps repository as the $values source.
// Only the repository and branch come from budctl, quoted for YAML.
const templatePatch = `spec:
  sources:
    {{- if .gitPath }}
    - repoURL: {{ .gitRepoURL | quote }}
      targetRevision: {{ .gitRevision | quote }}
      path: {{ .gitPath | quote }}
      helm:
        releaseName: "{{.name}}"
        valueFiles:
          {{- .valueFiles | toYaml | nindent 12 }}
    {{- else }}
    - repoURL: {{ .repoURL | quote }}
      chart: {{ .chart | quote }}
      targetRevision: {{ .targetRevision | quote }}
      helm:
        releaseName: "{{.name}}"
        valueFiles:
          {{- .valueFiles | toYaml | nindent 12 }}
    {{- end }}
    - repoURL: %s
      targetRevision: %s
      ref: values
`

// New builds the environment's ApplicationSet. Each element becomes an
// Application named <environment>-<component> in the environment's project.
func New(environment, repoURL, branch string, elements []Element) ApplicationSet {
	return ApplicationSet{
		APIVersion: argoAPIVersion,
		Kind:       "ApplicationSet",
		Metadata:   Metadata{Name: environment, Namespace: argoNamespace},
		Spec: ApplicationSetSpec{
			GoTemplate:        true,
			GoTemplateOptions: []string{"missingkey=error"},
			Generators:        []Generator{{List: ListGenerator{Elements: elements}}},
			Template: Template{
				// Applications apply server-side, so they must also diff server-side:
				// ArgoCD's default client-side diff reads every field the API server
				// defaults (Kyverno policies, CRDs) as drift, and the Application never
				// reports Synced.
				Metadata: Metadata{
					Name:        environment + "-{{.name}}",
					Annotations: map[string]string{"argocd.argoproj.io/compare-options": "ServerSideDiff=true"},
				},
				Spec: ApplicationSpec{
					Project:     environment,
					Destination: Destination{Server: inCluster, Namespace: "{{.namespace}}"},
					SyncPolicy: SyncPolicy{
						SyncOptions: []string{"CreateNamespace=true", "ServerSideApply=true"},
						Automated:   Automated{Enabled: false, SelfHeal: true},
					},
				},
			},
			TemplatePatch: fmt.Sprintf(templatePatch, strconv.Quote(repoURL), strconv.Quote(branch)),
		},
	}
}

// Root builds the root Application, which syncs the environment's
// ApplicationSet file from the GitOps repository.
func Root(environment, repoURL, branch string) Application {
	return Application{
		APIVersion: argoAPIVersion,
		Kind:       "Application",
		Metadata:   Metadata{Name: RootName, Namespace: argoNamespace},
		Spec: ApplicationSpec{
			Project: "default",
			Source: &Source{
				RepoURL:        repoURL,
				TargetRevision: branch,
				Path:           "appsets",
				Directory:      &Directory{Include: environment + ".yaml"},
			},
			Destination: Destination{Server: inCluster, Namespace: argoNamespace},
			SyncPolicy: SyncPolicy{
				SyncOptions: []string{"CreateNamespace=true", "Prune=confirm"},
				Automated:   Automated{Enabled: false, SelfHeal: true},
			},
		},
	}
}

// Marshal encodes an ArgoCD object as YAML.
func Marshal(object any) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("# Generated by budctl install from its component table.\n")
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(object); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
