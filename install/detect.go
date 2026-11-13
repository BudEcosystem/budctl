package install

import (
	"context"
	"regexp"
	"strings"

	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/BudEcosystem/budctl/k8s"
)

// DetectDefaults fills what the cluster can answer and the operator has not:
// the environment name from the kube context, OpenShift and its apps domain,
// and the default IngressClass and StorageClass. A value already set is never
// replaced.
func DetectDefaults(ctx context.Context, kube *k8s.Client, s *spec.Spec) {
	if kube == nil || s == nil {
		return
	}
	if s.Environment == "" {
		s.Environment = environmentName(kube.Context)
	}
	if kube.HasAPIVersion(ctx, "route.openshift.io/v1") {
		s.IsOpenShift = true
		if s.IngressClass == "" {
			s.IngressClass = "openshift-default"
		}
		s.IsTraefik = false
		if s.Domain == "" {
			if ing := kube.Get(ctx, "ingresses.config.openshift.io", "", "cluster"); ing != nil {
				s.Domain = ing.DigString("s", "domain")
			}
		}
	}
	if s.IngressClass == "" {
		classes := kube.List(ctx, "ingressclasses.networking.k8s.io", "")
		for _, class := range classes {
			annotations := class.Annotations()
			if annotations["ingressclass.kubernetes.io/is-default-class"] == "true" {
				s.IngressClass = class.Name()
				break
			}
		}
		if s.IngressClass == "" && len(classes) == 1 {
			s.IngressClass = classes[0].Name()
		}
	}
	if strings.Contains(strings.ToLower(s.IngressClass), "traefik") {
		s.IsTraefik = true
	}
	if s.StorageClass == "" {
		classes := kube.List(ctx, "storageclasses.storage.k8s.io", "")
		for _, class := range classes {
			a := class.Annotations()
			if a["storageclass.kubernetes.io/is-default-class"] == "true" || a["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
				s.StorageClass = class.Name()
				break
			}
		}
		if s.StorageClass == "" && len(classes) == 1 {
			s.StorageClass = classes[0].Name()
		}
	}
	s.Normalize()
}

var invalidEnvironment = regexp.MustCompile(`[^a-z0-9-]+`)

func environmentName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = invalidEnvironment.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if len(value) > 63 {
		value = strings.Trim(value[:63], "-")
	}
	if value == "" {
		return "production"
	}
	return value
}
