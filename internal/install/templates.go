package install

import "fmt"

func renderBootstrap(spec Spec) string {
	return fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: bootstrap
  namespace: argocd
spec:
  project: default
  source:
    repoURL: %q
    targetRevision: %q
    path: appsets
    directory:
      include: %q
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
      - Prune=confirm
    automated:
      enabled: false
      selfHeal: true
`, manifestRepo(spec.TargetRepo), spec.PushBranch, spec.Environment+".yaml")
}
