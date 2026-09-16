package install

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"gopkg.in/yaml.v3"
)

const openSandboxSourceRef = "adc5eb4518b820e3452512fcf30fe4cb2e1da524"

type Artifact struct {
	Path      string
	Data      []byte
	Sensitive bool
}

type Bundle struct {
	Artifacts        []Artifact
	RecoveryKey      []byte
	RecoveryFileName string
	AdminPassword    string
	AgeRecipient     string
	// BootstrapValues exists only in memory. It combines the generated ArgoCD
	// public values and plaintext SOPS identity so the first ArgoCD release can
	// decrypt the same files that are committed for its steady-state upgrade.
	BootstrapValues map[string]any
}

// Render creates an environment overlay without copying any environment's
// hardware-specific values. All ordinary Bud services and OpenSandbox remain
// enabled; Bud Studio is the only optional Application.
func Render(spec Spec) (Bundle, error) {
	generated, err := GenerateSecrets(spec.AdminPassword)
	if err != nil {
		return Bundle{}, err
	}
	return RenderWithSecrets(spec, generated)
}

// RenderWithSecrets makes retries deterministic at the credential level. SOPS
// ciphertext is freshly randomized, but service passwords and the environment
// age identity remain stable across a corrected or resumed run.
func RenderWithSecrets(spec Spec, generated GeneratedSecrets) (Bundle, error) {
	spec.Normalize()
	if err := spec.Validate(); err != nil {
		return Bundle{}, err
	}
	if generated.AgeIdentity == "" || generated.AgeRecipient == "" || generated.AdminPassword == "" || len(generated.Values) == 0 {
		return Bundle{}, fmt.Errorf("cached generated credentials are incomplete")
	}
	recipients := append([]string{generated.AgeRecipient}, spec.AgeRecipients...)

	plain := map[string]any{
		filepath.Join("values", "argocd", "secrets."+spec.Environment+".yaml"):      argocdSecrets(spec, generated),
		filepath.Join("values", "bud", "secrets."+spec.Environment+".yaml"):         budSecrets(spec, generated),
		filepath.Join("values", "keycloak", "secrets."+spec.Environment+".yaml"):    keycloakSecrets(spec, generated),
		filepath.Join("values", "postgres", "secrets."+spec.Environment+".yaml"):    postgresSecrets(generated),
		filepath.Join("values", "clickhouse", "secrets."+spec.Environment+".yaml"):  map[string]any{"users": map[string]any{"bud": map[string]any{"password": generated.Values["clickhouse"]}}},
		filepath.Join("values", "kafka", "secrets."+spec.Environment+".yaml"):       map[string]any{"users": map[string]any{"bud": map[string]any{"password": generated.Values["kafka"]}}},
		filepath.Join("values", "mongodb", "secrets."+spec.Environment+".yaml"):     map[string]any{"users": map[string]any{"bud_novu": map[string]any{"password": generated.Values["mongodb"]}}},
		filepath.Join("values", "seaweedfs", "secrets."+spec.Environment+".yaml"):   seaweedSecrets(generated),
		filepath.Join("values", "valkey", "secrets."+spec.Environment+".yaml"):      map[string]any{"auth": map[string]any{"password": generated.Values["valkey"]}},
		filepath.Join("values", "opensandbox", "secrets."+spec.Environment+".yaml"): openSandboxSecrets(spec, generated),
	}
	if spec.TLS == TLSACMEDNS01 {
		plain[filepath.Join("values", "cert-manager", "secrets."+spec.Environment+".yaml")] = map[string]any{
			"secrets": map[string]any{"cloudflare-api-token": map[string]any{"api-token": spec.CloudflareToken}},
		}
	} else if spec.TLS == TLSInternalCA {
		plain[filepath.Join("values", "cert-manager", "secrets."+spec.Environment+".yaml")] = map[string]any{
			"secrets": map[string]any{"bud-internal-ca": map[string]any{
				"tls.crt": spec.IssuerCACertPEM,
				"tls.key": spec.IssuerCAKeyPEM,
			}},
		}
	}
	if spec.BudStudio {
		plain[filepath.Join("values", "bud-studio", "secrets."+spec.Environment+".yaml")] = budStudioSecrets(spec, generated)
	}

	public := map[string]any{
		filepath.Join("apps", spec.Environment+".yaml"): []byte(renderBootstrap(spec)),
		// PrepareRepository replaces this typed-nil placeholder by rendering the
		// pinned template repository's canonical ApplicationSet.
		filepath.Join("appsets", spec.Environment+".yaml"):                       []byte(nil),
		filepath.Join("values", "argocd", "values."+spec.Environment+".yaml"):    argocdValues(spec),
		filepath.Join("values", "bud", "values."+spec.Environment+".yaml"):       budValues(spec),
		filepath.Join("values", "keycloak", "values."+spec.Environment+".yaml"):  keycloakValues(spec),
		filepath.Join("values", "seaweedfs", "values."+spec.Environment+".yaml"): seaweedValues(spec),
	}
	if values := certManagerValues(spec); values != nil {
		public[filepath.Join("values", "cert-manager", "values."+spec.Environment+".yaml")] = values
	}
	if spec.BudStudio {
		public[filepath.Join("values", "bud-studio", "values."+spec.Environment+".yaml")] = budStudioValues(spec)
	}

	bundle := Bundle{
		RecoveryKey:      []byte("# created by budctl; keep outside Git\n" + generated.AgeIdentity + "\n"),
		RecoveryFileName: "budctl-" + spec.Environment + ".agekey",
		AdminPassword:    generated.AdminPassword,
		AgeRecipient:     generated.AgeRecipient,
		BootstrapValues:  mergeValueMaps(argocdValues(spec), argocdSecrets(spec, generated)),
	}
	for path, value := range public {
		var err error
		data, ok := value.([]byte)
		if !ok {
			data, err = yaml.Marshal(value)
			if err != nil {
				return Bundle{}, fmt.Errorf("encode %s: %w", path, err)
			}
		}
		bundle.Artifacts = append(bundle.Artifacts, Artifact{Path: path, Data: data})
	}
	sops := adapters.NewSOPS()
	for path, value := range plain {
		data, err := yaml.Marshal(value)
		if err != nil {
			return Bundle{}, fmt.Errorf("encode %s: %w", path, err)
		}
		encrypted, err := sops.EncryptYAML(data, recipients)
		if err != nil {
			return Bundle{}, fmt.Errorf("encrypt %s: %w", path, err)
		}
		bundle.Artifacts = append(bundle.Artifacts, Artifact{Path: path, Data: encrypted, Sensitive: true})
	}
	sort.Slice(bundle.Artifacts, func(i, j int) bool { return bundle.Artifacts[i].Path < bundle.Artifacts[j].Path })
	return bundle, nil
}

func mergeValueMaps(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range over {
		if nested, ok := value.(map[string]any); ok {
			if current, ok := out[key].(map[string]any); ok {
				out[key] = mergeValueMaps(current, nested)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func registry(spec Spec) map[string]any {
	return map[string]any{"registry.bud.studio": map[string]any{
		"username": spec.RegistryUser, "password": spec.RegistryPassword,
	}}
}

func argocdSecrets(spec Spec, generated GeneratedSecrets) map[string]any {
	out := map[string]any{
		"sopsAgeKeys": generated.AgeIdentity,
		"argo-cd": map[string]any{"configs": map[string]any{"repositories": map[string]any{
			"bud-charts": map[string]any{
				"name": "bud-charts", "type": "helm", "url": "registry.bud.studio/charts",
				"enableOCI": "true", "username": spec.RegistryUser, "password": spec.RegistryPassword,
			},
		}}},
	}
	if strings.TrimSpace(spec.RepoSSHPrivateKey) != "" {
		out["repo"] = map[string]any{"sshPrivateKey": spec.RepoSSHPrivateKey}
	}
	return out
}

func postgresSecrets(g GeneratedSecrets) map[string]any {
	return map[string]any{"users": map[string]any{
		"bud":       map[string]any{"password": g.Values["postgres-bud"]},
		"keycloak":  map[string]any{"password": g.Values["postgres-keycloak"]},
		"seaweedfs": map[string]any{"password": g.Values["postgres-seaweedfs"]},
	}}
}

func seaweedSecrets(g GeneratedSecrets) map[string]any {
	return map[string]any{
		"postgres": map[string]any{"password": g.Values["postgres-seaweedfs"]},
		"identity": map[string]any{"bud": map[string]any{
			"accessKey": g.Values["s3-access"], "secretKey": g.Values["s3-secret"],
		}},
	}
}

func keycloakSecrets(spec Spec, g GeneratedSecrets) map[string]any {
	return map[string]any{
		"password":   g.Values["keycloak-admin"],
		"postgres":   map[string]any{"password": g.Values["postgres-keycloak"]},
		"registries": registry(spec),
		"realms": map[string]any{"keycloak-bud-keycloak-realm": map[string]any{
			"clients": map[string]any{
				"budadmin-web":      map[string]any{"secret": g.Values["keycloak-budadmin"]},
				"budcustomer-web":   map[string]any{"secret": g.Values["keycloak-budcustomer"]},
				"budplayground-web": map[string]any{"secret": g.Values["keycloak-budplayground"]},
				"mcp-gateway":       map[string]any{"secret": g.Values["keycloak-mcpgateway"]},
				"budapp-admin":      map[string]any{"secret": g.Values["keycloak-budapp-admin"]},
			},
		}},
	}
}

var postgresDatabases = []string{
	"keycloak", "budask", "budapp", "budcluster", "budmetrics", "budmodel",
	"budsim", "budeval", "buddoc", "budprompt", "mcpgateway", "budpipeline",
	"onyx", "budcodeinterpreter", "budevent", "budagent",
}

func budSecrets(spec Spec, g GeneratedSecrets) map[string]any {
	dbs := map[string]any{}
	for _, name := range postgresDatabases {
		user, password := "bud", g.Values["postgres-bud"]
		if name == "keycloak" {
			user, password = "keycloak", g.Values["postgres-keycloak"]
		}
		dbs[name] = map[string]any{"username": user, "password": password}
	}
	return map[string]any{
		"registries":  registry(spec),
		"appApiToken": g.Values["app-api"],
		"externalServices": map[string]any{
			"oidc":       map[string]any{"clients": map[string]any{"mcpgateway": map[string]any{"secret": g.Values["keycloak-mcpgateway"]}}},
			"s3":         map[string]any{"auth": map[string]any{"accessKey": g.Values["s3-access"], "secretKey": g.Values["s3-secret"]}},
			"mongodb":    map[string]any{"auth": map[string]any{"username": "bud_novu", "password": g.Values["mongodb"]}},
			"valkey":     map[string]any{"password": g.Values["valkey"]},
			"clickhouse": map[string]any{"auth": map[string]any{"username": "bud", "password": g.Values["clickhouse"]}},
			"kafka":      map[string]any{"auth": map[string]any{"username": "bud", "password": g.Values["kafka"]}},
			"postgresql": map[string]any{"databases": dbs},
		},
		"novu": map[string]any{
			"externalDatabase": map[string]any{"username": "bud_novu", "password": g.Values["mongodb"]},
			"store":            map[string]any{"encryption-key": g.Values["novu-encryption"]},
		},
		"novuExtra": map[string]any{"email": spec.AdminEmail, "password": g.Values["novu-admin"]},
		"microservices": map[string]any{
			"rsaKeys":    map[string]any{"privateKeyPassword": g.Values["rsa-password"], "privateKey": g.RSAPrivate, "publicKey": g.RSAPublic},
			"budcluster": map[string]any{"registerDefaultCluster": map[string]any{"token": g.Values["cluster-token"]}},
			"budcodeinterpreter": map[string]any{"env": map[string]any{
				"SECRETS_OPENSANDBOX_API_KEY": g.Values["opensandbox-api"],
			}},
			"budapp": map[string]any{
				"env": map[string]any{"JWT_SECRET_KEY": g.Values["jwt"], "AES_KEY_HEX": g.Values["aes"]},
				"redirectFlow": map[string]any{
					"sessionSecret": g.Values["session"], "defaultClientSecret": g.Values["keycloak-budadmin"],
					"adminClientSecret": g.Values["keycloak-budapp-admin"],
					"clientsByHost": map[string]any{
						"budadmin":      map[string]any{"clientId": "budadmin-web", "clientSecret": g.Values["keycloak-budadmin"]},
						"budcustomer":   map[string]any{"clientId": "budcustomer-web", "clientSecret": g.Values["keycloak-budcustomer"]},
						"budplayground": map[string]any{"clientId": "budplayground-web", "clientSecret": g.Values["keycloak-budplayground"]},
					},
				},
			},
			"budnotify": map[string]any{"env": map[string]any{"STORE_ENCRYPTION_KEY": g.Values["notify-store"], "JWT_SECRET": g.Values["notify-jwt"]}},
			"mcpgateway": map[string]any{"env": map[string]any{
				"BASIC_AUTH_USER": spec.AdminEmail, "BASIC_AUTH_PASSWORD": g.Values["mcp-basic"],
				"JWT_SECRET_KEY": g.Values["mcp-jwt"], "PLATFORM_ADMIN_EMAIL": spec.AdminEmail,
				"PLATFORM_ADMIN_PASSWORD": g.AdminPassword, "AUTH_ENCRYPTION_SECRET": g.Values["mcp-encryption"],
			}},
			"global": map[string]any{"env": map[string]any{
				"PASSWORD_SALT": g.Values["password-salt"], "SUPER_USER_EMAIL": spec.AdminEmail, "SUPER_USER_PASSWORD": g.AdminPassword,
			}},
		},
		"keycloak": map[string]any{
			"externalDatabase": map[string]any{"user": "keycloak", "password": g.Values["postgres-keycloak"]},
			"auth":             map[string]any{"adminUser": spec.AdminEmail, "adminPassword": g.Values["keycloak-admin"]},
		},
		"daprExtra": map[string]any{"crypto": map[string]any{
			"symmetricKey": g.Values["dapr-symmetric"], "asymmetricKey": g.Values["dapr-asymmetric"], "budeventCryptoKey": g.Values["dapr-budevent"],
		}},
	}
}

func openSandboxSecrets(spec Spec, g GeneratedSecrets) map[string]any {
	return map[string]any{
		"registries": registry(spec),
		"opensandbox": map[string]any{"opensandbox-server": map[string]any{"server": map[string]any{
			"env": []any{map[string]any{"name": "OPENSANDBOX_SERVER_API_KEY", "value": g.Values["opensandbox-api"]}},
		}}},
	}
}

func budStudioSecrets(spec Spec, g GeneratedSecrets) map[string]any {
	return map[string]any{
		"registries":       registry(spec),
		"externalDatabase": map[string]any{"url": fmt.Sprintf("postgresql://bud:%s@pooler-rw.postgres:5432/budagent", g.Values["postgres-bud"])},
		"externalKeycloak": map[string]any{"clientSecret": g.Values["keycloak-budadmin"]},
	}
}

func argocdValues(spec Spec) map[string]any {
	host := "argocd." + spec.Domain
	return map[string]any{
		"global":  map[string]any{"domain": host},
		"ingress": map[string]any{"enabled": true, "className": spec.IngressClass, "isTraefik": spec.IsTraefik, "host": host},
		"repo":    map[string]any{"enabled": true, "url": manifestRepo(spec.TargetRepo)},
		"argo-cd": map[string]any{"configs": map[string]any{"cm": map[string]any{"url": "https://" + host}}},
		"projects": map[string]any{spec.Environment: map[string]any{
			"clusterResourceWhitelist": []any{map[string]any{"group": "*", "kind": "*"}},
			"destinations":             []any{map[string]any{"namespace": "*", "server": "https://kubernetes.default.svc"}},
			"sourceRepos":              []any{"*"},
		}},
	}
}

func httpsMode(spec Spec) string {
	if spec.TLS == TLSExternal {
		return "external"
	}
	return "internal"
}

func budValues(spec Spec) map[string]any {
	services := map[string]any{
		// These two are disabled by the Bud chart defaults. The supported
		// platform enables them: code-interpreter is backed by OpenSandbox and
		// Bud Studio remains the only installer-level optional application.
		"budeval":            map[string]any{"enabled": true},
		"budcodeinterpreter": map[string]any{"enabled": true},
		"budapp": map[string]any{
			"redirectFlow": map[string]any{
				"clientsByHost": map[string]any{
					"budadmin": map[string]any{
						"hosts":                   []any{`{{ include "bud.ingress.hosts.budadmin" . }}`},
						"allowedReturnUrlOrigins": []any{`{{ include "bud.ingress.url.budadmin" . }}`},
					},
					"budcustomer": map[string]any{
						"hosts":                   []any{`{{ include "bud.ingress.hosts.budcustomer" . }}`},
						"allowedReturnUrlOrigins": []any{`{{ include "bud.ingress.url.budcustomer" . }}`},
					},
					"budplayground": map[string]any{
						"hosts":                   []any{`{{ include "bud.ingress.hosts.budplayground" . }}`},
						"allowedReturnUrlOrigins": []any{`{{ include "bud.ingress.url.budplayground" . }}`},
					},
				},
			},
		},
	}
	return map[string]any{
		"ingress": map[string]any{"https": httpsMode(spec), "isTraefik": spec.IsTraefik, "className": spec.IngressClass},
		"global":  map[string]any{"ingress": map[string]any{"hosts": map[string]any{"root": spec.Domain}}},
		"externalServices": map[string]any{
			"oidc": map[string]any{"url": "https://auth." + spec.Domain + "/realms/bud-keycloak"},
			"s3":   map[string]any{"endpoint": "s3." + spec.Domain, "secure": true},
		},
		"storage": map[string]any{"budmodelRegistry": map[string]any{
			"className": spec.StorageClass, "size": fmt.Sprintf("%dGi", spec.ModelStorageGi),
		}},
		"microservices": services,
	}
}

func keycloakValues(spec Spec) map[string]any {
	domain := spec.Domain
	callback := "https://app." + domain + "/auth/redirect/callback"
	admin, customer, playground := "https://admin."+domain, "https://customer."+domain, "https://playground."+domain
	allFrontends := strings.Join([]string{admin, customer, playground}, "##")
	clients := map[string]any{
		"budadmin-web": map[string]any{
			"attributes":   map[string]any{"post.logout.redirect.uris": admin},
			"redirectUris": []any{callback}, "webOrigins": []any{"+"},
		},
		"budcustomer-web": map[string]any{
			"attributes":   map[string]any{"post.logout.redirect.uris": allFrontends},
			"redirectUris": []any{callback, customer + "/*"}, "webOrigins": []any{"+"},
		},
		"budplayground-web": map[string]any{
			"attributes":   map[string]any{"post.logout.redirect.uris": playground},
			"redirectUris": []any{callback}, "webOrigins": []any{"+"},
		},
		"mcp-gateway": map[string]any{
			"attributes":   map[string]any{"post.logout.redirect.uris": allFrontends},
			"redirectUris": []any{callback}, "webOrigins": []any{"+"},
		},
	}
	return map[string]any{
		"ingress": map[string]any{"enabled": true, "https": true, "className": spec.IngressClass, "isTraefik": spec.IsTraefik, "host": "auth." + domain},
		"realms":  map[string]any{"keycloak-bud-keycloak-realm": map[string]any{"clients": clients}},
	}
}

func certManagerValues(spec Spec) map[string]any {
	switch spec.TLS {
	case TLSACMEDNS01:
		return map[string]any{
			"cert-manager": map[string]any{"ingressShim": map[string]any{"defaultIssuerName": "letsencrypt-dns01"}},
			"issuers": map[string]any{"letsencrypt-dns01": map[string]any{"acme": map[string]any{
				"profile":             "tlsserver",
				"server":              "https://acme-v02.api.letsencrypt.org/directory",
				"privateKeySecretRef": map[string]any{"name": "letsencrypt-dns01-account-key"},
				"solvers": []any{map[string]any{"dns01": map[string]any{"cloudflare": map[string]any{
					"apiTokenSecretRef": map[string]any{"name": "cloudflare-api-token", "key": "api-token"},
				}}}},
			}}},
		}
	case TLSACMEHTTP01:
		return map[string]any{
			"cert-manager": map[string]any{"ingressShim": map[string]any{"defaultIssuerName": "letsencrypt-http01"}},
			"issuers": map[string]any{"letsencrypt-http01": map[string]any{"acme": map[string]any{
				"profile":             "tlsserver",
				"server":              "https://acme-v02.api.letsencrypt.org/directory",
				"privateKeySecretRef": map[string]any{"name": "letsencrypt-http01-account-key"},
				"solvers":             []any{map[string]any{"http01": map[string]any{"ingress": map[string]any{"class": spec.IngressClass}}}},
			}}},
		}
	case TLSSelfSigned:
		if spec.TrustedCAPEM == "" {
			return nil
		}
		return map[string]any{"bundles": map[string]any{"ca-pemstore": map[string]any{
			"sources": append(selfSignedCASources(), map[string]any{"inLine": spec.TrustedCAPEM}),
		}}}
	case TLSInternalCA:
		sources := []any{
			map[string]any{"useDefaultCAs": true},
			map[string]any{"secret": map[string]any{"name": "bud-internal-ca", "key": "tls.crt"}},
		}
		if spec.TrustedCAPEM != "" {
			sources = append(sources, map[string]any{"inLine": spec.TrustedCAPEM})
		}
		return map[string]any{
			"trust-manager": map[string]any{"enabled": true},
			"cert-manager":  map[string]any{"ingressShim": map[string]any{"defaultIssuerName": "bud-internal-ca"}},
			"issuers":       map[string]any{"bud-internal-ca": map[string]any{"ca": map[string]any{"secretName": "bud-internal-ca"}}},
			"bundles": map[string]any{"ca-pemstore": map[string]any{
				"sources": sources,
				"target": map[string]any{
					"configMap":         map[string]any{"key": "cafebabe-ca.pem"},
					"additionalFormats": map[string]any{"pkcs12": map[string]any{"key": "cafebabe-ca.p12", "password": ""}},
				},
			}},
		}
	default:
		return nil
	}
}

func selfSignedCASources() []any {
	return []any{
		map[string]any{"useDefaultCAs": true},
		map[string]any{"secret": map[string]any{"name": "selfsigned-ca-root", "key": "tls.crt"}},
	}
}

func seaweedValues(spec Spec) map[string]any {
	values := map[string]any{
		"ingress": map[string]any{"enabled": true, "https": true, "className": spec.IngressClass, "isTraefik": spec.IsTraefik, "host": "s3." + spec.Domain},
		"buckets": map[string]any{"bud-models-registry": map[string]any{"quota": map[string]any{"size": fmt.Sprintf("%dGi", spec.ModelStorageGi)}}},
	}
	if spec.IsOpenShift {
		values["seaweedfs-operator"] = map[string]any{"webhook": map[string]any{"podSecurityContext": nil}}
	}
	return values
}

func budStudioValues(spec Spec) map[string]any {
	model := strings.TrimSpace(spec.StudioModel)
	return map[string]any{
		"fullnameOverride": "bud-studio",
		"web":              map[string]any{"enabled": true},
		"ingress": map[string]any{
			"enabled": true, "className": spec.IngressClass, "host": "studio." + spec.Domain,
			"tlsSecretName": "bud-studio-tls", "annotations": map[string]any{"kubernetes.io/tls-acme": "true"},
		},
		"postgresql":       map[string]any{"enabled": false},
		"keycloak":         map[string]any{"enabled": false, "clientBootstrap": map[string]any{"enabled": false}},
		"externalKeycloak": map[string]any{"baseUrl": "https://auth." + spec.Domain, "realm": "bud-keycloak", "clientId": "budadmin-web"},
		"budGateway":       map[string]any{"enabled": true, "model": model},
	}
}

func manifestRepo(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" {
		u.User = nil
		return strings.TrimSuffix(u.String(), ".git")
	}
	return raw
}

// RepositoryURL strips embedded HTTP credentials before a repository is
// written to manifests or terminal output.
func RepositoryURL(raw string) string { return manifestRepo(raw) }
