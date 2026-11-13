package components

import (
	"fmt"
	"strings"

	"github.com/BudEcosystem/budctl/install/spec"
)

// The per-environment values and credentials each component derives from the
// Spec. Shared defaults belong in base/, not here.

func clickhouseSecrets(_ spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{"users": map[string]any{"bud": map[string]any{"password": g.Values["clickhouse"]}}}
}

func kafkaSecrets(_ spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{"users": map[string]any{"bud": map[string]any{"password": g.Values["kafka"]}}}
}

func mongodbSecrets(_ spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{"users": map[string]any{"bud_novu": map[string]any{"password": g.Values["mongodb"]}}}
}

func valkeySecrets(_ spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{"auth": map[string]any{"password": g.Values["valkey"]}}
}

// certManagerSecrets carries the DNS-01 token or the internal issuing CA; the
// other TLS modes need no secret.
func certManagerSecrets(s spec.Spec, _ spec.GeneratedSecrets) map[string]any {
	switch s.TLS {
	case spec.TLSACMEDNS01:
		return map[string]any{
			"secrets": map[string]any{"cloudflare-api-token": map[string]any{"api-token": s.CloudflareToken}},
		}
	case spec.TLSInternalCA:
		return map[string]any{
			"secrets": map[string]any{"bud-internal-ca": map[string]any{
				"tls.crt": s.IssuerCACertPEM,
				"tls.key": s.IssuerCAKeyPEM,
			}},
		}
	}
	return nil
}

func registry(s spec.Spec) map[string]any {
	return map[string]any{"registry.bud.studio": map[string]any{
		"username": s.RegistryUser, "password": s.RegistryPassword,
	}}
}

func argocdSecrets(s spec.Spec, generated spec.GeneratedSecrets) map[string]any {
	out := map[string]any{
		"sopsAgeKeys": generated.AgeIdentity,
		"argo-cd": map[string]any{"configs": map[string]any{"repositories": map[string]any{
			"bud-charts": map[string]any{
				"name": "bud-charts", "type": "helm", "url": "registry.bud.studio/charts",
				"enableOCI": "true", "username": s.RegistryUser, "password": s.RegistryPassword,
			},
		}}},
	}
	if strings.TrimSpace(s.RepoSSHPrivateKey) != "" {
		out["repo"] = map[string]any{"sshPrivateKey": s.RepoSSHPrivateKey}
	}
	return out
}

func postgresSecrets(_ spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{"users": map[string]any{
		"bud":       map[string]any{"password": g.Values["postgres-bud"]},
		"keycloak":  map[string]any{"password": g.Values["postgres-keycloak"]},
		"seaweedfs": map[string]any{"password": g.Values["postgres-seaweedfs"]},
	}}
}

func seaweedSecrets(_ spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{
		"postgres": map[string]any{"password": g.Values["postgres-seaweedfs"]},
		"identity": map[string]any{"bud": map[string]any{
			"accessKey": g.Values["s3-access"], "secretKey": g.Values["s3-secret"],
		}},
	}
}

func keycloakSecrets(s spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{
		"password":   g.Values["keycloak-admin"],
		"postgres":   map[string]any{"password": g.Values["postgres-keycloak"]},
		"registries": registry(s),
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

func budSecrets(s spec.Spec, g spec.GeneratedSecrets) map[string]any {
	dbs := map[string]any{}
	for _, name := range postgresDatabases {
		user, password := "bud", g.Values["postgres-bud"]
		if name == "keycloak" {
			user, password = "keycloak", g.Values["postgres-keycloak"]
		}
		dbs[name] = map[string]any{"username": user, "password": password}
	}
	return map[string]any{
		"registries":  registry(s),
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
		"novuExtra": map[string]any{"email": s.AdminEmail, "password": g.Values["novu-admin"]},
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
				"BASIC_AUTH_USER": s.AdminEmail, "BASIC_AUTH_PASSWORD": g.Values["mcp-basic"],
				"JWT_SECRET_KEY": g.Values["mcp-jwt"], "PLATFORM_ADMIN_EMAIL": s.AdminEmail,
				"PLATFORM_ADMIN_PASSWORD": g.AdminPassword, "AUTH_ENCRYPTION_SECRET": g.Values["mcp-encryption"],
			}},
			"global": map[string]any{"env": map[string]any{
				"PASSWORD_SALT": g.Values["password-salt"], "SUPER_USER_EMAIL": s.AdminEmail, "SUPER_USER_PASSWORD": g.AdminPassword,
			}},
		},
		"keycloak": map[string]any{
			"externalDatabase": map[string]any{"user": "keycloak", "password": g.Values["postgres-keycloak"]},
			"auth":             map[string]any{"adminUser": s.AdminEmail, "adminPassword": g.Values["keycloak-admin"]},
		},
		"daprExtra": map[string]any{"crypto": map[string]any{
			"symmetricKey": g.Values["dapr-symmetric"], "asymmetricKey": g.Values["dapr-asymmetric"], "budeventCryptoKey": g.Values["dapr-budevent"],
		}},
	}
}

func openSandboxSecrets(s spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{
		"registries": registry(s),
		"opensandbox": map[string]any{"opensandbox-server": map[string]any{"server": map[string]any{
			"env": []any{map[string]any{"name": "OPENSANDBOX_SERVER_API_KEY", "value": g.Values["opensandbox-api"]}},
		}}},
	}
}

func budStudioSecrets(s spec.Spec, g spec.GeneratedSecrets) map[string]any {
	return map[string]any{
		"registries":       registry(s),
		"externalDatabase": map[string]any{"url": fmt.Sprintf("postgresql://bud:%s@pooler-rw.postgres:5432/budagent", g.Values["postgres-bud"])},
		"externalKeycloak": map[string]any{"clientSecret": g.Values["keycloak-budadmin"]},
	}
}

// The Bud charts are written for OpenShift, which assigns every pod a numeric
// user: they null the runAsUser of images whose own USER is a name (redis,
// nobody) while keeping runAsNonRoot. Anywhere else the kubelet then refuses
// to start the container ("image has non-numeric user"), so budctl gives
// those pods the numeric user their image already runs as.
const (
	redisUID  = 999   // the redis image's "redis" user
	nobodyUID = 65534 // "nobody", which the Prometheus images run as
)

func argocdValues(s spec.Spec) map[string]any {
	host := "argocd." + s.Domain
	argo := map[string]any{"configs": map[string]any{"cm": map[string]any{"url": "https://" + host}}}
	if !s.IsOpenShift {
		argo["redis"] = map[string]any{"securityContext": map[string]any{"runAsUser": redisUID}}
	}
	return map[string]any{
		"global":  map[string]any{"domain": host},
		"ingress": map[string]any{"enabled": true, "className": s.IngressClass, "isTraefik": s.IsTraefik, "host": host},
		"repo":    map[string]any{"enabled": true, "url": spec.RepositoryURL(s.TargetRepo)},
		"argo-cd": argo,
		"projects": map[string]any{s.Environment: map[string]any{
			"clusterResourceWhitelist": []any{map[string]any{"group": "*", "kind": "*"}},
			"destinations":             []any{map[string]any{"namespace": "*", "server": "https://kubernetes.default.svc"}},
			"sourceRepos":              []any{"*"},
		}},
	}
}

func httpsMode(s spec.Spec) string {
	if s.TLS == spec.TLSExternal {
		return "external"
	}
	return "internal"
}

func budValues(s spec.Spec) map[string]any {
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
	values := map[string]any{
		"ingress": map[string]any{"https": httpsMode(s), "isTraefik": s.IsTraefik, "className": s.IngressClass},
		"global":  map[string]any{"ingress": map[string]any{"hosts": map[string]any{"root": s.Domain}}},
		"externalServices": map[string]any{
			"oidc": map[string]any{"url": "https://auth." + s.Domain + "/realms/bud-keycloak"},
			"s3":   map[string]any{"endpoint": "s3." + s.Domain, "secure": true},
		},
		"storage": map[string]any{"budmodelRegistry": map[string]any{
			"className": s.StorageClass, "size": fmt.Sprintf("%dGi", s.ModelStorageGi),
		}},
		"microservices": services,
	}
	if !s.IsOpenShift {
		values["prometheus"] = map[string]any{"server": map[string]any{"securityContext": map[string]any{
			"runAsUser": nobodyUID, "runAsGroup": nobodyUID, "fsGroup": nobodyUID,
		}}}
	}
	return values
}

func keycloakValues(s spec.Spec) map[string]any {
	domain := s.Domain
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
		"ingress": map[string]any{"enabled": true, "https": true, "className": s.IngressClass, "isTraefik": s.IsTraefik, "host": "auth." + domain},
		"realms":  map[string]any{"keycloak-bud-keycloak-realm": map[string]any{"clients": clients}},
	}
}

func certManagerValues(s spec.Spec) map[string]any {
	switch s.TLS {
	case spec.TLSACMEDNS01:
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
	case spec.TLSACMEHTTP01:
		return map[string]any{
			"cert-manager": map[string]any{"ingressShim": map[string]any{"defaultIssuerName": "letsencrypt-http01"}},
			"issuers": map[string]any{"letsencrypt-http01": map[string]any{"acme": map[string]any{
				"profile":             "tlsserver",
				"server":              "https://acme-v02.api.letsencrypt.org/directory",
				"privateKeySecretRef": map[string]any{"name": "letsencrypt-http01-account-key"},
				"solvers":             []any{map[string]any{"http01": map[string]any{"ingress": map[string]any{"class": s.IngressClass}}}},
			}}},
		}
	case spec.TLSSelfSigned:
		if s.TrustedCAPEM == "" {
			return nil
		}
		return map[string]any{"bundles": map[string]any{"ca-pemstore": map[string]any{
			"sources": append(selfSignedCASources(), map[string]any{"inLine": s.TrustedCAPEM}),
		}}}
	case spec.TLSInternalCA:
		sources := []any{
			map[string]any{"useDefaultCAs": true},
			map[string]any{"secret": map[string]any{"name": "bud-internal-ca", "key": "tls.crt"}},
		}
		if s.TrustedCAPEM != "" {
			sources = append(sources, map[string]any{"inLine": s.TrustedCAPEM})
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

func seaweedValues(s spec.Spec) map[string]any {
	values := map[string]any{
		"ingress": map[string]any{"enabled": true, "https": true, "className": s.IngressClass, "isTraefik": s.IsTraefik, "host": "s3." + s.Domain},
		"buckets": map[string]any{"bud-models-registry": map[string]any{"quota": map[string]any{"size": fmt.Sprintf("%dGi", s.ModelStorageGi)}}},
	}
	switch {
	case s.IsOpenShift:
		values["seaweedfs-operator"] = map[string]any{"webhook": map[string]any{"podSecurityContext": nil}}
	case s.TLS != spec.TLSExternal:
		// The operator's own webhook certificate otherwise comes from PostSync
		// patch Jobs whose curl image has a non-numeric user, so they never
		// start. cert-manager is installed whenever TLS is not external, and
		// issues it instead.
		values["seaweedfs-operator"] = map[string]any{"webhook": map[string]any{"certManager": map[string]any{"enabled": true}}}
	}
	return values
}

func budStudioValues(s spec.Spec) map[string]any {
	model := strings.TrimSpace(s.StudioModel)
	return map[string]any{
		"fullnameOverride": "bud-studio",
		"web":              map[string]any{"enabled": true},
		"ingress": map[string]any{
			"enabled": true, "className": s.IngressClass, "host": "studio." + s.Domain,
			"tlsSecretName": "bud-studio-tls", "annotations": map[string]any{"kubernetes.io/tls-acme": "true"},
		},
		"postgresql":       map[string]any{"enabled": false},
		"keycloak":         map[string]any{"enabled": false, "clientBootstrap": map[string]any{"enabled": false}},
		"externalKeycloak": map[string]any{"baseUrl": "https://auth." + s.Domain, "realm": "bud-keycloak", "clientId": "budadmin-web"},
		"budGateway":       map[string]any{"enabled": true, "model": model},
	}
}
