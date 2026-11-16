package spec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"filippo.io/age"
)

type GeneratedSecrets struct {
	AgeIdentity   string            `yaml:"ageIdentity"`
	AgeRecipient  string            `yaml:"ageRecipient"`
	AdminPassword string            `yaml:"adminPassword"`
	Values        map[string]string `yaml:"values"`
	RSAPrivate    string            `yaml:"rsaPrivate"`
	RSAPublic     string            `yaml:"rsaPublic"`
}

func GenerateSecrets(adminPassword string) (GeneratedSecrets, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return GeneratedSecrets{}, fmt.Errorf("generate age identity: %w", err)
	}
	if adminPassword == "" {
		adminPassword, err = randomToken(24)
		if err != nil {
			return GeneratedSecrets{}, err
		}
	}
	privatePassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	privatePEM, publicPEM, err := generateRSA(privatePassword)
	if err != nil {
		return GeneratedSecrets{}, err
	}

	names := []string{
		"postgres-bud", "postgres-keycloak", "postgres-seaweedfs",
		"clickhouse", "kafka", "mongodb", "valkey", "s3-access", "s3-secret",
		"keycloak-admin", "keycloak-budadmin", "keycloak-budcustomer",
		"keycloak-budplayground", "keycloak-mcpgateway", "keycloak-budapp-admin",
		"app-api", "oidc-mcpgateway", "novu-encryption", "novu-admin",
		"jwt", "aes", "session", "password-salt", "notify-store", "notify-jwt",
		"mcp-basic", "mcp-jwt", "mcp-encryption", "cluster-token", "opensandbox-api",
	}
	values := make(map[string]string, len(names)+1)
	for _, name := range names {
		value, err := randomToken(32)
		if err != nil {
			return GeneratedSecrets{}, err
		}
		values[name] = value
	}
	values["rsa-password"] = privatePassword
	// The chart documents AES_KEY_HEX as hex, rather than arbitrary base64.
	aesBytes := make([]byte, 32)
	if _, err := rand.Read(aesBytes); err != nil {
		return GeneratedSecrets{}, fmt.Errorf("generate AES key: %w", err)
	}
	values["aes"] = hex.EncodeToString(aesBytes)
	if err := RepairSecrets(&GeneratedSecrets{Values: values}); err != nil {
		return GeneratedSecrets{}, err
	}

	return GeneratedSecrets{
		AgeIdentity:   id.String(),
		AgeRecipient:  id.Recipient().String(),
		AdminPassword: adminPassword,
		Values:        values,
		RSAPrivate:    privatePEM,
		RSAPublic:     publicPEM,
	}, nil
}

func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateRSA(password string) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}
	privatePEM, err := encryptRSAKey(key, password)
	if err != nil {
		return "", "", err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal RSA public key: %w", err)
	}
	return privatePEM, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
}

func encryptRSAKey(key *rsa.PrivateKey, password string) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal RSA key: %w", err)
	}
	privatePEM, err := encryptPKCS8(der, password)
	if err != nil {
		return "", fmt.Errorf("encrypt RSA key: %w", err)
	}
	return privatePEM, nil
}

// repairRSAKey re-wraps a key that an earlier budctl wrote as legacy
// "Proc-Type: 4,ENCRYPTED" PEM into encrypted PKCS#8. WaaV refuses the legacy
// form ("PEM headers disallowed by RFC7468") and never starts. The key and its
// password stay the same, so the public key and everything signed still match.
func repairRSAKey(g *GeneratedSecrets) error {
	block, _ := pem.Decode([]byte(g.RSAPrivate))
	if block == nil || !x509.IsEncryptedPEMBlock(block) {
		return nil
	}
	der, err := x509.DecryptPEMBlock(block, []byte(g.Values["rsa-password"]))
	if err != nil {
		return fmt.Errorf("decrypt cached RSA key: %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return fmt.Errorf("parse cached RSA key: %w", err)
	}
	g.RSAPrivate, err = encryptRSAKey(key, g.Values["rsa-password"])
	return err
}

// Novu accepts a password only if it is 8 to 64 characters with a digit, a
// lowercase letter, an uppercase letter and one of these symbols. budnotify
// creates the Novu admin with novu-admin at startup, and crash-loops when Novu
// refuses it.
const novuSymbols = "#?!@$%^&*()-"

func isNovuPassword(s string) bool {
	return len(s) >= 8 && len(s) <= 64 &&
		strings.ContainsAny(s, "0123456789") &&
		strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") &&
		strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
		strings.ContainsAny(s, novuSymbols)
}

func novuPassword() (string, error) {
	for {
		token, err := randomToken(32)
		if err != nil {
			return "", err
		}
		// NOTE: [AGENT]: "_" is the one URL-safe character outside Novu's
		// symbol set.
		token = strings.ReplaceAll(token, "_", "-")
		if isNovuPassword(token) {
			return token, nil
		}
	}
}

// Some of the Bud chart's keys have fixed formats. These are used as raw
// AES-256 keys, so they must be exactly 32 characters: the Dapr symmetric and
// budevent keys (or the chart refuses to render), and the Novu and budnotify
// store encryption keys (or Novu exits at startup: "STORE_ENCRYPTION_KEY:
// Expected to be string 32 char long"). The Dapr asymmetric key is read as a
// PEM private key.
const aesKeyLength = 32

var aesKeys = []string{"dapr-symmetric", "dapr-budevent", "novu-encryption", "notify-store"}

// RepairSecrets fills in the fixed-format keys, or replaces cached ones in a
// format the chart rejects. Earlier releases generated them as 43-character
// tokens, which the chart or the service rejects, so nothing can have been
// encrypted under them and replacing them loses nothing. A valid key is never
// replaced: rotating it would orphan every credential stored under it.
func RepairSecrets(g *GeneratedSecrets) error {
	if g.Values == nil {
		g.Values = map[string]string{}
	}
	if err := repairRSAKey(g); err != nil {
		return err
	}
	// NOTE: [AGENT]: A password Novu refuses was never set on any account, so
	// replacing it loses nothing; one it accepts is the live admin login and
	// is kept.
	if !isNovuPassword(g.Values["novu-admin"]) {
		password, err := novuPassword()
		if err != nil {
			return err
		}
		g.Values["novu-admin"] = password
	}
	for _, name := range aesKeys {
		if len(g.Values[name]) != aesKeyLength {
			// 24 random bytes encode to exactly 32 URL-safe characters.
			key, err := randomToken(24)
			if err != nil {
				return err
			}
			g.Values[name] = key
		}
	}
	if !isPrivateKeyPEM(g.Values["dapr-asymmetric"]) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("generate Dapr RSA key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		g.Values["dapr-asymmetric"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	// The Bud chart (1.4.0+) fails to render without kvCacheSaltKey, and
	// budgateway refuses to start unless it is standard base64 of at least 32
	// bytes. Every tenant's vLLM prefix-cache salt is derived from it, so a
	// valid key is never rotated.
	if !isKVCacheSalt(g.Values[kvCacheSaltKey]) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate KV-cache salt key: %w", err)
		}
		g.Values[kvCacheSaltKey] = base64.StdEncoding.EncodeToString(b)
	}
	// Tokens later chart releases require, which state saved by an earlier
	// budctl does not have. Only a missing one is generated.
	for _, name := range addedTokens {
		if g.Values[name] == "" {
			token, err := randomToken(32)
			if err != nil {
				return err
			}
			g.Values[name] = token
		}
	}
	return nil
}

// addedTokens are plain random tokens introduced after the first release:
// waav-front-api is the WaaV front model's API key, required from Bud chart
// 1.4.0 (the chart fails the render without it).
var addedTokens = []string{"waav-front-api"}

const kvCacheSaltKey = "kv-cache-salt"

func isKVCacheSalt(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) >= 32
}

func isPrivateKeyPEM(s string) bool {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return false
	}
	_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return err == nil
}
