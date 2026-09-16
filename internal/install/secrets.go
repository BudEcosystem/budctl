package install

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

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
		"mcp-basic", "mcp-jwt", "mcp-encryption", "dapr-symmetric",
		"dapr-asymmetric", "dapr-budevent", "cluster-token", "opensandbox-api",
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
	privateDER := x509.MarshalPKCS1PrivateKey(key)
	privateBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privateDER, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return "", "", fmt.Errorf("encrypt RSA key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal RSA public key: %w", err)
	}
	return string(pem.EncodeToMemory(privateBlock)), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
}
