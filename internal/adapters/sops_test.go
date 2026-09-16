package adapters

import (
	"bytes"
	"testing"

	"filippo.io/age"
	"github.com/getsops/sops/v3/decrypt"
)

func TestEncryptYAMLRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("username: robot\npassword: do-not-commit-this\n")
	encrypted, err := (SOPS{}).EncryptYAML(plain, []string{identity.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("do-not-commit-this")) {
		t.Fatal("encrypted document contains the plaintext secret")
	}
	t.Setenv("SOPS_AGE_KEY", identity.String())
	decrypted, err := decrypt.Data(encrypted, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(decrypted, []byte("password: do-not-commit-this")) {
		t.Fatalf("unexpected decrypted data: %s", decrypted)
	}
}
