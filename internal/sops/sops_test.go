package sops

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
	encrypted, err := (Client{}).EncryptYAML(plain, []string{identity.Recipient().String()})
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

func TestDecryptWithUsesOnlyTheGivenIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := (Client{}).EncryptYAML([]byte("password: s3cret\n"), []string{identity.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (Client{}).DecryptWith(encrypted, identity.String())
	if err != nil {
		t.Fatal(err)
	}
	if got["password"] != "s3cret" {
		t.Fatalf("decrypted %v", got)
	}
	if _, err := (Client{}).DecryptWith(encrypted, other.String()); err == nil {
		t.Fatal("a document decrypted with an identity that is not a recipient")
	}
}
