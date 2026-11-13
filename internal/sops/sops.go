// Package sops encrypts and decrypts values files in-process, with no sops binary.
package sops

import (
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/decrypt"
	storeyaml "github.com/getsops/sops/v3/stores/yaml"
	"github.com/getsops/sops/v3/version"
	"sigs.k8s.io/yaml"
)

// SOPS decrypts values files in-process. FRD-020 §9.1: SOPS is itself Go, so
// budctl carries it as a library and needs no sops binary on the host.
//
// This matters for correctness, not just convenience. A SOPS-encrypted values
// file is still valid YAML — every secret is an ENC[...] string — so feeding it
// unmodified into the values merge does not error. It silently produces a
// values tree whose credentials are ciphertext, and every config check then
// judges the wrong input while reporting success.
type Client struct{}

func New() *Client { return &Client{} }

// EncryptYAML encrypts a plaintext YAML document for every supplied age
// recipient and returns a regular SOPS YAML document. The installer uses this
// instead of invoking the sops binary, preserving budctl's single-binary
// contract and ensuring plaintext secrets never need a temporary file.
func (Client) EncryptYAML(plain []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one age recipient is required")
	}
	store := storeyaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plain)
	if err != nil {
		return nil, fmt.Errorf("parse plaintext YAML: %w", err)
	}

	group := sops.KeyGroup{}
	seen := map[string]bool{}
	for _, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" || seen[recipient] {
			continue
		}
		key, err := sopsage.MasterKeyFromRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("age recipient %q: %w", recipient, err)
		}
		seen[recipient] = true
		group = append(group, key)
	}
	if len(group) == 0 {
		return nil, fmt.Errorf("at least one non-empty age recipient is required")
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         []sops.KeyGroup{group},
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
			Version:           version.Version,
		},
	}
	dataKey, errs := tree.GenerateDataKey()
	if len(errs) > 0 {
		return nil, fmt.Errorf("encrypt SOPS data key: %v", errs)
	}
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("encrypt SOPS values: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt SOPS MAC: %w", err)
	}
	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("encode SOPS YAML: %w", err)
	}
	return out, nil
}

// IsEncrypted reports whether a file carries a SOPS envelope.
func (Client) IsEncrypted(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "\nsops:") || strings.HasPrefix(s, "sops:") || strings.Contains(s, "ENC[")
}

// Decrypt returns the plaintext values of a SOPS file. A file that is not
// encrypted is returned as-is, so callers can pass any values file.
func (s Client) Decrypt(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !s.IsEncrypted(path) {
		var out map[string]any
		if err := yaml.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return out, nil
	}
	plain, err := decrypt.Data(raw, "yaml")
	if err != nil {
		return nil, fmt.Errorf("%s: %w (is your age identity a recipient? run `bud_sops` to print your public key)", path, err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(plain, &out); err != nil {
		return nil, fmt.Errorf("%s: decrypted but not valid YAML: %w", path, err)
	}
	// The sops metadata block is not part of the values tree.
	delete(out, "sops")
	return out, nil
}

// DecryptWith decrypts a SOPS YAML document with the given age identity
// only, ignoring SOPS_AGE_KEY and the operator's other keys, and returns the
// plaintext values.
func (Client) DecryptWith(data []byte, identity string) (map[string]any, error) {
	parsed, err := age.ParseIdentities(strings.NewReader(identity))
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	store := storeyaml.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, err
	}
	var dataKey []byte
	for _, group := range tree.Metadata.KeyGroups {
		for _, key := range group {
			mk, ok := key.(*sopsage.MasterKey)
			if !ok {
				continue
			}
			sopsage.ParsedIdentities(parsed).ApplyToMasterKey(mk)
			if dataKey, err = mk.Decrypt(); err == nil {
				break
			}
		}
		if dataKey != nil {
			break
		}
	}
	if dataKey == nil {
		return nil, fmt.Errorf("the age identity is not a recipient of this document")
	}
	if _, err := tree.Decrypt(dataKey, aes.NewCipher()); err != nil {
		return nil, err
	}
	plain, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := yaml.Unmarshal(plain, &out); err != nil {
		return nil, err
	}
	return out, nil
}
