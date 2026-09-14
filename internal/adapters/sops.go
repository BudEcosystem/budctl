package adapters

import (
	"fmt"
	"os"
	"strings"

	"github.com/getsops/sops/v3/decrypt"
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
type SOPS struct{}

func NewSOPS() *SOPS { return &SOPS{} }

// IsEncrypted reports whether a file carries a SOPS envelope.
func (SOPS) IsEncrypted(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "\nsops:") || strings.HasPrefix(s, "sops:") || strings.Contains(s, "ENC[")
}

// Decrypt returns the plaintext values of a SOPS file. A file that is not
// encrypted is returned as-is, so callers can pass any values file.
func (s SOPS) Decrypt(path string) (map[string]any, error) {
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
