package install

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// WriteRecoveryKey creates the SOPS age identity file outside Git. It never
// overwrites: a different key at the same path belongs to another
// installation.
func WriteRecoveryKey(path string, key []byte) error {
	if path == "" {
		return fmt.Errorf("a recovery key path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create recovery key without overwriting: %w", err)
	}
	if _, err = f.Write(key); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// EnsureRecoveryKey preserves retryability without silently accepting a
// different key at the same path. An existing matching key is a successful
// resume; any mismatch requires an explicit new path.
func EnsureRecoveryKey(path string, key []byte) error {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return WriteRecoveryKey(path, key)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(body, key) {
		return fmt.Errorf("recovery key %s belongs to a different installation state", path)
	}
	return os.Chmod(path, 0o600)
}

// EnsureCACertificate writes the public self-signed root beside the recovery
// material. A different certificate at the same path is not replaced silently:
// changing a trust anchor should always be an explicit operator decision.
func EnsureCACertificate(path string, certificate []byte) error {
	if path == "" || len(bytes.TrimSpace(certificate)) == 0 {
		return fmt.Errorf("a CA certificate path and certificate are required")
	}
	if body, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(certificate)) {
			return fmt.Errorf("CA certificate %s contains a different trust anchor", path)
		}
		return os.Chmod(path, 0o644)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".budctl-ca-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(certificate); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}
