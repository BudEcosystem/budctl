package install

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

const stateVersion = 1

type State struct {
	Version      int               `yaml:"version"`
	UpdatedAt    time.Time         `yaml:"updatedAt"`
	Phase        string            `yaml:"phase"`
	Spec         Spec              `yaml:"spec"`
	Secrets      *GeneratedSecrets `yaml:"secrets,omitempty"`
	RecoveryPath string            `yaml:"recoveryPath,omitempty"`
	CAPath       string            `yaml:"caPath,omitempty"`
	Commit       string            `yaml:"commit,omitempty"`
}

func DefaultStatePath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user configuration directory: %w", err)
	}
	return filepath.Join(root, "budctl", "install-state.age"), nil
}

func StateKeyPath(statePath string) string { return statePath + ".agekey" }

// LoadState decrypts the last installer session. A missing state is a normal
// first run; a present but unreadable state is reported so it is never silently
// replaced along with the credentials required to resume.
func LoadState(path string) (State, bool, error) {
	ciphertext, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	identity, err := loadStateIdentity(StateKeyPath(path))
	if err != nil {
		return State{}, false, err
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return State{}, false, fmt.Errorf("decrypt installer state: %w", err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		return State{}, false, err
	}
	var state State
	if err := yaml.Unmarshal(plain, &state); err != nil {
		return State{}, false, fmt.Errorf("parse installer state: %w", err)
	}
	if state.Version != stateVersion {
		return State{}, false, fmt.Errorf("installer state version %d is not supported", state.Version)
	}
	return state, true, nil
}

// SaveState atomically encrypts a resumable installation session with a local
// age identity. Both the state and its identity are owner-readable only.
func SaveState(path string, state State) error {
	if path == "" {
		return fmt.Errorf("installer state path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	identity, err := ensureStateIdentity(StateKeyPath(path))
	if err != nil {
		return err
	}
	state.Version = stateVersion
	state.UpdatedAt = time.Now().UTC()
	plain, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, identity.Recipient())
	if err != nil {
		return err
	}
	if _, err := writer.Write(plain); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return atomicPrivateWrite(path, ciphertext.Bytes())
}

func ensureStateIdentity(path string) (*age.X25519Identity, error) {
	identity, err := loadStateIdentity(path)
	if err == nil {
		return identity, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	identity, err = age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if err := atomicPrivateWrite(path, []byte(identity.String()+"\n")); err != nil {
		return nil, err
	}
	return identity, nil
}

func loadStateIdentity(path string) (*age.X25519Identity, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	identity, err := age.ParseX25519Identity(string(bytes.TrimSpace(body)))
	if err != nil {
		return nil, fmt.Errorf("parse installer state identity %s: %w", path, err)
	}
	return identity, nil
}

func atomicPrivateWrite(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".budctl-state-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
