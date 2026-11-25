package tunnel

import (
	"fmt"
	"io"
	"sync/atomic"
)

// EncryptionMode is the per-tunnel payload protection mode.
type EncryptionMode string

const (
	// ModeEncrypted applies the existing frp stream encryption wrapper.
	ModeEncrypted EncryptionMode = "encrypted"
	// ModePlaintext disables tunnel payload encryption. It should only be used
	// on trusted networks or when global TLS already protects the connection.
	ModePlaintext EncryptionMode = "plaintext"
)

// Switch is a concurrency-safe network profile and encryption mode selector.
// Changes affect tunnels wrapped after the call. Established streams keep the
// wire mode negotiated when they were created, which avoids mid-stream protocol
// desynchronization and remains compatible with existing frp peers.
type Switch struct {
	network   atomic.Value // NetworkProfile
	encrypted atomic.Bool
}

// NewSwitch creates a selector for one of the three network profiles.
func NewSwitch(network NetworkProfile, encrypted bool) *Switch {
	s := &Switch{}
	p, err := ParseNetworkProfile(string(network))
	if err != nil {
		p = NetworkWAN
	}
	s.network.Store(p)
	s.encrypted.Store(encrypted)
	return s
}

// SetNetwork switches the active network profile.
func (s *Switch) SetNetwork(network NetworkProfile) error {
	p, err := ParseNetworkProfile(string(network))
	if err != nil {
		return err
	}
	s.network.Store(p)
	return nil
}

// Network returns the active canonical profile.
func (s *Switch) Network() NetworkProfile {
	p, _ := s.network.Load().(NetworkProfile)
	if p == "" {
		return NetworkWAN
	}
	return p
}

// SetEncryption switches between encrypted and plaintext wrapping for new tunnels.
func (s *Switch) SetEncryption(enabled bool) {
	s.encrypted.Store(enabled)
}

// SetMode sets the encryption mode using the named mode constants.
func (s *Switch) SetMode(mode EncryptionMode) error {
	switch mode {
	case ModeEncrypted:
		s.encrypted.Store(true)
	case ModePlaintext:
		s.encrypted.Store(false)
	default:
		return fmt.Errorf("unsupported encryption mode %q", mode)
	}
	return nil
}

// EncryptionEnabled reports whether new tunnels are encrypted.
func (s *Switch) EncryptionEnabled() bool {
	return s.encrypted.Load()
}

// Mode returns the named encryption mode.
func (s *Switch) Mode() EncryptionMode {
	if s.encrypted.Load() {
		return ModeEncrypted
	}
	return ModePlaintext
}

// Snapshot returns both selectors as values convenient for tests and logging.
func (s *Switch) Snapshot() (NetworkProfile, EncryptionMode) {
	return s.Network(), s.Mode()
}

// Wrap applies the currently selected network profile and encryption mode.
// Compression remains per-tunnel configuration; when adaptive is false the
// historical Snappy writer is used.
func (s *Switch) Wrap(rwc io.ReadWriteCloser, key []byte, compressionEnabled, adaptive bool) (io.ReadWriteCloser, func(), error) {
	network, mode := s.Snapshot()
	return Wrap(rwc, Options{
		Encryption: mode == ModeEncrypted,
		Key:        key,
		Compression: CompressionOptions{
			Enabled:  compressionEnabled,
			Adaptive: adaptive,
			Network:  network,
		},
	})
}
