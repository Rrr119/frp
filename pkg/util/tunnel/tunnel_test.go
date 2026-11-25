package tunnel

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
)

type readWriteCloserBuffer struct {
	bytes.Buffer
}

func (b *readWriteCloserBuffer) Close() error { return nil }

func TestAdaptiveWriterRoundTripWithLegacySnappyReader(t *testing.T) {
	payloads := map[string][]byte{
		"small":  []byte("hello tunnel"),
		"text":   bytes.Repeat([]byte("frp tunnel encryption and adaptive compression "), 512),
		"binary": make([]byte, 128*1024),
	}
	_, err := rand.Read(payloads["binary"])
	require.NoError(t, err)

	for _, profile := range Profiles() {
		for name, payload := range payloads {
			t.Run(fmt.Sprintf("%s/%s", profile, name), func(t *testing.T) {
				var wire bytes.Buffer
				writer := NewAdaptiveWriter(&wire, profile)
				n, err := writer.Write(payload)
				require.NoError(t, err)
				require.Equal(t, len(payload), n)

				got, err := io.ReadAll(snappy.NewReader(bytes.NewReader(wire.Bytes())))
				require.NoError(t, err)
				require.Equal(t, payload, got)
			})
		}
	}
}

func TestAdaptiveWriterChoosesFramesByCompressibility(t *testing.T) {
	t.Run("random data bypasses snappy encoding", func(t *testing.T) {
		payload := make([]byte, 8192)
		_, err := rand.Read(payload)
		require.NoError(t, err)

		var wire bytes.Buffer
		writer := NewAdaptiveWriter(&wire, NetworkWAN)
		_, err = writer.Write(payload)
		require.NoError(t, err)

		stats := writer.Stats()
		require.Zero(t, stats.CompressedBlocks)
		require.NotZero(t, stats.RawBlocks)
		require.NotZero(t, stats.SkippedBlocks)
		require.GreaterOrEqual(t, stats.PayloadBytes, uint64(len(payload)))
		require.LessOrEqual(t, stats.WireBytes, uint64(len(payload)+len(snappyMagicChunk)+snappyFrameHeader))
	})

	t.Run("repetitive text is compressed", func(t *testing.T) {
		payload := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 512)

		var wire bytes.Buffer
		writer := NewAdaptiveWriter(&wire, NetworkLossy)
		_, err := writer.Write(payload)
		require.NoError(t, err)

		stats := writer.Stats()
		require.NotZero(t, stats.CompressedBlocks)
		require.Less(t, wire.Len(), len(payload))
	})
}

func TestWrapRoundTripAcrossNetworksAndModes(t *testing.T) {
	payload := bytes.Repeat([]byte("per-tunnel encryption plus network aware compression "), 256)
	randomPayload := make([]byte, 4096)
	_, err := rand.Read(randomPayload)
	require.NoError(t, err)

	for _, profile := range Profiles() {
		for _, encrypted := range []bool{false, true} {
			for _, adaptive := range []bool{false, true} {
				name := fmt.Sprintf("%s/encrypted=%t/adaptive=%t", profile, encrypted, adaptive)
				t.Run(name, func(t *testing.T) {
					raw := &readWriteCloserBuffer{}
					rwc, recycle, err := Wrap(raw, Options{
						Encryption: encrypted,
						Key:        []byte("tunnel-key"),
						Compression: CompressionOptions{
							Enabled:  true,
							Adaptive: adaptive,
							Network:  profile,
						},
					})
					require.NoError(t, err)
					defer recycle()

					_, err = rwc.Write(payload)
					require.NoError(t, err)
					_, err = rwc.Write(randomPayload)
					require.NoError(t, err)

					wire := append([]byte(nil), raw.Bytes()...)
					got, err := io.ReadAll(rwc)
					require.NoError(t, err)
					require.Equal(t, append(append([]byte{}, payload...), randomPayload...), got)

					if !encrypted && adaptive {
						require.True(t, bytes.HasPrefix(wire, []byte(snappyMagicChunk)))
					}
					if encrypted {
						require.False(t, bytes.Contains(wire, payload))
					}
				})
			}
		}
	}
}

func TestSwitchThreeNetworksAndEncryptionModes(t *testing.T) {
	s := NewSwitch("", true)
	require.Equal(t, NetworkWAN, s.Network())
	require.Equal(t, ModeEncrypted, s.Mode())

	for _, profile := range Profiles() {
		require.NoError(t, s.SetNetwork(profile))
		require.Equal(t, profile, s.Network())

		require.NoError(t, s.SetMode(ModePlaintext))
		require.False(t, s.EncryptionEnabled())
		require.Equal(t, ModePlaintext, s.Mode())

		require.NoError(t, s.SetMode(ModeEncrypted))
		require.True(t, s.EncryptionEnabled())
		require.Equal(t, ModeEncrypted, s.Mode())

		s.SetEncryption(false)
		_, mode := s.Snapshot()
		require.Equal(t, ModePlaintext, mode)
	}

	require.NoError(t, s.SetNetwork("4G"))
	require.Equal(t, NetworkLossy, s.Network())
	require.NoError(t, s.SetNetwork("ethernet"))
	require.Equal(t, NetworkLAN, s.Network())
	require.Error(t, s.SetNetwork("saturn-network"))
	require.Error(t, s.SetMode("rot13"))
}

func TestSwitchConcurrentUpdates(t *testing.T) {
	s := NewSwitch(NetworkLAN, true)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			profiles := Profiles()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.SetNetwork(profiles[(i+int(time.Now().UnixNano()))%len(profiles)])
					s.SetEncryption(i%2 == 0)
					_, _ = s.Snapshot()
				}
			}
		}(i)
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestSwitchWrapChangesWireModeForEachNetwork(t *testing.T) {
	payload := []byte("switch tunnel mode without restarting the selector")
	s := NewSwitch(NetworkLAN, true)

	for _, profile := range Profiles() {
		require.NoError(t, s.SetNetwork(profile))
		for _, mode := range []EncryptionMode{ModeEncrypted, ModePlaintext} {
			require.NoError(t, s.SetMode(mode))

			raw := &readWriteCloserBuffer{}
			rwc, recycle, err := s.Wrap(raw, []byte("key"), true, true)
			require.NoError(t, err)

			_, err = rwc.Write(payload)
			require.NoError(t, err)
			wire := append([]byte(nil), raw.Bytes()...)

			got, err := io.ReadAll(rwc)
			require.NoError(t, err)
			require.Equal(t, payload, got)
			recycle()

			if mode == ModeEncrypted {
				require.False(t, bytes.Contains(wire, payload))
			} else {
				require.True(t, bytes.HasPrefix(wire, []byte(snappyMagicChunk)))
			}
		}
	}
}

func TestParseNetworkProfileAliases(t *testing.T) {
	tests := map[string]NetworkProfile{
		"":          NetworkWAN,
		"wifi":      NetworkWAN,
		"broadband": NetworkWAN,
		"ethernet":  NetworkLAN,
		"lan":       NetworkLAN,
		"5g":        NetworkLossy,
		"cellular":  NetworkLossy,
		"weak":      NetworkLossy,
	}
	for input, want := range tests {
		got, err := ParseNetworkProfile(input)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
}

func BenchmarkCompressionWriters(b *testing.B) {
	randomPayload := make([]byte, 16*1024)
	_, _ = rand.Read(randomPayload)
	textPayload := bytes.Repeat([]byte("frp adaptive compression benchmark payload "), 256)

	payloads := map[string][]byte{
		"text":   textPayload,
		"random": randomPayload,
		"small":  []byte(strings.Repeat("small-message ", 8)),
	}

	for payloadName, payload := range payloads {
		for _, profile := range Profiles() {
			b.Run(fmt.Sprintf("%s/%s/legacy", payloadName, profile), func(b *testing.B) {
				writer := snappy.NewWriter(io.Discard)
				b.SetBytes(int64(len(payload)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = writer.Write(payload)
				}
			})

			b.Run(fmt.Sprintf("%s/%s/adaptive", payloadName, profile), func(b *testing.B) {
				writer := NewAdaptiveWriter(io.Discard, profile)
				b.SetBytes(int64(len(payload)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = writer.Write(payload)
				}
			})
		}
	}
}

func BenchmarkSwitchSnapshot(b *testing.B) {
	s := NewSwitch(NetworkWAN, true)
	b.RunParallel(func(pb *testing.PB) {
		r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			_ = s.SetNetwork(Profiles()[r.Intn(3)])
			_, _ = s.Snapshot()
		}
	})
}
