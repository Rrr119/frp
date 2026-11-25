package tunnel

import (
	"fmt"
	"strings"
)

// NetworkProfile describes one of the three supported network environments.
type NetworkProfile string

const (
	// NetworkLAN represents a high-bandwidth, low-latency local or wired network.
	NetworkLAN NetworkProfile = "lan"
	// NetworkWAN represents an ordinary broadband, Wi-Fi, or public network.
	NetworkWAN NetworkProfile = "wan"
	// NetworkLossy represents a metered mobile, cellular, weak, or lossy network.
	NetworkLossy NetworkProfile = "lossy"
)

// ParseNetworkProfile canonicalizes supported profile names and common aliases.
func ParseNetworkProfile(s string) (NetworkProfile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default", "auto", "wan", "broadband", "wifi", "wi-fi", "wireless", "public":
		return NetworkWAN, nil
	case "lan", "local", "ethernet", "wired", "intranet":
		return NetworkLAN, nil
	case "lossy", "weak", "mobile", "cellular", "4g", "5g", "lte", "satellite", "metered":
		return NetworkLossy, nil
	default:
		return "", fmt.Errorf("unsupported network profile %q: want lan, wan, or lossy", s)
	}
}

// MustParseNetworkProfile is intended for tests and package-level defaults.
func MustParseNetworkProfile(s string) NetworkProfile {
	p, err := ParseNetworkProfile(s)
	if err != nil {
		panic(err)
	}
	return p
}

// Profiles returns the three canonical network profiles.
func Profiles() []NetworkProfile {
	return []NetworkProfile{NetworkLAN, NetworkWAN, NetworkLossy}
}

type compressionPolicy struct {
	minBytes       int
	sampleBytes    int
	maxDistinct    int
	minWireSavings float64
}

func policyFor(profile NetworkProfile) compressionPolicy {
	switch profile {
	case NetworkLAN:
		return compressionPolicy{
			minBytes:       1024,
			sampleBytes:    512,
			maxDistinct:    176,
			minWireSavings: 0.25,
		}
	case NetworkLossy:
		return compressionPolicy{
			minBytes:       64,
			sampleBytes:    512,
			maxDistinct:    214,
			minWireSavings: 0.05,
		}
	case NetworkWAN:
		fallthrough
	default:
		return compressionPolicy{
			minBytes:       256,
			sampleBytes:    512,
			maxDistinct:    196,
			minWireSavings: 0.125,
		}
	}
}
