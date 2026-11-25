package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
)

func TestProxyTunnelTransportMessageRoundTrip(t *testing.T) {
	base := ProxyBaseConfig{
		Name: "tunnel",
		Type: "tcp",
		Transport: ProxyTransport{
			UseEncryption:       true,
			UseCompression:      true,
			AdaptiveCompression: true,
			NetworkProfile:      "lossy",
		},
	}

	var message msg.NewProxy
	base.MarshalToMsg(&message)
	require.True(t, message.UseEncryption)
	require.True(t, message.UseCompression)
	require.True(t, message.AdaptiveCompression)
	require.Equal(t, "lossy", message.NetworkProfile)

	var decoded ProxyBaseConfig
	decoded.UnmarshalFromMsg(&message)
	require.Equal(t, base.Transport, decoded.Transport)
}

func TestVisitorTunnelTransportJSONFields(t *testing.T) {
	cfg := VisitorTransport{
		UseEncryption:       true,
		UseCompression:      true,
		AdaptiveCompression: true,
		NetworkProfile:      "wifi",
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.Contains(t, string(data), `"adaptiveCompression":true`)
	require.Contains(t, string(data), `"networkProfile":"wifi"`)
}
