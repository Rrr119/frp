// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// PluginAuthAPIVersion is the API version sent to auth plugins.
const PluginAuthAPIVersion = "0.1.0"

// PluginAuthRequest is the payload sent to the external auth plugin.
type PluginAuthRequest struct {
	Version string     `json:"version"`
	Op      string     `json:"op"`
	Content *msg.Login `json:"content"`
}

// PluginAuthResponse is the response expected from the external auth plugin.
type PluginAuthResponse struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason"`
	// User, if non-empty, is assigned as the authenticated identity of the
	// client. It overrides the user claimed in the login message.
	User string `json:"user,omitempty"`
}

// PluginAuthVerifier delegates login verification to an external HTTP auth
// plugin, enabling pluggable per-tenant authentication.
type PluginAuthVerifier struct {
	url    string
	client *http.Client
}

func NewPluginAuthVerifier(cfg v1.AuthPluginServerConfig) *PluginAuthVerifier {
	url := cfg.Addr + cfg.Path
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &PluginAuthVerifier{
		url:    url,
		client: &http.Client{Timeout: timeout},
	}
}

func (p *PluginAuthVerifier) VerifyLogin(loginMsg *msg.Login) error {
	res, err := p.do(context.Background(), &PluginAuthRequest{
		Version: PluginAuthAPIVersion,
		Op:      "Login",
		Content: loginMsg,
	})
	if err != nil {
		return fmt.Errorf("auth plugin request failed: %w", err)
	}
	if res.Reject {
		return fmt.Errorf("auth plugin rejected login: %s", res.RejectReason)
	}
	if res.User != "" {
		loginMsg.User = res.User
	}
	return nil
}

// VerifyPing is a no-op for plugin auth: clients are authenticated at login.
func (p *PluginAuthVerifier) VerifyPing(*msg.Ping) error {
	return nil
}

// VerifyNewWorkConn is a no-op for plugin auth: clients are authenticated at login.
func (p *PluginAuthVerifier) VerifyNewWorkConn(*msg.NewWorkConn) error {
	return nil
}

func (p *PluginAuthVerifier) do(ctx context.Context, r *PluginAuthRequest) (*PluginAuthResponse, error) {
	buf, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth plugin returned status code: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var res PluginAuthResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("unmarshal auth plugin response error: %w", err)
	}
	return &res, nil
}
