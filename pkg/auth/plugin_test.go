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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

func newPluginVerifier(t *testing.T, handler http.HandlerFunc) *PluginAuthVerifier {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewPluginAuthVerifier(v1.AuthPluginServerConfig{
		Addr:    srv.URL,
		Path:    "/auth",
		Timeout: 5,
	})
}

func TestPluginAuthVerifier_Allow(t *testing.T) {
	var gotReq PluginAuthRequest
	verifier := newPluginVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotReq))
		_ = json.NewEncoder(w).Encode(PluginAuthResponse{})
	})

	login := &msg.Login{User: "tenant-a", PrivilegeKey: "key"}
	require.NoError(t, verifier.VerifyLogin(login))
	require.Equal(t, PluginAuthAPIVersion, gotReq.Version)
	require.Equal(t, "Login", gotReq.Op)
	require.Equal(t, "tenant-a", gotReq.Content.User)
	require.Equal(t, "tenant-a", login.User)
}

func TestPluginAuthVerifier_Reject(t *testing.T) {
	verifier := newPluginVerifier(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PluginAuthResponse{
			Reject:       true,
			RejectReason: "unknown tenant",
		})
	})

	err := verifier.VerifyLogin(&msg.Login{User: "ghost"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown tenant")
}

func TestPluginAuthVerifier_AssignUser(t *testing.T) {
	verifier := newPluginVerifier(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(PluginAuthResponse{User: "tenant-real"})
	})

	login := &msg.Login{}
	require.NoError(t, verifier.VerifyLogin(login))
	require.Equal(t, "tenant-real", login.User)
}

func TestPluginAuthVerifier_ServerError(t *testing.T) {
	verifier := newPluginVerifier(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	require.Error(t, verifier.VerifyLogin(&msg.Login{}))
}

func TestPluginAuthVerifier_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_ = json.NewEncoder(w).Encode(PluginAuthResponse{})
	}))
	t.Cleanup(srv.Close)
	verifier := NewPluginAuthVerifier(v1.AuthPluginServerConfig{
		Addr:    srv.URL,
		Path:    "/auth",
		Timeout: 1,
	})
	require.Error(t, verifier.VerifyLogin(&msg.Login{}))
}

func TestPluginAuthVerifier_PingAndWorkConnPass(t *testing.T) {
	verifier := NewPluginAuthVerifier(v1.AuthPluginServerConfig{Addr: "127.0.0.1:1"})
	require.NoError(t, verifier.VerifyPing(&msg.Ping{}))
	require.NoError(t, verifier.VerifyNewWorkConn(&msg.NewWorkConn{}))
}

func TestNewAuthVerifier_PluginMethod(t *testing.T) {
	verifier := NewAuthVerifier(v1.AuthServerConfig{
		Method: v1.AuthMethodPlugin,
		Plugin: v1.AuthPluginServerConfig{Addr: "127.0.0.1:1"},
	})
	require.IsType(t, &PluginAuthVerifier{}, verifier)
}

func TestNewAuthSetter_PluginMethod(t *testing.T) {
	setter, err := NewAuthSetter(v1.AuthClientConfig{
		Method: v1.AuthMethodPlugin,
		Token:  "secret",
	})
	require.NoError(t, err)
	login := &msg.Login{Timestamp: time.Now().Unix()}
	require.NoError(t, setter.SetLogin(login))
	require.NotEmpty(t, login.PrivilegeKey)
}
