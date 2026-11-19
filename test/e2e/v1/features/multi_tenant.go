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

package features

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/mock/server/httpserver"
	"github.com/fatedier/frp/test/e2e/mock/server/streamserver"
)

var _ = ginkgo.Describe("[Feature: Multi-Tenant]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.It("Proxy name isolation between tenants", func() {
		serverConf := consts.DefaultServerConfig

		localPort := f.AllocPort()
		localServer := streamserver.New(streamserver.TCP, streamserver.WithBindPort(localPort))
		f.RunServer("", localServer)

		remotePortA := f.AllocPort()
		remotePortB := f.AllocPort()
		// Both tenants register a proxy with the same name. The user prefix
		// keeps them isolated from each other.
		newClientConf := func(user string, remotePort int) string {
			return consts.DefaultClientConfig + fmt.Sprintf(`
			user = "%s"

			[[proxies]]
			name = "tcp"
			type = "tcp"
			localPort = %d
			remotePort = %d
			`, user, localPort, remotePort)
		}

		f.RunProcesses(serverConf, []string{
			newClientConf("tenant-a", remotePortA),
			newClientConf("tenant-b", remotePortB),
		})

		framework.NewRequestExpect(f).Port(remotePortA).ExpectResp([]byte(consts.TestString)).Ensure()
		framework.NewRequestExpect(f).Port(remotePortB).ExpectResp([]byte(consts.TestString)).Ensure()
	})

	ginkgo.It("Per-user QPS limit", func() {
		serverConf := consts.DefaultServerConfig + `
		userQPSLimit = 1
		`

		localPort := f.AllocPort()
		localServer := streamserver.New(streamserver.TCP, streamserver.WithBindPort(localPort))
		f.RunServer("", localServer)

		// tenant-a registers two proxies in a burst: the first one succeeds,
		// the second one is rejected by the per-user QPS limit.
		remotePortA1 := f.AllocPort()
		remotePortA2 := f.AllocPort()
		clientConfA := consts.DefaultClientConfig + fmt.Sprintf(`
		user = "tenant-a"

		[[proxies]]
		name = "tcp1"
		type = "tcp"
		localPort = %d
		remotePort = %d

		[[proxies]]
		name = "tcp2"
		type = "tcp"
		localPort = %d
		remotePort = %d
		`, localPort, remotePortA1, localPort, remotePortA2)

		// tenant-b has an independent quota and is not affected by tenant-a.
		remotePortB := f.AllocPort()
		clientConfB := consts.DefaultClientConfig + fmt.Sprintf(`
		user = "tenant-b"

		[[proxies]]
		name = "tcp"
		type = "tcp"
		localPort = %d
		remotePort = %d
		`, localPort, remotePortB)

		f.RunProcesses(serverConf, []string{clientConfA, clientConfB})

		// The two NewProxy requests race for the single token in tenant-a's
		// bucket: exactly one of them must succeed.
		portOpen := func(port int) bool {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		}
		framework.ExpectTrue(portOpen(remotePortA1) != portOpen(remotePortA2),
			"exactly one of tenant-a's proxies should be registered")
		framework.NewRequestExpect(f).Port(remotePortB).ExpectResp([]byte(consts.TestString)).Ensure()
	})

	ginkgo.It("Audit log records tenant operations", func() {
		auditFile := filepath.Join(f.TempDirectory, "audit.log")
		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		auditLogFile = "%s"
		`, auditFile)

		localPort := f.AllocPort()
		localServer := streamserver.New(streamserver.TCP, streamserver.WithBindPort(localPort))
		f.RunServer("", localServer)

		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		user = "tenant-a"

		[[proxies]]
		name = "tcp"
		type = "tcp"
		localPort = %d
		remotePort = %d
		`, localPort, remotePort)

		f.RunProcesses(serverConf, []string{clientConf})
		framework.NewRequestExpect(f).Port(remotePort).ExpectResp([]byte(consts.TestString)).Ensure()

		gomega.Eventually(func() string {
			content, err := os.ReadFile(auditFile)
			if err != nil {
				return ""
			}
			return string(content)
		}, 5*time.Second, 100*time.Millisecond).Should(gomega.And(
			gomega.ContainSubstring(`"op":"Login"`),
			gomega.ContainSubstring(`"op":"NewProxy"`),
			gomega.ContainSubstring(`"user":"tenant-a"`),
			gomega.ContainSubstring(`"proxyName":"tenant-a.tcp"`),
		))
	})

	ginkgo.It("Plugin auth verifies tenants", func() {
		// Mock auth plugin: only the token "good-token" is accepted.
		pluginPort := f.AllocPort()
		pluginServer := httpserver.New(
			httpserver.WithBindPort(pluginPort),
			httpserver.WithHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var r auth.PluginAuthRequest
				if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				res := auth.PluginAuthResponse{
					Reject:       true,
					RejectReason: "invalid token",
				}
				if r.Content != nil && r.Content.PrivilegeKey != "" {
					// The privilege key is derived from the token; the mock
					// plugin trusts any presented key for "tenant-a" only.
					if r.Content.User == "tenant-a" {
						res = auth.PluginAuthResponse{}
					}
				}
				_ = json.NewEncoder(w).Encode(res)
			})),
		)
		f.RunServer("", pluginServer)

		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		auth.method = "plugin"
		auth.plugin.addr = "127.0.0.1:%d"
		auth.plugin.path = "/auth"
		`, pluginPort)

		localPort := f.AllocPort()
		localServer := streamserver.New(streamserver.TCP, streamserver.WithBindPort(localPort))
		f.RunServer("", localServer)

		remotePortOK := f.AllocPort()
		clientConfOK := consts.DefaultClientConfig + fmt.Sprintf(`
		user = "tenant-a"
		auth.method = "plugin"
		auth.token = "good-token"

		[[proxies]]
		name = "tcp"
		type = "tcp"
		localPort = %d
		remotePort = %d
		`, localPort, remotePortOK)

		remotePortDenied := f.AllocPort()
		clientConfDenied := consts.DefaultClientConfig + fmt.Sprintf(`
		user = "tenant-evil"
		auth.method = "plugin"
		auth.token = "bad-token"

		[[proxies]]
		name = "tcp"
		type = "tcp"
		localPort = %d
		remotePort = %d
		`, localPort, remotePortDenied)

		f.RunProcesses(serverConf, []string{clientConfOK, clientConfDenied})

		framework.NewRequestExpect(f).Port(remotePortOK).ExpectResp([]byte(consts.TestString)).Ensure()
		framework.NewRequestExpect(f).Port(remotePortDenied).ExpectError(true).Ensure()
	})
})
