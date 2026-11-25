// Copyright 2019 fatedier, fatedier@gmail.com
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

package visitor

import (
	"fmt"
	"io"
	"net"
	"slices"
	"sync"

	libio "github.com/fatedier/golib/io"

	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/tunnel"
	"github.com/fatedier/frp/pkg/util/util"
)

type listenerBundle struct {
	l          *netpkg.InternalListener
	sk         string
	allowUsers []string
}

// Manager for visitor listeners.
type Manager struct {
	listeners map[string]*listenerBundle

	mu sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string]*listenerBundle),
	}
}

func (vm *Manager) Listen(name string, sk string, allowUsers []string) (*netpkg.InternalListener, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if _, ok := vm.listeners[name]; ok {
		return nil, fmt.Errorf("custom listener for [%s] is repeated", name)
	}

	l := netpkg.NewInternalListener()
	vm.listeners[name] = &listenerBundle{
		l:          l,
		sk:         sk,
		allowUsers: allowUsers,
	}
	return l, nil
}

func (vm *Manager) NewConn(name string, conn net.Conn, timestamp int64, signKey string,
	useEncryption bool, useCompression bool, visitorUser string,
	wireProtocol string, udpPacketCodecs ...string,
) (err error) {
	return vm.NewConnWithConfig(name, conn, timestamp, signKey, ConnConfig{
		UseEncryption:   useEncryption,
		UseCompression:  useCompression,
		VisitorUser:     visitorUser,
		WireProtocol:    wireProtocol,
		UDPPacketCodecs: udpPacketCodecs,
	})
}

// ConnConfig contains visitor connection options, including optional adaptive
// compression settings negotiated through NewVisitorConn.
type ConnConfig struct {
	UseEncryption       bool
	UseCompression      bool
	AdaptiveCompression bool
	NetworkProfile      string
	VisitorUser         string
	WireProtocol        string
	UDPPacketCodecs     []string
}

func (vm *Manager) NewConnWithConfig(name string, conn net.Conn, timestamp int64, signKey string,
	cfg ConnConfig,
) (err error) {
	udpPacketCodec := ""
	if len(cfg.UDPPacketCodecs) > 0 {
		udpPacketCodec = cfg.UDPPacketCodecs[0]
	}
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if l, ok := vm.listeners[name]; ok {
		if util.GetAuthKey(l.sk, timestamp) != signKey {
			err = fmt.Errorf("visitor connection of [%s] auth failed", name)
			return
		}

		if !slices.Contains(l.allowUsers, cfg.VisitorUser) && !slices.Contains(l.allowUsers, "*") {
			err = fmt.Errorf("visitor connection of [%s] user [%s] not allowed", name, cfg.VisitorUser)
			return
		}

		var rwc io.ReadWriteCloser = conn
		if cfg.UseEncryption {
			if rwc, err = libio.WithEncryption(rwc, []byte(l.sk)); err != nil {
				err = fmt.Errorf("create encryption connection failed: %v", err)
				return
			}
		}
		if cfg.UseCompression {
			rwc = tunnel.WithCompression(rwc, cfg.AdaptiveCompression, tunnel.NetworkProfile(cfg.NetworkProfile))
		}
		visitorConn := netpkg.WrapReadWriteCloserToConn(rwc, conn)
		err = l.l.PutConn(&wireProtocolConn{
			Conn:           visitorConn,
			wireProtocol:   cfg.WireProtocol,
			udpPacketCodec: udpPacketCodec,
		})
	} else {
		err = fmt.Errorf("custom listener for [%s] doesn't exist", name)
		return
	}
	return
}

type wireProtocolConn struct {
	net.Conn
	wireProtocol   string
	udpPacketCodec string
}

func (c *wireProtocolConn) WireProtocol() string {
	return c.wireProtocol
}

func (c *wireProtocolConn) UDPPacketCodec() string {
	return c.udpPacketCodec
}

func (vm *Manager) CloseListener(name string) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	delete(vm.listeners, name)
}
