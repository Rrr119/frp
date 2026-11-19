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

// Package audit records security-relevant server events (client logins,
// proxy registrations and removals) as JSON lines for multi-tenant
// auditing.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Audit event operations.
const (
	OpLogin      = "Login"
	OpNewProxy   = "NewProxy"
	OpCloseProxy = "CloseProxy"
)

// Event describes a single auditable operation.
type Event struct {
	Time       time.Time `json:"time"`
	Op         string    `json:"op"`
	Success    bool      `json:"success"`
	User       string    `json:"user,omitempty"`
	RunID      string    `json:"runID,omitempty"`
	ClientAddr string    `json:"clientAddr,omitempty"`
	ProxyName  string    `json:"proxyName,omitempty"`
	ProxyType  string    `json:"proxyType,omitempty"`
	// Detail carries additional context, typically the rejection reason.
	Detail string `json:"detail,omitempty"`
}

// Logger appends audit events to a writer as JSON lines. It is safe for
// concurrent use. A nil *Logger is valid and drops all events.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

// NewLogger creates a Logger writing to w. If w implements io.Closer it is
// closed by Close.
func NewLogger(w io.Writer) *Logger {
	l := &Logger{w: w}
	if closer, ok := w.(io.Closer); ok {
		l.closer = closer
	}
	return l
}

// NewFileLogger creates a Logger appending to the file at path. It returns
// nil (and no error) if path is empty, meaning audit logging is disabled.
func NewFileLogger(path string) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return NewLogger(f), nil
}

// Log records one audit event. Events on a nil Logger are dropped.
func (l *Logger) Log(ev Event) {
	if l == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	buf, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(buf, '\n'))
}

// Close flushes and closes the underlying writer if it is closable.
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closer.Close()
}
