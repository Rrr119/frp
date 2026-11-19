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

package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLogger_NilSafe(t *testing.T) {
	var l *Logger
	l.Log(Event{Op: OpLogin, Success: true, User: "user-a"})
	require.NoError(t, l.Close())
}

func TestLogger_WriteJSONLines(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	l.Log(Event{
		Op:         OpLogin,
		Success:    true,
		User:       "user-a",
		RunID:      "run-1",
		ClientAddr: "127.0.0.1:5000",
	})
	l.Log(Event{
		Op:        OpNewProxy,
		Success:   false,
		User:      "user-b",
		ProxyName: "user-b.web",
		ProxyType: "http",
		Detail:    "rate limit exceeded",
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)

	var first, second Event
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))

	require.Equal(t, OpLogin, first.Op)
	require.True(t, first.Success)
	require.Equal(t, "user-a", first.User)
	require.Equal(t, "run-1", first.RunID)
	require.False(t, first.Time.IsZero())

	require.Equal(t, OpNewProxy, second.Op)
	require.False(t, second.Success)
	require.Equal(t, "user-b", second.User)
	require.Equal(t, "user-b.web", second.ProxyName)
	require.Equal(t, "rate limit exceeded", second.Detail)
}

func TestLogger_KeepProvidedTime(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	l.Log(Event{Time: ts, Op: OpCloseProxy, Success: true})

	var ev Event
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &ev))
	require.True(t, ts.Equal(ev.Time))
}

func TestNewFileLogger(t *testing.T) {
	// Empty path disables audit logging.
	l, err := NewFileLogger("")
	require.NoError(t, err)
	require.Nil(t, l)

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err = NewFileLogger(path)
	require.NoError(t, err)
	require.NotNil(t, l)

	l.Log(Event{Op: OpLogin, Success: true, User: "user-a"})
	require.NoError(t, l.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), `"user":"user-a"`)

	// The file is append-only: a second logger keeps existing events.
	l, err = NewFileLogger(path)
	require.NoError(t, err)
	l.Log(Event{Op: OpLogin, Success: true, User: "user-b"})
	require.NoError(t, l.Close())

	content, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), `"user":"user-a"`)
	require.Contains(t, string(content), `"user":"user-b"`)
}
