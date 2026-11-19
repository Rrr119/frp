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

package limit

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUserLimiter_Disabled(t *testing.T) {
	require.Nil(t, NewUserLimiter(0))
	require.Nil(t, NewUserLimiter(-1))

	var l *UserLimiter
	for range 100 {
		require.True(t, l.Allow("user-a"))
	}
	require.Equal(t, 0, l.Len())
}

func TestUserLimiter_PerUserIsolation(t *testing.T) {
	// 1 QPS per user, burst 1.
	l := NewUserLimiter(1)
	require.NotNil(t, l)

	// user-a exhausts its burst immediately.
	require.True(t, l.Allow("user-a"))
	require.False(t, l.Allow("user-a"))

	// user-b has an independent quota and is not affected by user-a.
	require.True(t, l.Allow("user-b"))
	require.False(t, l.Allow("user-b"))

	// The empty user is a separate shared tenant.
	require.True(t, l.Allow(""))
	require.False(t, l.Allow(""))

	require.Equal(t, 3, l.Len())
}

func TestUserLimiter_Refill(t *testing.T) {
	// 100 QPS with a burst of 100: one token is refilled every 10ms.
	l := NewUserLimiter(100)
	for range 100 {
		require.True(t, l.Allow("user-a"))
	}
	require.False(t, l.Allow("user-a"))

	require.Eventually(t, func() bool {
		return l.Allow("user-a")
	}, 2*time.Second, 5*time.Millisecond)
}

func TestUserLimiter_BurstCeiling(t *testing.T) {
	// 2.5 QPS results in a burst of 3.
	l := NewUserLimiter(2.5)
	for range 3 {
		require.True(t, l.Allow("user-a"))
	}
	require.False(t, l.Allow("user-a"))
}

func TestUserLimiter_SweepIdleEntries(t *testing.T) {
	l := NewUserLimiter(1)
	now := time.Now()
	l.nowFn = func() time.Time { return now }

	require.True(t, l.Allow("user-a"))
	require.Equal(t, 1, l.Len())

	// Move time forward beyond the idle timeout and fill the cache up to
	// the sweep threshold: the idle entry must be reclaimed.
	now = now.Add(userIdleTimeout + time.Minute)
	for i := range userSweepThreshold {
		require.True(t, l.Allow("filler-"+strconv.Itoa(i)))
	}
	require.Less(t, l.Len(), userSweepThreshold+1)
	l.mu.Lock()
	_, ok := l.entries["user-a"]
	l.mu.Unlock()
	require.False(t, ok)
}
