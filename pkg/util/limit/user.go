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
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// userIdleTimeout is how long a per-user limiter may stay unused before it
// becomes eligible for lazy cleanup.
const userIdleTimeout = 10 * time.Minute

// userSweepThreshold is the number of cached per-user limiters that triggers
// a lazy sweep of idle entries.
const userSweepThreshold = 1024

type userEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// UserLimiter enforces an independent rate limit for every user (tenant).
// Limits of different users never interfere with each other.
type UserLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	entries map[string]*userEntry
	nowFn   func() time.Time
}

// NewUserLimiter creates a limiter that allows up to qps operations per
// second for each user, with a burst equal to the ceiling of qps (at least 1).
// It returns nil if qps is not positive, meaning no limit is applied.
func NewUserLimiter(qps float64) *UserLimiter {
	if qps <= 0 {
		return nil
	}
	burst := int(math.Ceil(qps))
	if burst < 1 {
		burst = 1
	}
	return &UserLimiter{
		limit:   rate.Limit(qps),
		burst:   burst,
		entries: make(map[string]*userEntry),
		nowFn:   time.Now,
	}
}

// Allow reports whether one operation is allowed for the given user right now.
// An empty user is treated as a single shared tenant.
func (l *UserLimiter) Allow(user string) bool {
	if l == nil {
		return true
	}
	now := l.nowFn()

	l.mu.Lock()
	if len(l.entries) >= userSweepThreshold {
		l.sweepLocked(now)
	}
	entry, ok := l.entries[user]
	if !ok {
		entry = &userEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[user] = entry
	}
	entry.lastSeen = now
	limiter := entry.limiter
	l.mu.Unlock()

	return limiter.Allow()
}

// sweepLocked removes entries that have been idle for longer than
// userIdleTimeout. Caller must hold l.mu.
func (l *UserLimiter) sweepLocked(now time.Time) {
	for user, entry := range l.entries {
		if now.Sub(entry.lastSeen) > userIdleTimeout {
			delete(l.entries, user)
		}
	}
}

// Len returns the number of cached per-user limiters. It is mainly used by
// tests and diagnostics.
func (l *UserLimiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
