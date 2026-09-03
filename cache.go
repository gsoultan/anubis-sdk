package anubis

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// decisionCache holds allow/deny answers for a short, configured window.
//
// Eviction is generational rather than LRU: when the live generation fills,
// it becomes the old generation and a fresh one starts, and the old one is
// dropped whole on the next fill. Two map allocations replace per-entry
// bookkeeping, which matters because this sits on the request path — a cache
// that allocates per lookup is a regression dressed as an optimisation.
type decisionCache struct {
	ttl     time.Duration
	maxSize int

	mu   sync.Mutex
	live map[string]cacheEntry
	old  map[string]cacheEntry
}

type cacheEntry struct {
	decision Decision
	expires  time.Time
}

func newDecisionCache(cfg CacheConfig) *decisionCache {
	return &decisionCache{
		ttl:     cfg.TTL,
		maxSize: cfg.MaxSize,
		live:    make(map[string]cacheEntry, 64),
	}
}

func (c *decisionCache) get(key string, now time.Time) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.live[key]
	if !ok {
		if e, ok = c.old[key]; !ok {
			return Decision{}, false
		}
	}
	if now.After(e.expires) {
		return Decision{}, false
	}
	return e.decision, true
}

func (c *decisionCache) put(key string, d Decision, now time.Time) {
	// A step-up refusal goes stale the instant the user re-authenticates,
	// which is the entire point of it. Caching one would send a user who has
	// just done everything asked of them round the loop a second time.
	if d.Reason == codeStepUpRequired {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.live) >= c.maxSize {
		c.old, c.live = c.live, make(map[string]cacheEntry, c.maxSize/2)
	}
	c.live[key] = cacheEntry{decision: d, expires: now.Add(c.ttl)}
}

// cacheKey covers every input the decision depended on.
//
// Every one of these changes the answer, so leaving any of them out answers
// one caller's question with another caller's answer — a data leak wearing a
// performance costume.
func cacheKey(subject SubjectID, permission Permission, scopes Scopes, amr AuthMethods, authTime int64) string {
	var b strings.Builder
	b.WriteString(string(subject))
	b.WriteByte(0)
	b.WriteString(string(permission))
	b.WriteByte(0)

	// Scopes.Axes sorts already, which is the point of it being a method: Go
	// map iteration order is random, and an unsorted key would cache the same
	// question under many different keys.
	for _, axis := range scopes.Axes() {
		b.WriteString(string(axis))
		b.WriteByte('=')
		b.WriteString(scopes[axis])
		b.WriteByte(0)
	}
	methods := append([]string(nil), amr.Strings()...)
	sort.Strings(methods)
	for _, m := range methods {
		b.WriteString(m)
		b.WriteByte(0)
	}
	b.WriteString(strconv.FormatInt(authTime, 10))

	sum := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
