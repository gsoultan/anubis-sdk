package keys

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultTTL is how long a fetched document is treated as current, and so
	// the upper bound on how long a withdrawn key keeps verifying tokens. A
	// cache that refetches only on an unknown kid never notices a removal:
	// rotation works, revocation silently does not.
	DefaultTTL = 5 * time.Minute
	// DefaultMinRefetch floors the gap between the fetches an unknown kid can
	// provoke while the document is still current.
	DefaultMinRefetch = 30 * time.Second
	// DefaultMinRetry floors the gap between attempts after a failed fetch.
	// Short on purpose: until the first fetch lands, nothing verifies at all.
	DefaultMinRetry = time.Second
)

// Cache fetches and caches the keys document.
//
// Two clocks govern refetching. TTL bounds how stale the document may get, so
// a key withdrawn upstream stops verifying. MinRefetch bounds what an unknown
// kid can provoke inside that window — kid arrives inside attacker-supplied
// tokens, so a stream of garbage kids must not become a stream of outbound
// requests.
//
// Fetches are single-flight and run with no lock held. Holding the lock across
// the round trip would turn a slow keys endpoint into a stall of every
// concurrent verification, including the ones that would have hit the cache.
type Cache struct {
	URL string
	// Issuer binds the document to a deployment; see ParseDocument.
	Issuer     string
	HTTPClient *http.Client
	TTL        time.Duration
	MinRefetch time.Duration
	MinRetry   time.Duration

	mu        sync.Mutex
	set       *Set
	lastFetch time.Time
	nextFetch time.Time
	lastErr   error
	inflight  chan struct{}
}

func NewCache(url string) *Cache {
	return &Cache{
		URL:        url,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		TTL:        DefaultTTL,
		MinRefetch: DefaultMinRefetch,
		MinRetry:   DefaultMinRetry,
	}
}

// Get returns the key for kid as of now.
func (kc *Cache) Get(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	return kc.GetAt(ctx, kid, time.Now())
}

// GetAt returns the key for kid as of now, refetching the document when it is
// missing, stale, or does not hold the kid and the refetch budget allows.
func (kc *Cache) GetAt(ctx context.Context, kid string, now time.Time) (ed25519.PublicKey, error) {
	set, fetched := kc.snapshot()

	// The hot path: a current document holding the kid answers with zero I/O.
	if set != nil && now.Sub(fetched) < kc.ttl() {
		if pk, ok := set.GetAt(kid, now); ok {
			return pk, nil
		}
	}

	// Missing, stale, or an unknown kid worth spending a fetch on.
	if err := kc.refetch(ctx, now); err != nil && set == nil {
		return nil, err
	}

	if set, _ = kc.snapshot(); set != nil {
		// When the fetch failed, stale keys beat no keys; the unknown-kid
		// rejection below still stands.
		if pk, ok := set.GetAt(kid, now); ok {
			return pk, nil
		}
	}
	return nil, ErrUnknownKid
}

func (kc *Cache) snapshot() (*Set, time.Time) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return kc.set, kc.lastFetch
}

// refetch runs at most one fetch at a time. A caller arriving while one is in
// flight waits for that result rather than starting its own — otherwise a
// burst of unknown kids becomes a burst of outbound requests, which is exactly
// what the kid budget exists to prevent.
func (kc *Cache) refetch(ctx context.Context, now time.Time) error {
	kc.mu.Lock()
	if ch := kc.inflight; ch != nil {
		kc.mu.Unlock()
		select {
		case <-ch:
			kc.mu.Lock()
			err := kc.lastErr
			kc.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if now.Before(kc.nextFetch) {
		err := kc.lastErr // the reason the last attempt failed, not "throttled"
		kc.mu.Unlock()
		return err
	}
	ch := make(chan struct{})
	kc.inflight = ch
	kc.mu.Unlock()

	// Released on the way out however we leave, including a panic. A wedged
	// inflight slot would park every later caller on a channel nothing closes,
	// which is a worse outage than the failed fetch that caused it.
	defer func() {
		kc.mu.Lock()
		kc.inflight = nil
		kc.mu.Unlock()
		close(ch)
	}()

	set, err := kc.fetch(ctx) // deliberately not under kc.mu

	kc.mu.Lock()
	kc.lastErr = err
	if err == nil {
		kc.set, kc.lastFetch = set, now
		kc.nextFetch = now.Add(kc.minRefetch())
	} else {
		kc.nextFetch = now.Add(kc.minRetry())
	}
	kc.mu.Unlock()
	return err
}

func (kc *Cache) fetch(ctx context.Context) (*Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kc.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := kc.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("anubis: keys fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anubis: keys fetch: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseDocument(raw, kc.Issuer)
}

// A zero interval would mean "no limit at all" — always stale, never throttled
// — which is the failure this cache exists to avoid. Read the timings through
// these so a zero-value Cache degrades to the defaults, not to a fetch storm.
func (kc *Cache) ttl() time.Duration {
	if kc.TTL <= 0 {
		return DefaultTTL
	}
	return kc.TTL
}

func (kc *Cache) minRefetch() time.Duration {
	if kc.MinRefetch <= 0 {
		return DefaultMinRefetch
	}
	return kc.MinRefetch
}

func (kc *Cache) minRetry() time.Duration {
	if kc.MinRetry <= 0 {
		return DefaultMinRetry
	}
	return kc.MinRetry
}

func (kc *Cache) client() *http.Client {
	if kc.HTTPClient == nil {
		return &http.Client{Timeout: 5 * time.Second}
	}
	return kc.HTTPClient
}
