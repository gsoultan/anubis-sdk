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

// Cache fetches and caches the keys document. On an unknown kid it
// refetches at most once per MinRefetch — a stream of garbage kids must not
// translate into a stream of outbound requests.
type Cache struct {
	URL        string
	HTTPClient *http.Client
	MinRefetch time.Duration

	mu        sync.Mutex
	set       *Set
	lastFetch time.Time
}

func NewCache(url string) *Cache {
	return &Cache{
		URL:        url,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		MinRefetch: 30 * time.Second,
	}
}

// Get returns the key for kid, refetching the document once if the kid is
// unknown and the refetch budget allows.
func (kc *Cache) Get(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	if kc.set != nil {
		if pk, ok := kc.set.Get(kid); ok {
			return pk, nil
		}
	}
	if kc.set == nil || time.Since(kc.lastFetch) >= kc.MinRefetch {
		if err := kc.fetchLocked(ctx); err != nil {
			if kc.set == nil {
				return nil, err
			}
			// stale keys beat no keys; the unknown-kid rejection below stands
		}
		if pk, ok := kc.set.Get(kid); ok {
			return pk, nil
		}
	}
	return nil, ErrUnknownKid
}

func (kc *Cache) fetchLocked(ctx context.Context) error {
	kc.lastFetch = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kc.URL, nil)
	if err != nil {
		return err
	}
	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("anubis: keys fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("anubis: keys fetch: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	set, err := ParseDocument(raw)
	if err != nil {
		return err
	}
	kc.set = set
	return nil
}
