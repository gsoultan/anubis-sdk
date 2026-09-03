package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newKey(t *testing.T, kid string) (ed25519.PublicKey, Entry) {
	t.Helper()
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pk, Entry{Kid: kid, Alg: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(pk)}
}

func doc(t *testing.T, issuer string, entries ...Entry) []byte {
	t.Helper()
	raw, err := json.Marshal(Document{Issuer: issuer, Keys: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---- ParseDocument -------------------------------------------------------

func TestParseDocumentBindsIssuer(t *testing.T) {
	_, e := newKey(t, "k1")
	for _, tc := range []struct {
		name, inDoc, expected string
		wantErr               bool
	}{
		{name: "match", inDoc: "https://a.test", expected: "https://a.test"},
		{name: "mismatch", inDoc: "https://evil.test", expected: "https://a.test", wantErr: true},
		{name: "document omits issuer", inDoc: "", expected: "https://a.test"},
		{name: "caller does not bind", inDoc: "https://evil.test", expected: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDocument(doc(t, tc.inDoc, e), tc.expected)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseDocument err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseDocumentBoundsKeyCount(t *testing.T) {
	entries := make([]Entry, 0, maxKeys+1)
	for i := 0; i <= maxKeys; i++ {
		_, e := newKey(t, string(rune('a'+i%26))+string(rune('0'+i/26)))
		entries = append(entries, e)
	}
	if _, err := ParseDocument(doc(t, "", entries...), ""); err == nil {
		t.Fatalf("accepted %d keys, want rejection above %d", len(entries), maxKeys)
	}
}

func TestParseDocumentPinsEd25519(t *testing.T) {
	_, good := newKey(t, "k1")
	_, bad := newKey(t, "k2")
	bad.Alg = "RS256"
	set, err := ParseDocument(doc(t, "", good, bad), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Get("k2"); ok {
		t.Fatal("loaded a non-Ed25519 key; the algorithm is meant to be pinned")
	}
	if _, ok := set.Get("k1"); !ok {
		t.Fatal("dropped the Ed25519 key")
	}
}

// ---- validity windows ----------------------------------------------------

func TestSetEnforcesValidityWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	_, notYet := newKey(t, "future")
	notYet.NotBefore = now.Add(time.Minute).Unix()
	_, retired := newKey(t, "past")
	retired.NotAfter = now.Unix()
	_, always := newKey(t, "unbounded")

	set, err := ParseDocument(doc(t, "", notYet, retired, always), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kid  string
		at   time.Time
		want bool
	}{
		{"future", now, false},
		{"future", now.Add(2 * time.Minute), true},
		{"past", now.Add(-time.Second), true},
		{"past", now, false}, // not_after is exclusive: trust stops at the bound
		{"unbounded", now.Add(-1000 * time.Hour), true},
		{"unbounded", now.Add(1000 * time.Hour), true},
	} {
		if _, ok := set.GetAt(tc.kid, tc.at); ok != tc.want {
			t.Errorf("GetAt(%q, %v) ok = %v, want %v", tc.kid, tc.at.Unix(), ok, tc.want)
		}
	}
}

// ---- cache ---------------------------------------------------------------

// keysServer serves a document that the test can swap, counting every request
// so the tests can assert on outbound spend rather than on timing.
type keysServer struct {
	*httptest.Server
	mu      sync.Mutex
	body    []byte
	status  int
	hits    atomic.Int64
	release chan struct{} // non-nil: the handler waits for it
	entered chan struct{}
}

func newKeysServer(t *testing.T, body []byte) *keysServer {
	t.Helper()
	ks := &keysServer{body: body, status: http.StatusOK, entered: make(chan struct{}, 64)}
	ks.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ks.hits.Add(1)
		ks.mu.Lock()
		body, status, release := ks.body, ks.status, ks.release
		ks.mu.Unlock()
		select {
		case ks.entered <- struct{}{}:
		default:
		}
		if release != nil {
			<-release
		}
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(ks.Close)
	return ks
}

func (ks *keysServer) serve(body []byte, status int) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.body, ks.status = body, status
}

func (ks *keysServer) blockUntil(ch chan struct{}) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.release = ch
}

func newTestCache(url string) *Cache {
	c := NewCache(url)
	c.TTL = 5 * time.Minute
	c.MinRefetch = 30 * time.Second
	c.MinRetry = time.Second
	return c
}

// The gap this closes: a cache that only refetches on an unknown kid never
// notices a key being withdrawn, so a compromised key keeps verifying tokens
// for the lifetime of the process.
func TestCacheRevocationPropagatesAfterTTL(t *testing.T) {
	_, k1 := newKey(t, "k1")
	_, k2 := newKey(t, "k2")
	srv := newKeysServer(t, doc(t, "", k1, k2))
	c := newTestCache(srv.URL)
	ctx, now := context.Background(), time.Unix(1_700_000_000, 0)

	if _, err := c.GetAt(ctx, "k2", now); err != nil {
		t.Fatalf("k2 before revocation: %v", err)
	}

	srv.serve(doc(t, "", k1), http.StatusOK) // k2 withdrawn

	if _, err := c.GetAt(ctx, "k2", now.Add(time.Minute)); err != nil {
		t.Fatalf("inside the TTL the cached document still answers: %v", err)
	}
	if _, err := c.GetAt(ctx, "k2", now.Add(6*time.Minute)); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("past the TTL a withdrawn key must stop verifying, got %v", err)
	}
}

// kid is attacker-controlled, so a stream of garbage kids must not become a
// stream of outbound requests.
func TestCacheRateLimitsUnknownKid(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newKeysServer(t, doc(t, "", k1))
	c := newTestCache(srv.URL)
	ctx, now := context.Background(), time.Unix(1_700_000_000, 0)

	for i := 0; i < 50; i++ {
		if _, err := c.GetAt(ctx, "garbage", now); !errors.Is(err, ErrUnknownKid) {
			t.Fatalf("got %v, want ErrUnknownKid", err)
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("50 garbage kids caused %d fetches, want 1", got)
	}
	if _, err := c.GetAt(ctx, "garbage", now.Add(31*time.Second)); !errors.Is(err, ErrUnknownKid) {
		t.Fatal(err)
	}
	if got := srv.hits.Load(); got != 2 {
		t.Fatalf("past MinRefetch: %d fetches, want 2", got)
	}
}

// The regression: while the cache was empty the rate limit was bypassed
// entirely, so every concurrent request on a cold start issued its own fetch
// — serialised behind the lock, at the HTTP timeout each.
func TestCacheColdStartIsSingleFlight(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newKeysServer(t, doc(t, "", k1))
	release := make(chan struct{})
	srv.blockUntil(release)

	c := newTestCache(srv.URL)
	ctx, now := context.Background(), time.Unix(1_700_000_000, 0)

	const callers = 32
	var entered atomic.Int64
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entered.Add(1)
			_, errs[i] = c.GetAt(ctx, "k1", now)
		}(i)
	}
	for entered.Load() < callers {
		runtimeGosched()
	}
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("%d concurrent cold-start callers caused %d fetches, want 1", callers, got)
	}
}

// The other half of the regression: the fetch used to run with the lock held,
// so a slow keys endpoint stalled every concurrent verification — including
// the ones whose key was already cached.
func TestCacheHitDoesNotWaitOnInFlightFetch(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newKeysServer(t, doc(t, "", k1))
	c := newTestCache(srv.URL)
	ctx, now := context.Background(), time.Unix(1_700_000_000, 0)

	if _, err := c.GetAt(ctx, "k1", now); err != nil { // warm
		t.Fatal(err)
	}

	release := make(chan struct{})
	srv.blockUntil(release)
	defer close(release)

	later := now.Add(31 * time.Second) // past MinRefetch, inside the TTL
	go c.GetAt(ctx, "garbage", later)  //nolint:errcheck // provokes the blocked fetch
	<-srv.entered

	done := make(chan error, 1)
	go func() { _, err := c.GetAt(ctx, "k1", later); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cached key: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cached key blocked behind an in-flight fetch")
	}
}

func TestCacheStaleKeysBeatNoKeys(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newKeysServer(t, doc(t, "", k1))
	c := newTestCache(srv.URL)
	ctx, now := context.Background(), time.Unix(1_700_000_000, 0)

	if _, err := c.GetAt(ctx, "k1", now); err != nil {
		t.Fatal(err)
	}
	srv.serve(nil, http.StatusInternalServerError)

	if _, err := c.GetAt(ctx, "k1", now.Add(6*time.Minute)); err != nil {
		t.Fatalf("keys endpoint down and the document stale: %v; stale keys beat no keys", err)
	}
}

// Until the first fetch lands nothing verifies, but a down endpoint must still
// not take one outbound request per inbound request.
func TestCacheBootstrapFailureIsRateLimited(t *testing.T) {
	srv := newKeysServer(t, nil)
	srv.serve(nil, http.StatusInternalServerError)
	c := newTestCache(srv.URL)
	ctx, now := context.Background(), time.Unix(1_700_000_000, 0)

	for i := 0; i < 20; i++ {
		if _, err := c.GetAt(ctx, "k1", now); err == nil {
			t.Fatal("expected an error while the cache is empty")
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("20 requests against a down endpoint caused %d fetches, want 1", got)
	}
	if _, err := c.GetAt(ctx, "k1", now.Add(2*time.Second)); err == nil {
		t.Fatal("expected an error")
	}
	if got := srv.hits.Load(); got != 2 {
		t.Fatalf("past MinRetry: %d fetches, want 2", got)
	}
}

func TestCacheRejectsDocumentFromAnotherIssuer(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newKeysServer(t, doc(t, "https://staging.test", k1))
	c := newTestCache(srv.URL)
	c.Issuer = "https://prod.test"

	_, err := c.GetAt(context.Background(), "k1", time.Unix(1_700_000_000, 0))
	if err == nil || errors.Is(err, ErrUnknownKid) {
		t.Fatalf("loaded another deployment's keys, got err = %v", err)
	}
}

func TestZeroValueCacheUsesDefaults(t *testing.T) {
	c := &Cache{}
	if c.ttl() != DefaultTTL || c.minRefetch() != DefaultMinRefetch || c.minRetry() != DefaultMinRetry {
		t.Fatal("a zero interval must degrade to the default, not to 'no limit'")
	}
}

func runtimeGosched() { runtime.Gosched() }

// A zero-value Cache must not wedge: before the timings and the client
// defaulted, an unconfigured cache panicked mid-fetch and left the in-flight
// slot occupied, parking every later caller on a channel nothing closed.
func TestZeroValueCacheStillFetches(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newKeysServer(t, doc(t, "", k1))
	c := &Cache{URL: srv.URL}

	done := make(chan error, 1)
	go func() { _, err := c.GetAt(context.Background(), "k1", time.Now()); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("zero-value cache: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("zero-value cache wedged")
	}
}
