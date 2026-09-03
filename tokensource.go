package anubis

import (
	"context"
	"errors"
	"sync"
	"time"
)

// refreshMargin refreshes a little before the access token actually expires.
//
// A token that is valid when the request leaves and expired when it arrives is
// a 401 nobody can reproduce. The margin has to exceed the clock skew the
// verifier tolerates plus a round trip.
const refreshMargin = 30 * time.Second

// TokenSource holds a token pair and keeps it fresh. Safe for concurrent use,
// and that is the entire reason it exists.
//
// Refresh tokens are single-use and rotate on every refresh. Two goroutines
// that both notice an expired access token will both refresh; one wins, and
// the other presents a token Anubis has already consumed. Anubis reads that,
// correctly, as theft — and revokes the family and the session. A client
// without this type logs its own users out under concurrency, and pages a
// human while doing it.
//
// So refreshes are single-flight: the first caller refreshes, everyone else
// waits for that same result. One refresh per rotation, always.
type TokenSource struct {
	refresh func(ctx context.Context, current Tokens) (*Tokens, error)
	now     func() time.Time

	// needsRefreshToken distinguishes a rotating user session, which cannot
	// refresh without one, from a client-credentials source, which re-mints
	// from its own secret and never has one.
	needsRefreshToken bool

	mu       sync.Mutex
	tokens   Tokens
	onRotate func(Tokens) error
	inflight *flight
}

type flight struct {
	done   chan struct{}
	tokens Tokens
	err    error
}

// TokenSource wraps a pair so it stays fresh.
//
//	ts := client.TokenSource(tokens)
//	ts.OnRotate(func(t anubis.Tokens) error { return sessions.Save(t) })
//	tok, err := ts.Token(ctx)
func (c *Client) TokenSource(t Tokens) *TokenSource {
	if t.IssuedAt.IsZero() {
		t.IssuedAt = c.opts.now()
	}
	return &TokenSource{
		now:               c.opts.now,
		needsRefreshToken: true,
		tokens:            t,
		refresh: func(ctx context.Context, current Tokens) (*Tokens, error) {
			return c.Refresh(ctx, current.RefreshToken)
		},
	}
}

// OnRotate registers a callback that receives every new pair.
//
// It runs BEFORE Token returns, so a process that dies between the two has
// already stored the new pair. Storing afterwards loses the rotation on a
// crash and produces the same self-inflicted theft signal this type exists to
// prevent.
//
// If the callback returns an error the new tokens are still adopted in memory,
// because the old refresh token is already dead on the server — holding onto
// it would guarantee a reuse refusal on the next attempt. The error is
// returned to the caller so the failure to persist is not silent.
func (ts *TokenSource) OnRotate(f func(Tokens) error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.onRotate = f
}

// Current returns the pair held right now, without refreshing.
func (ts *TokenSource) Current() Tokens {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.tokens
}

// Token returns a valid access token, refreshing if the one held is close to
// expiry. Concurrent callers share a single refresh.
func (ts *TokenSource) Token(ctx context.Context) (Tokens, error) {
	ts.mu.Lock()
	if ts.valid() {
		t := ts.tokens
		ts.mu.Unlock()
		return t, nil
	}
	if f := ts.inflight; f != nil {
		// Somebody is already rotating. Wait for their result rather than
		// starting a second rotation — the second one is the theft signal.
		ts.mu.Unlock()
		select {
		case <-f.done:
			return f.tokens, f.err
		case <-ctx.Done():
			return Tokens{}, ctx.Err()
		}
	}
	if ts.needsRefreshToken && ts.tokens.RefreshToken == "" {
		ts.mu.Unlock()
		return Tokens{}, errors.New("anubis: the access token has expired and there is no refresh token — sign in again")
	}
	f := &flight{done: make(chan struct{})}
	ts.inflight = f
	current := ts.tokens
	ts.mu.Unlock()

	ts.rotate(ctx, f, current)
	return f.tokens, f.err
}

func (ts *TokenSource) rotate(ctx context.Context, f *flight, current Tokens) {
	next, err := ts.refresh(ctx, current)

	ts.mu.Lock()
	if err == nil && next != nil {
		if next.IssuedAt.IsZero() {
			next.IssuedAt = ts.now()
		}
		// A refresh that returns no new refresh token is a client-credentials
		// re-mint, not a rotation; carry the old one forward so the source
		// stays usable.
		if next.RefreshToken == "" {
			next.RefreshToken = current.RefreshToken
		}
		ts.tokens = *next
	}
	onRotate := ts.onRotate
	rotated := ts.tokens
	ts.inflight = nil
	ts.mu.Unlock()

	// Called without the lock: the callback persists to somewhere that may
	// itself take time, and holding the mutex across it would serialise every
	// reader of this source behind a disk write. It still happens before
	// f.done closes, which is what "before Token returns" means.
	if err == nil && onRotate != nil {
		if perr := onRotate(rotated); perr != nil {
			err = perr
		}
	}

	f.tokens, f.err = rotated, err
	if err != nil {
		f.tokens = Tokens{}
	}
	close(f.done)
}

func (ts *TokenSource) valid() bool {
	if ts.tokens.AccessToken == "" {
		return false
	}
	exp := ts.tokens.Expiry()
	if exp.IsZero() {
		// No expiry known: the only honest reading is that it is still good,
		// since refreshing on every call would burn a rotation per request.
		return true
	}
	return ts.now().Add(refreshMargin).Before(exp)
}

// Refresh rotates a pair once.
//
// Prefer TokenSource, which serialises this. Calling Refresh directly from
// concurrent request handlers is how a client reports itself for theft.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	if refreshToken == "" {
		return nil, errors.New("anubis: refresh needs a refresh token")
	}
	var out struct {
		Tokens *Tokens `json:"tokens"`
	}
	if err := c.rpcNoAuth(ctx, procRefresh, map[string]any{"refresh_token": refreshToken}, &out); err != nil {
		return nil, err
	}
	if out.Tokens == nil {
		return nil, errors.New("anubis: refresh returned no tokens")
	}
	c.stamp(out.Tokens)
	return out.Tokens, nil
}

// ClientCredentials mints a token for the application acting as itself.
//
// It returns a TokenSource rather than a token because these are short-lived
// and have no refresh token: the only correct handling is to re-mint on
// expiry, and that should not be every caller's job to remember.
//
// Audience is what stops a token minted for one service being replayed against
// another — the confused deputy the receiving verifier's Audience field exists
// for. It defaults to the calling application itself.
func (c *Client) ClientCredentials(ctx context.Context, audience string) (*TokenSource, error) {
	if c.opts.clientID == "" || c.opts.clientSecret == "" {
		return nil, errors.New("anubis: client credentials need WithApplication(clientID, clientSecret)")
	}
	mint := func(ctx context.Context, _ Tokens) (*Tokens, error) {
		req := map[string]any{
			"tenant":        c.opts.tenant,
			"client_id":     c.opts.clientID,
			"client_secret": c.opts.clientSecret,
			"audience":      audience,
		}
		var out struct {
			AccessToken string `json:"accessToken"`
			TokenType   string `json:"tokenType"`
			ExpiresIn   int    `json:"expiresIn"`
		}
		if err := c.rpcNoAuth(ctx, procClientCredentials, req, &out); err != nil {
			return nil, err
		}
		return &Tokens{
			AccessToken: out.AccessToken,
			TokenType:   out.TokenType,
			ExpiresIn:   out.ExpiresIn,
			IssuedAt:    c.opts.now(),
		}, nil
	}
	ts := &TokenSource{refresh: mint, now: c.opts.now}
	if _, err := ts.Token(ctx); err != nil {
		return nil, err
	}
	return ts, nil
}
