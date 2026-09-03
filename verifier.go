package anubis

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/gsoultan/anubis-sdk/keys"
	"github.com/gsoultan/anubis-sdk/paseto"
)

// Verifier verifies v4.public access tokens offline. Zero I/O on the verify
// path except a bounded, rate-limited key refetch on unknown or stale keys.
type Verifier struct {
	cfg   Config
	cache *keys.Cache
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Audience == "" {
		return nil, ErrNoAudience
	}
	if cfg.KeysURL == "" && cfg.StaticKeys == nil {
		return nil, errors.New("anubis: either KeysURL or StaticKeys is required")
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 60 * time.Second
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	v := &Verifier{cfg: cfg}
	if cfg.KeysURL != "" {
		if err := checkKeysURL(cfg.KeysURL); err != nil {
			return nil, err
		}
		c := keys.NewCache(cfg.KeysURL)
		c.Issuer = cfg.Issuer
		if cfg.HTTPClient != nil {
			c.HTTPClient = cfg.HTTPClient
		}
		v.cache = c
	}
	return v, nil
}

// checkKeysURL refuses a keys endpoint that is not integrity-protected.
// Whoever answers this URL decides which public keys the verifier trusts, and
// therefore who can mint tokens it accepts — over plaintext that is anyone on
// the path. Loopback is exempt: it never leaves the host, and test servers and
// local development run there.
func checkKeysURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("anubis: KeysURL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("anubis: KeysURL %q is plaintext http — whoever answers it "+
			"decides which keys this verifier trusts; use https", raw)
	default:
		return fmt.Errorf("anubis: KeysURL %q: scheme must be https", raw)
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Verify checks signature, key validity window, expiry, nbf, issuer and
// audience, and returns the claims. It does NOT check epoch or session
// revocation — those need state only Anubis holds; use introspection when
// instant revocation matters.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	// The kid rides in the footer, which is authenticated by the signature —
	// but we must read it BEFORE verification to select the key. That
	// pre-verification read may only ever index the bounded key map.
	_, _, footer, err := paseto.Parse(token)
	if err != nil {
		return nil, err
	}
	var kid string
	if len(footer) > 0 {
		var tf tokenFooter
		if err := json.Unmarshal(footer, &tf); err != nil {
			return nil, fmt.Errorf("anubis: token footer: %w", err)
		}
		kid = tf.Kid
	}

	// One instant for the whole verification: a key that is inside its window
	// and a token that is inside its lifetime must be judged against the same
	// clock reading.
	now := v.cfg.now()

	pk, err := v.key(ctx, kid, now)
	if err != nil {
		return nil, err
	}
	msg, _, err := paseto.Verify(pk, token, nil)
	if err != nil {
		return nil, err
	}
	claims, err := parseClaims(msg)
	if err != nil {
		return nil, err
	}
	if claims.Version != 0 && claims.Version != 1 {
		return nil, ErrTokenVersion
	}
	if err := claims.Validate(now, v.cfg.Issuer, v.cfg.Audience, v.cfg.Leeway); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Verifier) key(ctx context.Context, kid string, now time.Time) (ed25519.PublicKey, error) {
	if v.cfg.StaticKeys != nil {
		if pk, ok := v.cfg.StaticKeys.GetAt(kid, now); ok {
			return pk, nil
		}
		if v.cache == nil {
			return nil, ErrUnknownKid
		}
	}
	return v.cache.GetAt(ctx, kid, now)
}
