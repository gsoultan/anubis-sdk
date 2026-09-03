package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// maxKeys bounds the kid map. kid is attacker-controlled input (it arrives in
// tokens); it may only ever index a bounded, pre-loaded, in-memory map —
// never a database query, filesystem path or per-token network fetch.
const maxKeys = 64

// Set is an immutable kid -> public key map.
type Set struct {
	keys map[string]entry
}

// entry pairs a key with the window it may be trusted in.
type entry struct {
	pk        ed25519.PublicKey
	notBefore int64
	notAfter  int64
}

// ParseDocument parses a published keys document.
//
// issuer, when non-empty, must match the document's own issuer. A verifier
// that loads whatever keys its URL happens to serve has no way to notice it
// was pointed at the wrong deployment — and whoever answers that URL decides
// which keys it trusts. A document that omits the field is accepted: the
// binding is only ever as good as what the issuer publishes.
func ParseDocument(raw []byte, issuer string) (*Set, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("anubis: keys document: %w", err)
	}
	if issuer != "" && doc.Issuer != "" && doc.Issuer != issuer {
		return nil, fmt.Errorf("anubis: keys document is issued by %q, expected %q", doc.Issuer, issuer)
	}
	if len(doc.Keys) > maxKeys {
		return nil, fmt.Errorf("anubis: keys document has %d keys, max %d", len(doc.Keys), maxKeys)
	}
	ks := &Set{keys: make(map[string]entry, len(doc.Keys))}
	for _, k := range doc.Keys {
		if k.Alg != "Ed25519" {
			continue // pinned algorithm; nothing negotiable
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("anubis: key %q: bad public key", k.Kid)
		}
		ks.keys[k.Kid] = entry{
			pk:        ed25519.PublicKey(raw),
			notBefore: k.NotBefore,
			notAfter:  k.NotAfter,
		}
	}
	return ks, nil
}

// GetAt returns the key for kid if the set holds it and now falls inside its
// published validity window. Either bound left at zero is unbounded.
//
// not_after is when a verifier stops *trusting* the key, not when the issuer
// stops signing with it: a token minted a second before the deadline is
// rejected the moment it passes. Publish not_after at least one maximum token
// lifetime past the last time the key will sign, or a rotation rejects tokens
// that are still legitimately live.
func (ks *Set) GetAt(kid string, now time.Time) (ed25519.PublicKey, bool) {
	e, ok := ks.keys[kid]
	if !ok {
		return nil, false
	}
	n := now.Unix()
	if e.notBefore != 0 && n < e.notBefore {
		return nil, false
	}
	if e.notAfter != 0 && n >= e.notAfter {
		return nil, false
	}
	return e.pk, true
}

// Get returns the key for kid as of now.
func (ks *Set) Get(kid string) (ed25519.PublicKey, bool) { return ks.GetAt(kid, time.Now()) }

// ErrUnknownKid: the token names a key this set does not hold, or one that has
// fallen outside its validity window. Rejected with zero I/O — attacker-
// controlled input must not drive lookups.
var ErrUnknownKid = errors.New("anubis: unknown kid")
