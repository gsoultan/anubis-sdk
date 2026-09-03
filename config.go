package anubis

import (
	"time"

	"github.com/gsoultan/anubis-sdk/keys"
)

// Config configures offline verification.
type Config struct {
	// Issuer must match the token's iss claim exactly.
	Issuer string
	// Audience is this service's identifier. Mandatory: a verifier without an
	// audience accepts tokens minted for other services (confused deputy).
	Audience string
	// KeysURL is the discovery endpoint
	// (https://anubis.internal/.well-known/anubis-keys.json). Either KeysURL
	// or StaticKeys must be set.
	KeysURL string
	// StaticKeys pins keys directly (air-gapped consumers, tests).
	StaticKeys *keys.Set
	// Leeway absorbs clock skew between services. Default 60s; enforce NTP.
	Leeway time.Duration
	// now is a test seam.
	now func() time.Time
}
