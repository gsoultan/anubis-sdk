package anubis

import (
	"net/http"
	"time"

	"github.com/gsoultan/anubis-sdk/keys"
)

// Config configures offline verification.
type Config struct {
	// Issuer must match the token's iss claim exactly. It is also matched
	// against the issuer named in the keys document, so a verifier pointed at
	// the wrong deployment's KeysURL fails loudly instead of trusting it.
	Issuer string
	// Audience is this service's identifier. Mandatory: a verifier without an
	// audience accepts tokens minted for other services (confused deputy).
	Audience string
	// KeysURL is the discovery endpoint
	// (https://anubis.internal/.well-known/anubis-keys.json). Either KeysURL
	// or StaticKeys must be set. It must be https unless it points at
	// loopback: whoever answers it decides which keys this verifier trusts.
	KeysURL string
	// StaticKeys pins keys directly (air-gapped consumers, tests).
	StaticKeys *keys.Set
	// HTTPClient fetches the keys document. Supply one to trust a private CA
	// — an .internal deployment's chain is not in the system pool — or to
	// route through a proxy. Defaults to a client with a 5s timeout.
	HTTPClient *http.Client
	// Leeway absorbs clock skew between services. Default 60s; enforce NTP.
	Leeway time.Duration
	// now is a test seam.
	now func() time.Time
}
