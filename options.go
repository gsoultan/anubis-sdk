package anubis

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds a single call to Anubis. Short, because every call
// this client makes is on somebody's request path: a decision that has not
// arrived in ten seconds has already cost more than the denial would have.
const DefaultTimeout = 10 * time.Second

// An Option configures the client.
type Option func(*options) error

type options struct {
	httpClient   *http.Client
	timeout      time.Duration
	clientID     string
	clientSecret string
	apiKey       string
	tenant       string
	loginStore   LoginStore
	cache        *decisionCache
	headers      map[string]string
	now          func() time.Time
}

// WithApplication identifies the calling application by its registered slug —
// which is also its client_id, and the aud its tokens are minted for.
//
// The secret is optional and only meaningful for `web`, `server` and `service`
// applications; `spa` kinds have none, because a secret shipped to a browser
// is not a secret. Pass "" for those.
func WithApplication(clientID, clientSecret string) Option {
	return func(o *options) error {
		if clientID == "" {
			return errors.New("anubis: WithApplication needs a client id (the application slug)")
		}
		o.clientID, o.clientSecret = clientID, clientSecret
		return nil
	}
}

// WithAPIKey authenticates as the tenant with an anb_live_ key.
//
// The key is the tenant's credential, not a person's: it is what a trusted
// back end uses to ask Authorize and Explain about its own users. Keys are
// refused on the admin plane by design — administration is performed by
// platform operators, not by credentials an application holds.
func WithAPIKey(key string) Option {
	return func(o *options) error {
		if !strings.HasPrefix(key, "anb_live_") {
			return errors.New(`anubis: an api key looks like "anb_live_<prefix>_<secret>"`)
		}
		o.apiKey = key
		return nil
	}
}

// WithTenant sets the tenant slug used by the browser flows and the direct
// Login call. Single-tenant installations can leave it unset.
func WithTenant(slug string) Option {
	return func(o *options) error { o.tenant = slug; return nil }
}

// WithHTTPClient supplies the HTTP client to call with — for a custom
// transport, a proxy, or a connection pool shared with the rest of an
// application. Its own Timeout is left alone; WithTimeout is ignored when this
// is set, since a caller who brings a client has already made that decision.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) error {
		if c == nil {
			return errors.New("anubis: WithHTTPClient needs a client")
		}
		o.httpClient = c
		return nil
	}
}

// WithTimeout bounds each call. Ignored when WithHTTPClient is used.
//
// This is a ceiling, not a schedule: a context deadline shorter than it still
// wins.
func WithTimeout(d time.Duration) Option {
	return func(o *options) error { o.timeout = d; return nil }
}

// WithLoginStore replaces the default cookie storage for in-flight logins.
//
// The default keeps the PKCE verifier and state in a short-lived, HttpOnly,
// SameSite=Lax cookie on your own origin, which works without any
// infrastructure. Supply your own when a server-side session or a shared cache
// is a better fit — a load-balanced fleet with sticky-session problems, or a
// callback handled by a different process than the redirect.
func WithLoginStore(s LoginStore) Option {
	return func(o *options) error {
		if s == nil {
			return errors.New("anubis: WithLoginStore needs a store")
		}
		o.loginStore = s
		return nil
	}
}

// CacheConfig configures short-lived caching of authorization decisions.
type CacheConfig struct {
	// TTL is how long an allow may be reused — and therefore, exactly, how
	// long a disabled identity keeps its access after deprovisioning. Anubis
	// promises a disabled identity is denied on the next decision; a cache
	// makes that "the next decision after this TTL". Choose it knowing that.
	TTL time.Duration
	// MaxSize bounds the entry count. The key includes the subject and the
	// scope values, both of which come from the request, so an unbounded map
	// here is a memory exhaustion primitive.
	MaxSize int
}

// WithDecisionCache enables decision caching. It is off by default.
//
// The key is the full (subject, permission, scopes, amr, auth_time) tuple: a
// cache keyed on anything less answers one caller's question with another
// caller's answer, which is a data leak wearing a performance costume.
//
// Denials carrying step_up_required are never cached. They become stale the
// instant the user re-authenticates, which is the entire point of them, and a
// cached one would send a user who has just done everything asked of them
// round the step-up loop a second time.
func WithDecisionCache(cfg CacheConfig) Option {
	return func(o *options) error {
		if cfg.TTL <= 0 {
			return errors.New("anubis: WithDecisionCache needs a positive TTL")
		}
		if cfg.MaxSize <= 0 {
			cfg.MaxSize = 10_000
		}
		o.cache = newDecisionCache(cfg)
		return nil
	}
}

// WithHeader sets an extra HTTP header on every request — a tracing header, or
// whatever a proxy in front of Anubis requires.
//
// Authorization is not settable this way: it is what WithAPIKey is for, and a
// second source for it would only make a mismatch possible.
func WithHeader(name, value string) Option {
	return func(o *options) error {
		if strings.EqualFold(name, "Authorization") {
			return errors.New("anubis: set the credential with WithAPIKey, not with WithHeader")
		}
		if o.headers == nil {
			o.headers = map[string]string{}
		}
		o.headers[name] = value
		return nil
	}
}

func newOptions(opts []Option) (options, error) {
	o := options{timeout: DefaultTimeout, now: time.Now}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return o, err
		}
	}
	if o.apiKey != "" && o.clientSecret != "" {
		// Two credentials means two identities: the tenant's system, and the
		// application acting as itself. A client holding both would pick one
		// by accident, and the audit trail would name the wrong caller.
		return o, errors.New("anubis: WithAPIKey and a client secret are different callers — configure one client for each")
	}
	if o.httpClient == nil {
		o.httpClient = &http.Client{Timeout: o.timeout}
	}
	// Copied rather than mutated: a caller's client may be shared with the rest
	// of the application, and its redirect policy is not ours to change on it.
	// The copy keeps the Transport pointer, so the connection pool is still the
	// caller's — only the redirect decision is ours.
	noRedirect := *o.httpClient
	noRedirect.CheckRedirect = refuseRedirect
	o.httpClient = &noRedirect

	if o.loginStore == nil {
		o.loginStore = &cookieStore{}
	}
	return o, nil
}

// refuseRedirect stops a redirect being followed on an API call.
//
// net/http drops Authorization when a redirect crosses to another host, but it
// does not drop a request body, and it has never heard of X-Anubis-Tenant.
// A Connect procedure has no reason to redirect, so the safe reading of one is
// that something is in front of Anubis that should not be.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("anubis: the server redirected to %s; refusing to follow it with a credential attached", req.URL.Redacted())
}
