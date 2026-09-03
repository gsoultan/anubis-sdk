package anubis

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Decision is Anubis's answer.
//
// A denial is an answer, not a failure: the reason and the failing axis are
// always populated on a refusal, because a deny nobody can explain is a
// support ticket.
type Decision struct {
	Allow       bool        `json:"allow"`
	Reason      string      `json:"reason"`
	FailingAxis Axis        `json:"failingAxis"`
	Message     string      `json:"message"`
	RequiredAMR AuthMethods `json:"requiredAmr"`
	MaxAuthAge  string      `json:"maxAuthAge"`
	CurrentAMR  AuthMethods `json:"currentAmr"`
	AuthAge     string      `json:"authAge"`

	permission Permission
	subject    SubjectID
}

// Permission is what was asked about.
func (d Decision) Permission() Permission { return d.permission }

// Subject is who it was asked about.
func (d Decision) Subject() SubjectID { return d.subject }

// NeedsStepUp reports whether the refusal can be cured by re-authenticating.
func (d Decision) NeedsStepUp() bool { return d.Reason == codeStepUpRequired }

// MaxAuthAgeDuration is how fresh the authentication has to be, parsed. Anubis
// sends it as a string; a caller comparing durations should not have to.
func (d Decision) MaxAuthAgeDuration() (time.Duration, bool) { return parseAge(d.MaxAuthAge) }

// Err renders a refusal as a typed error, or nil when allowed.
func (d Decision) Err() error {
	if d.Allow {
		return nil
	}
	if d.NeedsStepUp() {
		return &StepUpRequiredError{
			RequiredAMR: d.RequiredAMR,
			CurrentAMR:  d.CurrentAMR,
			MaxAuthAge:  d.MaxAuthAge,
			AuthAge:     d.AuthAge,
			Permission:  d.permission,
			Subject:     d.subject,
		}
	}
	return &DeniedError{
		Reason:      d.Reason,
		FailingAxis: d.FailingAxis,
		Message:     d.Message,
		Permission:  d.permission,
		Subject:     d.subject,
	}
}

// Explanation is why a decision went the way it did: which grant matched,
// which role conferred the permission, and on a denial exactly which axis
// failed. Detail is the full evaluation tree as JSON — the same one the
// console's access playground renders.
type Explanation struct {
	Allow       bool   `json:"allow"`
	Reason      string `json:"reason"`
	FailingAxis Axis   `json:"failingAxis"`
	Detail      string `json:"detailJson"`
}

// Require asks whether the verified caller may do something, and returns a
// typed error if not.
//
// The subject, the authentication methods and the authentication time are read
// from the principal the middleware verified. That is not convenience: amr and
// auth_time are what make step-up decisions possible, and a caller assembling
// this request by hand will leave them out — turning every step-up rule into a
// silent, permanent denial that looks like a permissions bug.
func (c *Client) Require(ctx context.Context, permission Permission, scopes Scopes) error {
	d, err := c.Authorize(ctx, permission, scopes)
	if err != nil {
		return err
	}
	return d.Err()
}

// Authorize asks the same question and returns the answer as data, for callers
// to whom a denial is a value rather than an error — rendering a page with the
// approve button hidden, say.
func (c *Client) Authorize(ctx context.Context, permission Permission, scopes Scopes) (Decision, error) {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return Decision{}, ErrNoPrincipal
	}
	return c.authorize(ctx, id.Subject, permission, scopes, id.Methods, id.AuthenticatedAt().Unix())
}

// AuthorizeSubject asks about a named subject rather than the verified caller.
//
// For back ends that hold a tenant API key and ask about their users — a batch
// job, an admin screen. Pass the subject's own methods and authentication time
// when you have them; passing none means step-up rules can only ever deny.
func (c *Client) AuthorizeSubject(ctx context.Context, subject SubjectID, permission Permission, scopes Scopes, methods AuthMethods, authTime time.Time) (Decision, error) {
	var at int64
	if !authTime.IsZero() {
		at = authTime.Unix()
	}
	return c.authorize(ctx, subject, permission, scopes, methods, at)
}

func (c *Client) authorize(ctx context.Context, subject SubjectID, permission Permission, scopes Scopes, methods AuthMethods, authTime int64) (Decision, error) {
	if subject == "" {
		return Decision{}, errors.New("anubis: authorize needs a subject")
	}
	if permission == "" {
		return Decision{}, errors.New(`anubis: authorize needs a permission, like "billing:invoice:approve"`)
	}
	if !permission.IsValid() {
		// Caught here rather than answered with a denial, because a denial for
		// a permission that cannot exist is indistinguishable from one for a
		// permission the caller does not hold.
		return Decision{}, fmt.Errorf("anubis: %q is not a permission key — expected app:resource:action", permission)
	}
	var key string
	if c.opts.cache != nil {
		key = cacheKey(subject, permission, scopes, methods, authTime)
		if d, ok := c.opts.cache.get(key, c.opts.now()); ok {
			d.permission, d.subject = permission, subject
			return d, nil
		}
	}

	req := map[string]any{
		"subject":    string(subject),
		"permission": string(permission),
		"scopes":     scopes.wire(),
		"amr":        methods.Strings(),
		"auth_time":  authTime,
	}
	var d Decision
	if err := c.rpc(ctx, procAuthorize, req, &d); err != nil {
		return Decision{}, err
	}
	d.permission, d.subject = permission, subject
	if c.opts.cache != nil {
		c.opts.cache.put(key, d, c.opts.now())
	}
	return d, nil
}

// Explain returns the full evaluation tree for a decision.
//
// Reach for it the moment a denial is not obvious. It is not a debugging
// afterthought: past two axes, "why was this denied" stops being answerable by
// reading the grant table.
func (c *Client) Explain(ctx context.Context, permission Permission, scopes Scopes) (*Explanation, error) {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return nil, ErrNoPrincipal
	}
	req := map[string]any{
		"subject":    string(id.Subject),
		"permission": string(permission),
		"scopes":     scopes.wire(),
	}
	var out Explanation
	if err := c.rpc(ctx, procExplain, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BeginStepUp turns a step-up refusal into the sign-in redirect that satisfies
// it, so the caller does not have to work out what "required_amr" means.
//
// It is a fresh authorization request — new PKCE, new state — because that is
// what re-authentication is. After the user comes back through CompleteLogin,
// retry the action.
func (c *Client) BeginStepUp(w http.ResponseWriter, err error, p LoginParams) (*Redirect, error) {
	var stepUp *StepUpRequiredError
	if !errors.As(err, &stepUp) {
		return nil, fmt.Errorf("anubis: BeginStepUp needs a step-up refusal, got %w", err)
	}
	p.Prompt = "login"
	if len(p.ACRValues) == 0 {
		p.ACRValues = stepUp.RequiredAMR.Strings()
	}
	if p.MaxAge == 0 {
		if d, ok := stepUp.MaxAuthAgeDuration(); ok {
			p.MaxAge = int(d / time.Second)
		}
	}
	return c.BeginLogin(w, p)
}

// ScopeFunc derives the scope set for a request.
//
// Scopes are a function of the request, not a constant: the organisation and
// the customer live in the path or the body. A static map would only be right
// for routes where scoping does not matter, and those are the routes that do
// not need this.
type ScopeFunc func(*http.Request) Scopes

// AxesFrom adapts a plain function into a ScopeFunc.
func AxesFrom(f func(*http.Request) Scopes) ScopeFunc { return ScopeFunc(f) }

// Requires guards a handler with a permission check.
//
// Mount it inside the verifier's middleware, which is what puts the principal
// in the context. A refusal answers 403, except a step-up refusal which
// answers 401 with insufficient_user_authentication — the same machine-readable
// signal RequireAMR uses, so a client that already handles one handles both.
func (c *Client) Requires(permission Permission, scopes ScopeFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var s Scopes
			if scopes != nil {
				s = scopes(r)
			}
			err := c.Require(r.Context(), permission, s)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
			var stepUp *StepUpRequiredError
			if errors.As(err, &stepUp) {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication"`)
				http.Error(w, "step-up authentication required", http.StatusUnauthorized)
				return
			}
			var denied *DeniedError
			if errors.As(err, &denied) {
				http.Error(w, denied.Message, http.StatusForbidden)
				return
			}
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		})
	}
}

// Ask is one question for AuthorizeMany.
type Ask struct {
	Permission Permission
	Scopes     Scopes
}

// AuthorizeMany asks about several permission/scope pairs at once.
//
// This is N round trips with bounded concurrency, not a batch call: Anubis has
// no batch decision procedure today, and pretending otherwise by hiding the
// loop would only make the cost harder to see. For a list page of any size,
// prefer restructuring the question — ask once for the axis nodes the subject
// holds the permission on, and filter in your own query.
func (c *Client) AuthorizeMany(ctx context.Context, asks []Ask) ([]Decision, error) {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return nil, ErrNoPrincipal
	}
	const maxInFlight = 8
	out := make([]Decision, len(asks))
	errs := make([]error, len(asks))
	authTime := id.AuthenticatedAt().Unix()

	sem := make(chan struct{}, maxInFlight)
	var wg sync.WaitGroup
	for i, a := range asks {
		wg.Add(1)
		go func(i int, a Ask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = c.authorize(ctx, id.Subject, a.Permission, a.Scopes, id.Methods, authTime)
		}(i, a)
	}
	wg.Wait()
	return out, errors.Join(errs...)
}

// SwitchScope re-issues the caller's tokens pinned to a different active
// scope, without re-authentication. Mirrors AWS AssumeRole.
//
// Anubis refuses a scope the caller is not entitled to, so this doubles as the
// only way an application can find out whether a move is allowed: there is no
// procedure that lists the nodes somebody may switch to.
func (c *Client) SwitchScope(ctx context.Context, scopes Scopes) (*Tokens, error) {
	var out struct {
		Tokens *Tokens `json:"tokens"`
	}
	req := map[string]any{"scopes": scopes.wire()}
	if err := c.rpc(ctx, procSwitchScope, req, &out); err != nil {
		return nil, err
	}
	if out.Tokens == nil {
		return nil, errors.New("anubis: scope switch returned no tokens")
	}
	c.stamp(out.Tokens)
	return out.Tokens, nil
}

// Introspect asks Anubis for live token state, including revocation.
//
// Offline verification cannot see a session that died before the token
// expired. Where "valid until expiry" is unacceptable — admin planes,
// irreversible actions — this closes that window, at the price of a network
// hop on the path.
func (c *Client) Introspect(ctx context.Context, token string) (*Introspection, error) {
	var out Introspection
	if err := c.rpc(ctx, procIntrospect, map[string]any{"token": token}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Me returns the signed-in caller's own view of themselves.
//
// Richer than the token: it carries the EFFECTIVE PERMISSION KEYS, expanded
// from every role held, which the token does not. That set is what a front end
// needs to decide which buttons to draw — though drawing a button is not the
// same as being allowed to press it, and the press still goes through Require.
//
// ActiveScopes is still the active scope, one node per axis. Neither this nor
// the token can tell you every node the person is entitled to; that lives in
// grants, on the admin plane.
func (c *Client) Me(ctx context.Context) (*Me, error) {
	var out Me
	if err := c.rpc(ctx, procGetMe, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Sessions lists the caller's signed-in devices.
func (c *Client) Sessions(ctx context.Context) ([]Session, error) {
	var out struct {
		Sessions []Session `json:"sessions"`
	}
	if err := c.rpc(ctx, procListSessions, struct{}{}, &out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}

// parseAge reads a duration Anubis expressed as a string ("2m").
func parseAge(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
