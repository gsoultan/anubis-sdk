package anubis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// loginCookie holds the in-flight login. Short-lived, HttpOnly and
// SameSite=Lax — Lax rather than Strict because the browser arrives back from
// Anubis's origin by top-level navigation, and Strict would withhold the
// cookie on exactly the request that needs it.
const loginCookie = "anubis_login"

// loginTTL bounds how long a started sign-in may be completed. Ten minutes is
// generous for a password and a second factor, and short enough that an
// abandoned login is not a credential lying around.
const loginTTL = 10 * time.Minute

// Pending is an in-flight login: the PKCE verifier and the state, which have
// to survive a browser round trip and must never reach the browser's URL bar.
type Pending struct {
	State       string    `json:"s"`
	Verifier    string    `json:"v"`
	RedirectURI string    `json:"r"`
	Created     time.Time `json:"c"`
}

// LoginStore keeps a Pending between the redirect and the callback.
//
// The interface takes the ResponseWriter and Request deliberately: what makes
// the state check worth anything is that the pending login is bound to the
// browser that started it. A store keyed only on the state parameter can
// verify that some login produced this state, not that THIS browser did — and
// the attack the state parameter exists to stop is precisely an attacker
// feeding a victim's browser a callback from the attacker's own sign-in.
// Every implementation therefore has to talk to the browser somehow.
type LoginStore interface {
	// Put records the pending login, setting whatever the browser must carry.
	Put(w http.ResponseWriter, p Pending) error
	// Take returns the pending login and consumes it. A login state is
	// single-use: a store that hands the same one out twice reopens the replay
	// that state exists to close.
	Take(w http.ResponseWriter, r *http.Request) (Pending, error)
}

// cookieStore is the default: the whole pending login lives in one HttpOnly
// cookie on your own origin. No infrastructure, no shared state between
// replicas, and nothing to clean up when a user abandons a sign-in.
//
// The verifier in it is not a secret from the user — PKCE protects against an
// attacker who intercepts the code, not against the user — so it needs no
// encryption. It does need HttpOnly, so that a script on your origin cannot
// read it and complete somebody else's sign-in.
type cookieStore struct{}

func (cookieStore) Put(w http.ResponseWriter, p Pending) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/",
		MaxAge:   int(loginTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (cookieStore) Take(w http.ResponseWriter, r *http.Request) (Pending, error) {
	var p Pending
	c, err := r.Cookie(loginCookie)
	if err != nil {
		return p, &StateMismatchError{Reason: "no login in progress for this browser"}
	}
	// Consumed whatever happens next: a login that failed to complete must not
	// leave a reusable verifier behind.
	http.SetCookie(w, &http.Cookie{
		Name: loginCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return p, &StateMismatchError{Reason: "login cookie is unreadable"}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, &StateMismatchError{Reason: "login cookie is unreadable"}
	}
	return p, nil
}

// LoginParams starts a browser sign-in.
type LoginParams struct {
	// RedirectURI must be registered on the application, and is matched
	// exactly — no wildcards, no prefixes. An open redirect in an SSO service
	// is full account takeover, so there is no fuzz in the match.
	RedirectURI string
	// Scope defaults to ["openid"].
	Scope []string
	// Realm selects the identity population; empty means "internal".
	Realm string
	// Page picks a specific sign-in page by slug. Most specific wins:
	// this, then the application's own page, then the tenant default.
	Page string
	// Tenant overrides the client's configured tenant.
	Tenant string
	// Nonce is passed through untouched for callers who bind it themselves.
	Nonce string
	// Prompt, when set to "login", forces re-authentication even if an SSO
	// session is live. StepUpURL sets it for you.
	Prompt string
	// ACRValues carries required authentication methods for a step-up.
	ACRValues []string
	// MaxAge caps how old the authentication may be, in seconds.
	MaxAge int
}

// Redirect is where to send the browser.
type Redirect struct {
	URL   string
	State string
}

// BeginLogin starts an authorization-code sign-in with PKCE.
//
// It generates the code verifier and the state, stores both where the callback
// can find them, and returns the URL to redirect to. Send the browser there:
//
//	redirect, err := client.BeginLogin(w, anubis.LoginParams{
//	    RedirectURI: "https://billing.example.com/callback",
//	})
//	http.Redirect(w, r, redirect.URL, http.StatusFound)
func (c *Client) BeginLogin(w http.ResponseWriter, p LoginParams) (*Redirect, error) {
	if c.opts.clientID == "" {
		return nil, errors.New("anubis: BeginLogin needs the application slug — configure WithApplication")
	}
	if p.RedirectURI == "" {
		return nil, errors.New("anubis: BeginLogin needs a RedirectURI, and it must be one registered on the application")
	}
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, err
	}
	pending := Pending{State: state, Verifier: verifier, RedirectURI: p.RedirectURI, Created: c.opts.now()}
	if err := c.opts.loginStore.Put(w, pending); err != nil {
		return nil, fmt.Errorf("anubis: storing the pending login: %w", err)
	}

	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.opts.clientID},
		"redirect_uri":          {p.RedirectURI},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	q.Set("scope", joinOrDefault(p.Scope, " ", "openid"))
	setIf(q, "tenant", firstNonEmpty(p.Tenant, c.opts.tenant))
	setIf(q, "realm", p.Realm)
	setIf(q, "page", p.Page)
	setIf(q, "nonce", p.Nonce)
	setIf(q, "prompt", p.Prompt)
	setIf(q, "acr_values", joinOrDefault(p.ACRValues, " ", ""))
	if p.MaxAge > 0 {
		q.Set("max_age", fmt.Sprint(p.MaxAge))
	}
	return &Redirect{URL: c.baseURL + pathAuthorize + "?" + q.Encode(), State: state}, nil
}

// CompleteLogin handles the callback: it checks the state, exchanges the code
// and returns the tokens.
//
// The state comparison happens here, before anything is exchanged, and it is
// not optional — there is no parameter that turns it off and no variant of
// this method that skips it. A caller cannot forget a check that was never
// theirs to make.
func (c *Client) CompleteLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Tokens, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return nil, &APIError{Code: e, Message: q.Get("error_description"), Status: http.StatusBadRequest}
	}
	pending, err := c.opts.loginStore.Take(w, r)
	if err != nil {
		return nil, err
	}
	if c.opts.now().Sub(pending.Created) > loginTTL {
		return nil, &StateMismatchError{Reason: "the sign-in took longer than " + loginTTL.String()}
	}
	// Constant time because the comparison is against an attacker-supplied
	// value, and a state that leaks byte by byte is a state that can be
	// guessed.
	got := q.Get("state")
	if len(got) != len(pending.State) ||
		subtle.ConstantTimeCompare([]byte(got), []byte(pending.State)) != 1 {
		return nil, &StateMismatchError{Reason: "callback state is not the one this browser was sent with"}
	}
	code := q.Get("code")
	if code == "" {
		return nil, &StateMismatchError{Reason: "callback carried no code"}
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {pending.Verifier},
		"redirect_uri":  {pending.RedirectURI},
		"client_id":     {c.opts.clientID},
	}
	// Sent for confidential applications because the discovery document
	// advertises client_secret_post. Note that the token endpoint does not
	// currently verify it: PKCE is what actually binds the exchange. Sending
	// it costs nothing and means this client is already correct when the
	// server starts checking.
	setIf(form, "client_secret", c.opts.clientSecret)

	var out httpTokens
	if err := c.form(ctx, pathToken, form, &out); err != nil {
		return nil, err
	}
	return out.tokens(c.opts.now()), nil
}

// Login signs in directly, without a browser.
//
// For first-party native and CLI applications only. A third-party application
// collecting a password is a phishing lesson taught to your own users; send
// those through BeginLogin instead.
func (c *Client) Login(ctx context.Context, cred Credentials) (*LoginResult, error) {
	req := map[string]any{
		"tenant":    firstNonEmpty(cred.Tenant, c.opts.tenant),
		"realm":     cred.Realm,
		"username":  cred.Username,
		"password":  cred.Password,
		"client_id": firstNonEmpty(cred.ClientID, c.opts.clientID),
		"device_fp": cred.DeviceFP,
	}
	var out LoginResult
	if err := c.rpcNoAuth(ctx, procLogin, req, &out); err != nil {
		return nil, err
	}
	c.stamp(out.Tokens)
	if out.EnrolmentRequired != nil {
		return &out, &EnrolmentRequiredError{
			Factors:    out.EnrolmentRequired.Factors,
			Deadline:   out.EnrolmentRequired.DeadlineTime(),
			GrantToken: out.EnrolmentRequired.GrantToken,
		}
	}
	return &out, nil
}

// VerifyMFA finishes a sign-in that stopped for a second factor.
func (c *Client) VerifyMFA(ctx context.Context, mfaToken, code string) (*Tokens, error) {
	var out struct {
		Tokens *Tokens `json:"tokens"`
	}
	req := map[string]any{"mfa_token": mfaToken, "code": code}
	if err := c.rpcNoAuth(ctx, procVerifyMfa, req, &out); err != nil {
		return nil, err
	}
	if out.Tokens == nil {
		return nil, errors.New("anubis: mfa verification returned no tokens")
	}
	c.stamp(out.Tokens)
	return out.Tokens, nil
}

// rpcNoAuth calls a procedure that authenticates by its own payload — sign-in
// and refresh carry the credential in the body, and demanding an ambient one
// as well would make it impossible to sign in for the first time.
func (c *Client) rpcNoAuth(ctx context.Context, procedure string, in, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+procedure, jsonBody(in))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) stamp(t *Tokens) {
	if t != nil {
		t.IssuedAt = c.opts.now()
	}
}

// randomToken produces 256 bits of base64url, which is both a valid PKCE code
// verifier (43 characters, inside the spec's 43..128) and an unguessable state.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("anubis: generating a random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func setIf(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}

func joinOrDefault(vs []string, sep, def string) string {
	if len(vs) == 0 {
		return def
	}
	out := vs[0]
	for _, v := range vs[1:] {
		out += sep + v
	}
	return out
}
