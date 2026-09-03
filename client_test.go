package anubis_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

const app = "billing-api"

// newTestServer is spelled out so identity_test.go can share it.
func newTestServer(t *testing.T) *anubistest.Server { return anubistest.NewServer(t) }

func newClient(t *testing.T, s *anubistest.Server, opts ...anubis.Option) *anubis.Client {
	t.Helper()
	base := []anubis.Option{
		anubis.WithApplication(app, ""),
		anubis.WithAPIKey("anb_live_ab12cd34_s3cr3t"),
		anubis.WithTenant("impack"),
	}
	c, err := anubis.New(s.URL, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// signedIn returns a context carrying a verified principal, as the middleware
// would have left it.
func signedIn(subject anubis.SubjectID, amr ...anubis.AuthMethod) context.Context {
	return anubis.WithPrincipal(context.Background(), &anubis.Principal{
		Token: "v4.public.test",
		Claims: &anubis.Claims{
			Subject: subject, AMR: amr, AuthTime: time.Now().Unix(),
		},
	})
}

// ---- sign-in --------------------------------------------------------------

func TestLoginRoundTrip(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)

	begin := httptest.NewRecorder()
	redirect, err := c.BeginLogin(begin, anubis.LoginParams{RedirectURI: "https://app.example.com/callback"})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	u, _ := url.Parse(redirect.URL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL is missing PKCE: %s", u.RawQuery)
	}
	if strings.Contains(redirect.URL, "code_verifier") {
		t.Fatal("the verifier must never reach the browser's URL bar")
	}

	tokens := completeLogin(t, c, s, begin, redirect, nil)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("no tokens: %+v", tokens)
	}
	if tokens.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want 600 (snake_case body must decode)", tokens.ExpiresIn)
	}
}

// completeLogin walks the browser leg and calls CompleteLogin. tamper, when
// set, rewrites the callback query first.
func completeLogin(t *testing.T, c *anubis.Client, s *anubistest.Server, begin *httptest.ResponseRecorder, redirect *anubis.Redirect, tamper func(url.Values)) *anubis.Tokens {
	t.Helper()
	location := s.AuthorizeRedirect(redirect.URL)
	if location == "" {
		t.Fatal("no redirect back from /v1/authorize")
	}
	cb, _ := url.Parse(location)
	if tamper != nil {
		q := cb.Query()
		tamper(q)
		cb.RawQuery = q.Encode()
	}
	req := httptest.NewRequest(http.MethodGet, cb.String(), nil)
	for _, ck := range begin.Result().Cookies() {
		req.AddCookie(ck)
	}
	tokens, err := c.CompleteLogin(context.Background(), httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	return tokens
}

func TestStateMismatchRefusesExchange(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)

	begin := httptest.NewRecorder()
	redirect, err := c.BeginLogin(begin, anubis.LoginParams{RedirectURI: "https://app.example.com/callback"})
	if err != nil {
		t.Fatal(err)
	}
	location := s.AuthorizeRedirect(redirect.URL)
	cb, _ := url.Parse(location)
	q := cb.Query()
	q.Set("state", "attacker-chosen-state")
	cb.RawQuery = q.Encode()

	req := httptest.NewRequest(http.MethodGet, cb.String(), nil)
	for _, ck := range begin.Result().Cookies() {
		req.AddCookie(ck)
	}
	before := s.Calls["TokenExchange"]
	_, err = c.CompleteLogin(context.Background(), httptest.NewRecorder(), req)

	var mismatch *anubis.StateMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want StateMismatchError, got %v", err)
	}
	if s.Calls["TokenExchange"] != before {
		t.Fatal("the code was exchanged despite a bad state — the check must happen first")
	}
}

func TestCallbackWithoutCookieIsRefused(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/callback?code=x&state=y", nil)

	_, err := c.CompleteLogin(context.Background(), httptest.NewRecorder(), req)
	var mismatch *anubis.StateMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want StateMismatchError, got %v", err)
	}
}

func TestLoginCookieIsSingleUse(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	begin := httptest.NewRecorder()
	redirect, _ := c.BeginLogin(begin, anubis.LoginParams{RedirectURI: "https://app.example.com/callback"})

	location := s.AuthorizeRedirect(redirect.URL)
	req := httptest.NewRequest(http.MethodGet, location, nil)
	for _, ck := range begin.Result().Cookies() {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	if _, err := c.CompleteLogin(context.Background(), w, req); err != nil {
		t.Fatalf("first CompleteLogin: %v", err)
	}
	// The store must have cleared the cookie on the way out.
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "anubis_login" && ck.MaxAge >= 0 {
			t.Fatal("login cookie was not consumed")
		}
	}
}

func TestDirectLoginChallenges(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)

	res, err := c.Login(context.Background(), anubis.Credentials{Username: "mfa-user", Password: "pw"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.NeedsMFA() || res.MFA.Token == "" {
		t.Fatalf("want an MFA challenge, got %+v", res)
	}

	// Enrol-or-deny: a refusal that carries the means to comply. The deadline
	// arrives as a JSON string, because protojson renders int64 that way.
	_, err = c.Login(context.Background(), anubis.Credentials{Username: "enrol-user", Password: "pw"})
	var enrol *anubis.EnrolmentRequiredError
	if !errors.As(err, &enrol) {
		t.Fatalf("want EnrolmentRequiredError, got %v", err)
	}
	if enrol.GrantToken == "" {
		t.Error("no grant token — the refusal carries no way to comply")
	}
	if enrol.Deadline.IsZero() || enrol.Deadline.Year() < 2000 {
		t.Errorf("deadline did not decode from its string form: %v", enrol.Deadline)
	}

	_, err = c.Login(context.Background(), anubis.Credentials{Username: "bad-user", Password: "pw"})
	var authErr *anubis.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want AuthError, got %v", err)
	}
}

// ---- refresh rotation -----------------------------------------------------

// TestConcurrentRefreshIsSingleFlight is the test this type exists for.
// Twenty handlers notice an expired token at once; exactly one refresh may
// leave the process, because the second one is a theft signal.
func TestConcurrentRefreshIsSingleFlight(t *testing.T) {
	s := anubistest.NewServer(t)
	s.RefreshDelay = 50 * time.Millisecond
	c := newClient(t, s)

	tokens := s.IssueSession("usr_test", app)
	tokens.ExpiresIn = 1
	tokens.IssuedAt = time.Now().Add(-time.Hour)
	ts := c.TokenSource(tokens)

	const n = 20
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	results := make([]anubis.Tokens, n)
	errs := make([]error, n)
	for i := range n {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = ts.Token(context.Background())
		}(i)
	}
	start.Done()
	done.Wait()

	if got := s.Calls["Refresh"]; got != 1 {
		t.Fatalf("Refresh called %d times, want exactly 1 — concurrent refreshes are what Anubis reads as theft", got)
	}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if results[i].AccessToken != results[0].AccessToken {
			t.Fatalf("goroutine %d got a different token; every waiter must share the one rotation", i)
		}
	}
}

func TestRefreshReuseIsTypedAndNotRetryable(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	tokens := s.IssueSession("usr_test", app)

	if _, err := c.Refresh(context.Background(), tokens.RefreshToken); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	// The same token again: two parties held it.
	_, err := c.Refresh(context.Background(), tokens.RefreshToken)

	var reuse *anubis.RefreshReuseError
	if !errors.As(err, &reuse) {
		t.Fatalf("want RefreshReuseError, got %T: %v", err, err)
	}
	// It must NOT also classify as a plain auth failure, or a caller with a
	// retry-on-AuthError path would retry a theft signal.
	var authErr *anubis.AuthError
	if errors.As(err, &authErr) {
		t.Fatal("reuse detection must not be reachable as AuthError")
	}
	// And the stable code must have survived the base64 protobuf detail.
	if !strings.Contains(err.Error(), "theft") {
		t.Errorf("error text lost its meaning: %v", err)
	}
}

func TestOnRotateRunsBeforeTokenReturns(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	tokens := s.IssueSession("usr_test", app)
	tokens.ExpiresIn = 1
	tokens.IssuedAt = time.Now().Add(-time.Hour)

	ts := c.TokenSource(tokens)
	var persisted anubis.Tokens
	ts.OnRotate(func(tk anubis.Tokens) error { persisted = tk; return nil })

	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.RefreshToken == "" {
		t.Fatal("OnRotate did not run before Token returned")
	}
	if persisted.RefreshToken != got.RefreshToken {
		t.Fatal("a different pair was persisted than was returned")
	}
	if persisted.RefreshToken == tokens.RefreshToken {
		t.Fatal("the refresh token did not rotate")
	}
}

func TestOnRotateFailureStillAdoptsTheNewPair(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	tokens := s.IssueSession("usr_test", app)
	tokens.ExpiresIn = 1
	tokens.IssuedAt = time.Now().Add(-time.Hour)

	ts := c.TokenSource(tokens)
	ts.OnRotate(func(anubis.Tokens) error { return errors.New("disk full") })

	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("a failed persist must be reported, not swallowed")
	}
	// The old refresh token is already dead server-side. Holding it would
	// guarantee a reuse refusal next time.
	if ts.Current().RefreshToken == tokens.RefreshToken {
		t.Fatal("the dead refresh token was kept after a persist failure")
	}
}

// ---- decisions ------------------------------------------------------------

func TestRequireAllowsAndDenies(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	ctx := signedIn("usr_1", "pwd")

	s.Allow("usr_1", "billing:invoice:approve")
	if err := c.Require(ctx, "billing:invoice:approve", anubis.Scopes{"org": "o1"}); err != nil {
		t.Fatalf("want allow, got %v", err)
	}

	s.Deny("usr_1", "billing:invoice:void", "scope_mismatch", "customer")
	err := c.Require(ctx, "billing:invoice:void", anubis.Scopes{"org": "o1"})
	var denied *anubis.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("want DeniedError, got %v", err)
	}
	if denied.FailingAxis != "customer" {
		t.Errorf("failing axis = %q, want customer — a deny that does not name the axis is a support ticket", denied.FailingAxis)
	}
}

func TestAuthorizeSendsAMRAndAuthTimeFromTheToken(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	s.RequireStepUp("usr_1", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")

	err := c.Require(signedIn("usr_1", "pwd"), "billing:invoice:approve", nil)
	var stepUp *anubis.StepUpRequiredError
	if !errors.As(err, &stepUp) {
		t.Fatalf("want StepUpRequiredError, got %v", err)
	}
	if len(stepUp.RequiredAMR) != 1 || stepUp.RequiredAMR[0] != anubis.MethodOTP {
		t.Errorf("required amr = %v, want [otp]", stepUp.RequiredAMR)
	}
	if stepUp.MaxAuthAge != "2m" {
		t.Errorf("max auth age = %q, want 2m", stepUp.MaxAuthAge)
	}
}

func TestBeginStepUpBuildsAReAuthRedirect(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	s.RequireStepUp("usr_1", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")

	err := c.Require(signedIn("usr_1", "pwd"), "billing:invoice:approve", nil)
	redirect, berr := c.BeginStepUp(httptest.NewRecorder(), err, anubis.LoginParams{
		RedirectURI: "https://app.example.com/callback",
	})
	if berr != nil {
		t.Fatalf("BeginStepUp: %v", berr)
	}
	q, _ := url.ParseQuery(strings.SplitN(redirect.URL, "?", 2)[1])
	if q.Get("prompt") != "login" {
		t.Error("a step-up must force re-authentication")
	}
	if q.Get("acr_values") != "otp" {
		t.Errorf("acr_values = %q, want otp", q.Get("acr_values"))
	}
	if q.Get("max_age") != "120" {
		t.Errorf("max_age = %q, want 120 (2m parsed)", q.Get("max_age"))
	}
}

func TestBeginStepUpRejectsOtherErrors(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	_, err := c.BeginStepUp(httptest.NewRecorder(), errors.New("something else"), anubis.LoginParams{
		RedirectURI: "https://app.example.com/callback",
	})
	if err == nil {
		t.Fatal("BeginStepUp must refuse an error that is not a step-up refusal")
	}
}

func TestAuthorizeWithoutPrincipalIsRefused(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	_, err := c.Authorize(context.Background(), "billing:invoice:approve", nil)
	if !errors.Is(err, anubis.ErrNoPrincipal) {
		t.Fatalf("want ErrNoPrincipal, got %v", err)
	}
}

func TestDecisionCacheServesRepeatsAndNeverCachesStepUp(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s, anubis.WithDecisionCache(anubis.CacheConfig{TTL: time.Minute, MaxSize: 100}))
	ctx := signedIn("usr_1", "pwd")

	s.Allow("usr_1", "billing:invoice:approve")
	for range 3 {
		if err := c.Require(ctx, "billing:invoice:approve", anubis.Scopes{"org": "o1"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Calls["Authorize"]; got != 1 {
		t.Errorf("Authorize called %d times, want 1 — the cache did not serve the repeats", got)
	}

	// A different scope is a different question and must not hit the entry
	// above.
	if err := c.Require(ctx, "billing:invoice:approve", anubis.Scopes{"org": "o2"}); err != nil {
		t.Fatal(err)
	}
	if got := s.Calls["Authorize"]; got != 2 {
		t.Errorf("Authorize called %d times, want 2 — the cache key ignored the scopes", got)
	}

	s.RequireStepUp("usr_1", "billing:invoice:void", anubis.AuthMethods{anubis.MethodOTP}, "2m")
	for range 3 {
		_ = c.Require(ctx, "billing:invoice:void", nil)
	}
	if got := s.Calls["Authorize"]; got != 5 {
		t.Errorf("Authorize called %d times, want 5 — a step-up refusal must never be cached", got)
	}
}

func TestExplainReturnsTheTree(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	x, err := c.Explain(signedIn("usr_1", "pwd"), "billing:invoice:void", nil)
	if err != nil {
		t.Fatal(err)
	}
	if x.FailingAxis != "customer" || x.Detail == "" {
		t.Fatalf("explanation is empty: %+v", x)
	}
}

func TestRequiresMiddleware(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	s.Allow("usr_1", "billing:invoice:approve")
	s.RequireStepUp("usr_2", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")

	reached := false
	h := c.Requires("billing:invoice:approve", anubis.AxesFrom(func(r *http.Request) anubis.Scopes {
		return anubis.Scopes{"org": r.URL.Query().Get("org")}
	}))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodGet, "/?org=o1", nil).WithContext(signedIn("usr_1", "pwd"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !reached || w.Code != http.StatusOK {
		t.Fatalf("allowed request did not reach the handler (code %d)", w.Code)
	}

	reached = false
	req = httptest.NewRequest(http.MethodGet, "/?org=o1", nil).WithContext(signedIn("usr_2", "pwd"))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if reached {
		t.Fatal("a step-up refusal reached the handler")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a step-up refusal", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_user_authentication") {
		t.Error("a step-up refusal must be machine-readable")
	}
}

// ---- introspection and client credentials ---------------------------------

func TestIntrospectDecodesInt64Strings(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	in, err := c.Introspect(context.Background(), "v4.public.whatever")
	if err != nil {
		t.Fatal(err)
	}
	if !in.Active || in.Subject != "usr_test" {
		t.Fatalf("bad introspection: %+v", in)
	}
	if in.Expires == 0 {
		t.Fatal("exp did not decode — protojson renders int64 as a JSON string")
	}
}

func TestClientCredentialsMintsAndReMints(t *testing.T) {
	s := anubistest.NewServer(t)
	c, err := anubis.New(s.URL,
		anubis.WithApplication("billing-batch", "shhh"),
		anubis.WithTenant("impack"))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := c.ClientCredentials(context.Background(), "reporting-api")
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	tok, err := ts.Token(context.Background())
	if err != nil || tok.AccessToken == "" {
		t.Fatalf("no token: %v", err)
	}
	// It has no refresh token, and must still be usable rather than erroring
	// with "no refresh token".
	if s.Calls["ClientCredentials"] != 1 {
		t.Errorf("minted %d times, want 1 while still valid", s.Calls["ClientCredentials"])
	}
}

// ---- back-channel logout --------------------------------------------------

func TestBackchannelLogoutCallsBackAndRejectsReplayedAccessTokens(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	v := s.Verifier(app)

	var got anubis.LogoutEvent
	h := c.BackchannelLogout(v, func(_ context.Context, ev anubis.LogoutEvent) error {
		got = ev
		return nil
	})

	post := func(token string) int {
		form := url.Values{"logout_token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if code := post(s.MintLogoutToken(app, "usr_test", "ses_42")); code != http.StatusNoContent {
		t.Fatalf("valid logout token got %d", code)
	}
	if got.SessionID != "ses_42" || got.Subject != "usr_test" {
		t.Fatalf("event did not carry the session: %+v", got)
	}

	// An ACCESS token is signed by the same key, for the same audience, by the
	// same issuer. Only the logout event claim tells them apart — without that
	// check, anyone holding a user's token could sign them out at will.
	access := s.MintToken(anubis.Claims{
		Subject: "usr_test", Audience: []string{app}, Session: "ses_42",
	})
	if code := post(access); code != http.StatusBadRequest {
		t.Fatalf("a replayed access token was accepted as a logout notification (got %d)", code)
	}
}

// ---- construction ---------------------------------------------------------

func TestNewRejectsBadConfiguration(t *testing.T) {
	cases := []struct {
		name string
		url  string
		opts []anubis.Option
	}{
		{"plain http", "http://anubis.example.com", nil},
		{"not an origin", "anubis.internal", nil},
		{"api key shape", "https://a.example.com", []anubis.Option{anubis.WithAPIKey("nope")}},
		{"two identities", "https://a.example.com", []anubis.Option{
			anubis.WithAPIKey("anb_live_ab12cd34_s3cr3t"), anubis.WithApplication("app", "secret"),
		}},
		{"authorization by hand", "https://a.example.com", []anubis.Option{
			anubis.WithHeader("Authorization", "Bearer x"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := anubis.New(tc.url, tc.opts...); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestCallWithoutCredentialIsRefused(t *testing.T) {
	s := anubistest.NewServer(t)
	c, err := anubis.New(s.URL, anubis.WithApplication(app, ""))
	if err != nil {
		t.Fatal(err)
	}
	// A principal with no token: nothing to present.
	ctx := anubis.WithPrincipal(context.Background(), &anubis.Principal{Claims: &anubis.Claims{Subject: "usr_1"}})
	if _, err := c.Authorize(ctx, "billing:invoice:approve", nil); !errors.Is(err, anubis.ErrNoCredential) {
		t.Fatalf("want ErrNoCredential, got %v", err)
	}
}
