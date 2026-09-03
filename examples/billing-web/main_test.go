package main

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

const slug = "billing-web"

// start brings up an in-process Anubis and the example application in front of
// it. The application is served over TLS because its cookies are Secure, and a
// Secure cookie is not sent over plain http — so a plain-http harness would
// pass a sign-in test that a browser would fail.
func start(t *testing.T) (*anubistest.Server, *app, *httptest.Server) {
	t.Helper()
	an := anubistest.NewServer(t)

	var handler http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	// The application needs its own origin to build redirect_uri, which is only
	// known once the listener is up — hence the indirection above.
	a, err := newApp(config{
		AnubisURL: an.URL,
		AppURL:    srv.URL,
		Slug:      slug,
		APIKey:    "anb_live_ab12cd34_s3cr3t",
		Tenant:    "impack",
	})
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	handler = a.routes()
	return an, a, srv
}

// browser is a client that keeps cookies and follows redirects, which is the
// only way to exercise a sign-in the way the thing signing in actually works.
func browser(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := srv.Client()
	c.Jar = jar
	return c
}

func TestSignInThroughToDashboard(t *testing.T) {
	_, a, srv := start(t)
	c := browser(t, srv)

	// One request. It redirects to Anubis, Anubis bounces back with a code, the
	// callback exchanges it, and the dashboard renders.
	res, err := c.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("landed on %s with status %d", res.Request.URL.Path, res.StatusCode)
	}
	if got := res.Request.URL.Path; got != "/dashboard" {
		t.Fatalf("ended on %q, want /dashboard", got)
	}
	body := read(t, res)
	if !strings.Contains(body, "signed in as usr_test") {
		t.Fatalf("dashboard did not render the signed-in user: %q", body)
	}
	if len(a.sessions.byID) != 1 {
		t.Fatalf("got %d application sessions, want 1", len(a.sessions.byID))
	}
}

func TestCallbackFromNowhereIsRefused(t *testing.T) {
	_, a, srv := start(t)
	c := browser(t, srv)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// A callback that this browser never started: no login cookie, so no state
	// to compare against. The code is never exchanged.
	res, err := c.Get(srv.URL + "/callback?code=stolen&state=guessed")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", res.StatusCode)
	}
	if len(a.sessions.byID) != 0 {
		t.Fatal("a session was created from an unverified callback")
	}
}

// api calls the bearer-token side of the application.
func api(t *testing.T, srv *httptest.Server, method, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

func TestApproveInvoice(t *testing.T) {
	an, _, srv := start(t)
	token := an.MintToken(anubis.Claims{
		Subject: "usr_1", Audience: []string{slug}, Session: "ses_1", AMR: anubis.AuthMethods{anubis.MethodPassword},
	})

	t.Run("no token at all is rejected before any handler runs", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/invoices/7/approve", nil)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", res.StatusCode)
		}
	})

	t.Run("a token minted for another application is rejected", func(t *testing.T) {
		other := an.MintToken(anubis.Claims{Subject: "usr_1", Audience: []string{"hr-web"}})
		res := api(t, srv, http.MethodPost, "/api/invoices/7/approve", other)
		defer res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 — the aud check is what stops this", res.StatusCode)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		an.Allow("usr_1", "billing:invoice:approve")
		res := api(t, srv, http.MethodPost, "/api/invoices/7/approve", token)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", res.StatusCode)
		}
		if body := read(t, res); !strings.Contains(body, "approved invoice 7") {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("denied, naming the axis", func(t *testing.T) {
		an.Deny("usr_1", "billing:invoice:approve", "scope_mismatch", "customer")
		res := api(t, srv, http.MethodPost, "/api/invoices/7/approve", token)
		defer res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", res.StatusCode)
		}
		if body := read(t, res); !strings.Contains(body, "customer") {
			t.Fatalf("the refusal did not mention the failing axis: %q", body)
		}
	})

	t.Run("step-up, with somewhere to send the user", func(t *testing.T) {
		an.RequireStepUp("usr_1", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")
		res := api(t, srv, http.MethodPost, "/api/invoices/7/approve", token)
		defer res.Body.Close()

		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", res.StatusCode)
		}
		if !strings.Contains(res.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
			t.Error("a step-up refusal must be machine-readable")
		}
		// The application did not invent a second factor: it asked Anubis for
		// one, with the requirement Anubis stated.
		loc, err := url.Parse(res.Header.Get("Location"))
		if err != nil || loc.Path != "/v1/authorize" {
			t.Fatalf("Location = %q, want an /v1/authorize redirect", res.Header.Get("Location"))
		}
		q := loc.Query()
		if q.Get("prompt") != "login" || q.Get("acr_values") != "otp" || q.Get("max_age") != "120" {
			t.Fatalf("step-up did not carry the requirement: %v", q)
		}
		if q.Get("code_challenge") == "" {
			t.Error("step-up must be a fresh authorization request, PKCE and all")
		}
	})
}

func TestBackchannelLogoutEndsOurSessionToo(t *testing.T) {
	an, a, srv := start(t)
	c := browser(t, srv)

	if _, err := c.Get(srv.URL + "/login"); err != nil {
		t.Fatal(err)
	}
	var sid anubis.SessionID
	for _, s := range a.sessions.byID {
		sid = s.sid
	}
	if sid == "" {
		t.Fatal("no session was established")
	}

	// The user signs out on another application. Anubis notifies us.
	form := url.Values{"logout_token": {an.MintLogoutToken(slug, "usr_test", sid)}}
	res, err := srv.Client().PostForm(srv.URL+"/anubis/backchannel-logout", form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", res.StatusCode)
	}
	if len(a.sessions.byID) != 0 {
		t.Fatal("our session survived a sign-out everywhere — the user is still logged in here")
	}

	// And the browser that was signed in is now sent back to sign in.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	after, err := c.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer after.Body.Close()
	if after.StatusCode != http.StatusFound || after.Header.Get("Location") != "/login" {
		t.Fatalf("dashboard returned %d → %q, want a redirect to /login",
			after.StatusCode, after.Header.Get("Location"))
	}
}

func TestReplayedAccessTokenIsNotALogoutNotice(t *testing.T) {
	an, a, srv := start(t)
	c := browser(t, srv)
	if _, err := c.Get(srv.URL + "/login"); err != nil {
		t.Fatal(err)
	}

	// Same issuer, same audience, same key — only the logout event claim tells
	// these apart. Without that check, anyone holding a user's token could sign
	// them out at will.
	access := an.MintToken(anubis.Claims{Subject: "usr_test", Audience: []string{slug}})
	res, err := srv.Client().PostForm(srv.URL+"/anubis/backchannel-logout",
		url.Values{"logout_token": {access}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", res.StatusCode)
	}
	if len(a.sessions.byID) != 1 {
		t.Fatal("a replayed access token signed the user out")
	}
}

func read(t *testing.T, res *http.Response) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	return string(buf[:n])
}
