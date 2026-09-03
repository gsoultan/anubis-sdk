// Command billing-web is a worked example of integrating an application with
// Anubis: browser sign-in, offline token verification, a permission check with
// step-up, refresh that survives concurrency, and being signed out from
// somewhere else.
//
// Run it against a real installation:
//
//	ANUBIS_URL=https://anubis.internal \
//	ANUBIS_APP=billing-web \
//	ANUBIS_SECRET=… \
//	ANUBIS_API_KEY=anb_live_… \
//	APP_URL=https://billing.example.com \
//	go run ./examples/billing-web
//
// main_test.go drives every route below against an in-process Anubis, so the
// code on this page is executed rather than merely plausible.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
)

func main() {
	app, err := newApp(config{
		AnubisURL: env("ANUBIS_URL", "https://anubis.internal"),
		AppURL:    env("APP_URL", "https://billing.example.com"),
		Slug:      env("ANUBIS_APP", "billing-web"),
		Secret:    os.Getenv("ANUBIS_SECRET"),
		APIKey:    os.Getenv("ANUBIS_API_KEY"),
		Tenant:    env("ANUBIS_TENANT", "impack"),
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", app.routes()))
}

type config struct {
	AnubisURL string
	AppURL    string
	Slug      string // the registered application slug — also client_id and aud
	Secret    string // shown once at registration; empty for an spa
	APIKey    string // anb_live_… — the tenant's credential, for asking about users
	Tenant    string
}

type app struct {
	cfg      config
	verifier *anubis.Verifier
	client   *anubis.Client
	sessions *sessionStore
}

func newApp(cfg config) (*app, error) {
	// The offline half. Audience is this application's slug: without it we
	// would accept a token minted for a different application, which is the
	// confused deputy. The constructor refuses to build without one.
	verifier, err := anubis.NewVerifier(anubis.Config{
		Issuer:   cfg.AnubisURL,
		Audience: cfg.Slug,
		KeysURL:  cfg.AnubisURL + "/.well-known/anubis-keys.json",
	})
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}

	// The online half. WithApplication names us in the sign-in redirect;
	// WithAPIKey is the credential we ask decisions with. A trusted back end
	// asking about its own users wants the tenant key rather than forwarding
	// whatever token happens to be on the request.
	opts := []anubis.Option{
		anubis.WithApplication(cfg.Slug, cfg.Secret),
		anubis.WithTenant(cfg.Tenant),
	}
	if cfg.APIKey != "" {
		// An api key and a client secret are different callers, so a client
		// may hold one or the other. This one asks decisions; sign-in below
		// needs no credential at all.
		opts = []anubis.Option{
			anubis.WithApplication(cfg.Slug, ""),
			anubis.WithTenant(cfg.Tenant),
			anubis.WithAPIKey(cfg.APIKey),
		}
	}
	client, err := anubis.New(cfg.AnubisURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}

	return &app{cfg: cfg, verifier: verifier, client: client, sessions: newSessionStore()}, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /", a.home)

	// Browser sign-in and sign-out.
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /callback", a.callback)
	mux.HandleFunc("GET /logout", a.logout)
	mux.HandleFunc("GET /dashboard", a.dashboard)

	// The API an SPA or a mobile client calls, guarded by offline verification.
	// Everything under here has a verified principal in its context, which is
	// what lets Require read the subject, amr and auth_time rather than making
	// the handler assemble them.
	mux.Handle("GET /api/invoices", a.verifier.Middleware(http.HandlerFunc(a.listInvoices)))
	mux.Handle("POST /api/invoices/{id}/approve", a.verifier.Middleware(http.HandlerFunc(a.approveInvoice)))

	// The URI registered as backchannel_logout_uri. Without this, our own
	// session cookie keeps a user signed in after they signed out everywhere.
	mux.Handle("POST /anubis/backchannel-logout", a.client.BackchannelLogout(a.verifier, a.onRemoteLogout))

	return mux
}

// ---- sign-in --------------------------------------------------------------

// login sends the browser to Anubis. The SDK generates the PKCE verifier and
// the state and stores both in a cookie on our origin, so neither is ours to
// manage and neither reaches the URL bar.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	redirect, err := a.client.BeginLogin(w, anubis.LoginParams{
		RedirectURI: a.cfg.AppURL + "/callback",
		Scope:       []string{"openid", "profile"},
	})
	if err != nil {
		http.Error(w, "cannot start sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirect.URL, http.StatusFound)
}

// callback finishes the sign-in.
//
// CompleteLogin compares the state before it exchanges anything, so a callback
// that did not originate here never becomes a session. There is no argument
// that turns that off.
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	tokens, err := a.client.CompleteLogin(r.Context(), w, r)
	if err != nil {
		var mismatch *anubis.StateMismatchError
		if errors.As(err, &mismatch) {
			// Not a bug to retry — this is what CSRF against sign-in looks like.
			log.Printf("SECURITY: rejected callback: %v", err)
			http.Error(w, "sign-in could not be verified", http.StatusBadRequest)
			return
		}
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}

	// Hold the pair in a TokenSource, which serialises refreshes. Two requests
	// that both refresh would present the same rotating token twice, and Anubis
	// reads that as theft — correctly, because it cannot tell us from a thief.
	source := a.client.TokenSource(*tokens)

	id := a.sessions.create(source, tokens.SessionID)

	// Persist every rotation. OnRotate runs before Token returns, so a crash
	// between the two cannot lose the new pair and strand us holding a dead one.
	source.OnRotate(func(t anubis.Tokens) error {
		a.sessions.save(id, t)
		return nil
	})

	http.SetCookie(w, &http.Cookie{
		Name: "billing_session", Value: id, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// logout sends the browser to Anubis, which asks for confirmation before
// ending anything — a bare GET that ends sessions is reachable from any page
// on the internet with an <img> tag.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("billing_session"); err == nil {
		a.sessions.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "billing_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, a.client.LogoutURL(anubis.LogoutParams{
		// Matched exactly against post_logout_redirect_uris — a SEPARATE
		// allowlist from the sign-in callbacks.
		PostLogoutRedirectURI: a.cfg.AppURL + "/",
	}), http.StatusFound)
}

// onRemoteLogout runs when the user signs out somewhere else. Kill the session
// by sid: signing out by subject would end sessions on devices they did not
// ask about.
func (a *app) onRemoteLogout(_ context.Context, ev anubis.LogoutEvent) error {
	a.sessions.dropBySID(ev.SessionID)
	log.Printf("signed out %s (session %s) on back-channel notice", ev.Subject, ev.SessionID)
	return nil
}

// ---- pages ----------------------------------------------------------------

func (a *app) home(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, `billing — <a href="/login">sign in</a>`)
}

// dashboard is guarded by our own session, not by a bearer token: the browser
// holds a cookie, not an Authorization header.
func (a *app) dashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := a.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// Token() refreshes if the access token is close to expiry, once, however
	// many requests notice at the same moment.
	tokens, err := session.source.Token(r.Context())
	if err != nil {
		var reuse *anubis.RefreshReuseError
		if errors.As(err, &reuse) {
			// Two parties held this refresh token. Anubis has already revoked
			// the family and the session; there is nothing to retry.
			log.Printf("SECURITY: refresh token theft on session %s: %v", session.sid, err)
			a.sessions.drop(session.id)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Error(w, "session could not be refreshed", http.StatusBadGateway)
		return
	}
	claims, err := a.verifier.Verify(r.Context(), tokens.AccessToken)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	fmt.Fprintf(w, "signed in as %s, roles %v\n", claims.Subject, claims.Roles)
}

// ---- the API --------------------------------------------------------------

func (a *app) listInvoices(w http.ResponseWriter, r *http.Request) {
	p, _ := anubis.FromContext(r.Context())
	fmt.Fprintf(w, "invoices for %s\n", p.Claims.Subject)
}

// approveInvoice is the interesting one: a privileged action, so authentication
// is not enough and we ask.
func (a *app) approveInvoice(w http.ResponseWriter, r *http.Request) {
	invoice := lookupInvoice(r.PathValue("id"))

	// Every axis the action touches. On a strict axis an omitted axis is
	// DENIED, not ignored — so a forgotten axis shows up as a permissions bug
	// that is really a bug here.
	err := a.client.Require(r.Context(), "billing:invoice:approve", anubis.Scopes{
		"org":      invoice.OrgID,
		"customer": invoice.CustomerID,
	})

	switch {
	case err == nil:
		fmt.Fprintf(w, "approved invoice %s\n", invoice.ID)

	case isStepUp(err):
		// Machine-readable, so we do not guess what "stronger" means. Send the
		// user back through sign-in with the requirement attached, then they
		// retry this action.
		redirect, berr := a.client.BeginStepUp(w, err, anubis.LoginParams{
			RedirectURI: a.cfg.AppURL + "/callback",
		})
		if berr != nil {
			http.Error(w, "step-up unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication"`)
		w.Header().Set("Location", redirect.URL)
		http.Error(w, "approving an invoice needs a second factor", http.StatusUnauthorized)

	case isDenied(err):
		// The refusal always names the axis that failed, so the message can be
		// specific instead of "forbidden".
		var denied *anubis.DeniedError
		errors.As(err, &denied)
		log.Printf("denied %s: %s (axis %s)", denied.Permission, denied.Reason, denied.FailingAxis)
		http.Error(w, denied.Message, http.StatusForbidden)

	default:
		// Anubis is unreachable, rate limiting us, or refusing our credential.
		// Fail closed: an approval is not something to wave through because the
		// authority is down.
		log.Printf("authorization unavailable: %v", err)
		http.Error(w, "cannot check permissions right now", http.StatusServiceUnavailable)
	}
}

func isStepUp(err error) bool {
	var e *anubis.StepUpRequiredError
	return errors.As(err, &e)
}

func isDenied(err error) bool {
	var e *anubis.DeniedError
	return errors.As(err, &e)
}

// ---- the boring parts -----------------------------------------------------

type invoice struct{ ID, OrgID, CustomerID string }

func lookupInvoice(id string) invoice {
	return invoice{ID: id, OrgID: "01a027ff-org", CustomerID: "01a027fb-cust"}
}

type session struct {
	id     string
	sid    anubis.SessionID // what back-channel logout names
	source *anubis.TokenSource
}

type sessionStore struct {
	mu     sync.RWMutex
	byID   map[string]*session
	bySID  map[anubis.SessionID]string
	serial int
}

func newSessionStore() *sessionStore {
	return &sessionStore{byID: map[string]*session{}, bySID: map[anubis.SessionID]string{}}
}

func (s *sessionStore) create(source *anubis.TokenSource, sid anubis.SessionID) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	id := fmt.Sprintf("sess-%d-%d", s.serial, time.Now().UnixNano())
	s.byID[id] = &session{id: id, sid: sid, source: source}
	s.bySID[sid] = id
	return id
}

func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.byID[id]
	return sess, ok
}

// save is where a real application writes the rotated pair to its session
// storage. In memory here; the point is that it happens on every rotation.
func (s *sessionStore) save(id string, t anubis.Tokens) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byID[id]; ok {
		delete(s.bySID, sess.sid)
		sess.sid = t.SessionID
		s.bySID[t.SessionID] = id
	}
}

func (s *sessionStore) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byID[id]; ok {
		delete(s.bySID, sess.sid)
		delete(s.byID, id)
	}
}

func (s *sessionStore) dropBySID(sid anubis.SessionID) {
	s.mu.Lock()
	id, ok := s.bySID[sid]
	s.mu.Unlock()
	if ok {
		s.drop(id)
	}
}

func (a *app) session(r *http.Request) (*session, bool) {
	c, err := r.Cookie("billing_session")
	if err != nil {
		return nil, false
	}
	return a.sessions.get(c.Value)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
