package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

const slug = "billing-api"

func start(t *testing.T) (*anubistest.Server, *httptest.Server) {
	t.Helper()
	an := anubistest.NewServer(t)
	handler, err := build(an.URL, slug, "anb_live_ab12cd34_s3cr3t", "impack")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return an, srv
}

func call(t *testing.T, srv *httptest.Server, method, path, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { res.Body.Close() })

	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func token(an *anubistest.Server, subject anubis.SubjectID, amr ...anubis.AuthMethod) string {
	return an.MintToken(anubis.Claims{
		Subject: subject, Audience: []string{slug}, Session: "ses_1", AMR: amr,
	})
}

// ---- the transport layer carries the credential inward --------------------

func TestNoCredentialIsRefusedWithTheAnubisEnvelope(t *testing.T) {
	_, srv := start(t)
	res, body := call(t, srv, http.MethodGet, "/invoices", "")

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Error("a 401 must say how to fix itself")
	}
	// The same envelope Anubis answers with, so a client handling its refusals
	// handles this service's with no second code path.
	if body["error"] != "unauthenticated" {
		t.Fatalf("body = %v, want the anubis error envelope", body)
	}
	// And it does not say WHY. "expired" versus "wrong audience" is a map of
	// the verification rules, drawn for whoever is probing them.
	if msg, _ := body["message"].(string); strings.Contains(msg, "audience") ||
		strings.Contains(msg, "expired") {
		t.Errorf("the refusal leaked which check failed: %q", msg)
	}
}

func TestTokenForAnotherServiceIsRefused(t *testing.T) {
	an, srv := start(t)
	other := an.MintToken(anubis.Claims{Subject: "usr_1", Audience: []string{"hr-api"}})

	res, _ := call(t, srv, http.MethodGet, "/invoices", other)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 — the aud check is what stops the confused deputy", res.StatusCode)
	}
}

func TestAuthenticatedListNeedsNoDecision(t *testing.T) {
	an, srv := start(t)
	res, body := call(t, srv, http.MethodGet, "/invoices?org=org-north", token(an, "usr_1", "pwd"))

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	if len(body["invoices"].([]any)) != 1 {
		t.Fatalf("filtering did not happen: %v", body)
	}
	if an.Calls["Authorize"] != 0 {
		t.Error("listing asked Anubis for a decision it does not need")
	}
}

// ---- the endpoint layer decides -------------------------------------------

func TestApproveSuppliesEveryAxisFromTheLoadedRecord(t *testing.T) {
	an, srv := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	res, body := call(t, srv, http.MethodPost, "/invoices/inv-1/approve", token(an, "usr_1", "pwd", "otp"))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200: %v", res.StatusCode, body)
	}

	// The service recorded who approved, from the principal in the context —
	// identity reached the business layer without it parsing a header.
	invoice := body["invoice"].(map[string]any)
	if invoice["approved"] != true || invoice["approved_by"] != "usr_1" {
		t.Fatalf("invoice = %v", invoice)
	}

	// The claim this example exists to make: the axes came off the record the
	// loader resolved, not off the URL.
	ask := an.LastAsk()
	if ask.Scopes["org"] != "org-north" || ask.Scopes["customer"] != "cust-acme" {
		t.Fatalf("scopes = %v, want both axes from the loaded invoice", ask.Scopes)
	}
	// And amr and auth_time rode along, which is what makes step-up decidable
	// at all. A handler assembling this by hand is where they get dropped.
	if len(ask.AMR) != 2 || ask.AuthTime == 0 {
		t.Fatalf("amr = %v, auth_time = %d — both must come off the token", ask.AMR, ask.AuthTime)
	}
}

func TestDenialNamesTheFailingAxis(t *testing.T) {
	an, srv := start(t)
	an.Deny("usr_1", "billing:invoice:approve", "scope_mismatch", "customer")

	res, body := call(t, srv, http.MethodPost, "/invoices/inv-1/approve", token(an, "usr_1", "pwd"))
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", res.StatusCode)
	}
	if body["error"] != "scope_mismatch" {
		t.Fatalf("error = %v, want the reason Anubis gave", body["error"])
	}
	details, _ := body["details"].(map[string]any)
	if details["failing_axis"] != "customer" {
		t.Fatalf("details = %v — a deny that does not name the axis is a support ticket", details)
	}
}

func TestStepUpIs401NotBecause403MeansStopTrying(t *testing.T) {
	an, srv := start(t)
	an.RequireStepUp("usr_1", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")

	res, body := call(t, srv, http.MethodPost, "/invoices/inv-1/approve", token(an, "usr_1", "pwd"))

	// 401, not 403: the caller can fix this, and 403 tells them not to bother.
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
		t.Error("a step-up refusal must be machine-readable")
	}
	if body["error"] != "step_up_required" {
		t.Fatalf("error = %v", body["error"])
	}
	details, _ := body["details"].(map[string]any)
	if details["required_amr"] != "otp" || details["max_auth_age"] != "2m" {
		t.Fatalf("details = %v — the caller must not have to guess what 'stronger' means", details)
	}
}

// TestUnknownInvoiceNeverReachesAnubis pins the middleware order. The loader
// runs before Authorize, so a request naming nothing spends no decision.
func TestUnknownInvoiceNeverReachesAnubis(t *testing.T) {
	an, srv := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	res, body := call(t, srv, http.MethodPost, "/invoices/nope/approve", token(an, "usr_1", "pwd"))
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", res.StatusCode)
	}
	if body["error"] != "not_found" {
		t.Fatalf("the service's own error was swallowed by the SDK encoder: %v", body)
	}
	if an.Calls["Authorize"] != 0 {
		t.Error("asked Anubis about an invoice that does not exist")
	}
}

// TestAuthorizeWithoutAuthenticateRefuses guards the wiring itself: a chain
// assembled in the wrong order must fail loudly rather than ask Anubis about
// nobody and act on whatever comes back.
func TestAuthorizeWithoutAuthenticateRefuses(t *testing.T) {
	an := anubistest.NewServer(t)
	client, err := anubis.New(an.URL,
		anubis.WithApplication(slug, ""), anubis.WithAPIKey("anb_live_ab12cd34_s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	ep := anubiskit.Authorize(client, "billing:invoice:approve", billing.ScopesOfInvoice)(
		func(context.Context, any) (any, error) { reached = true; return nil, nil })

	_, err = ep(context.Background(), billing.ApproveRequest{InvoiceID: "inv-1"})
	if !errors.Is(err, anubiskit.ErrPrincipalContextMissing) {
		t.Fatalf("err = %v, want ErrPrincipalContextMissing", err)
	}
	if reached {
		t.Fatal("the endpoint ran for an unauthenticated caller")
	}
	if an.Calls["Authorize"] != 0 {
		t.Error("a decision was requested for an unauthenticated caller")
	}
}
