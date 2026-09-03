package anubis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gsoultan/anubis-sdk/paseto"
)

// backchannelEvent is the OIDC event key a logout token must carry.
const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutParams builds the RP-initiated sign-out redirect.
type LogoutParams struct {
	Tenant string
	// PostLogoutRedirectURI is matched exactly against the application's
	// post_logout_redirect_uris — a SEPARATE allowlist from the sign-in
	// callbacks. An unregistered address is refused rather than silently
	// followed: "you have been signed out, sign in again" is a convincing
	// phishing message when the link really did come from the identity
	// provider.
	PostLogoutRedirectURI string
	// Page picks a specific sign-out page by slug.
	Page string
}

// LogoutURL is where to send the browser to sign out.
//
// Anubis answers the GET by rendering its sign-out page and ASKING. That
// confirmation is not politeness: a bare GET that ends sessions is reachable
// from any page on the internet with an <img> tag.
func (c *Client) LogoutURL(p LogoutParams) string {
	q := url.Values{}
	setIf(q, "tenant", firstNonEmpty(p.Tenant, c.opts.tenant))
	setIf(q, "post_logout_redirect_uri", p.PostLogoutRedirectURI)
	setIf(q, "page", p.Page)
	if len(q) == 0 {
		return c.baseURL + pathLogout
	}
	return c.baseURL + pathLogout + "?" + q.Encode()
}

// Logout ends the calling session — this device only.
func (c *Client) Logout(ctx context.Context) error {
	return c.rpc(ctx, procLogout, struct{}{}, nil)
}

// LogoutAll ends every session the subject holds and bumps their token epoch.
//
// This is what triggers back-channel logout: Anubis POSTs a signed logout
// token to every application that registered a backchannel_logout_uri.
func (c *Client) LogoutAll(ctx context.Context) error {
	return c.rpc(ctx, procLogoutAll, struct{}{}, nil)
}

// LogoutSession ends one named session — the "sign out that other device"
// button on a session list.
func (c *Client) LogoutSession(ctx context.Context, sessionID string) error {
	return c.rpc(ctx, procLogoutSession, map[string]any{"session_id": sessionID}, nil)
}

// RevokeSession is LogoutSession from the user's own session list.
func (c *Client) RevokeSession(ctx context.Context, sessionID string) error {
	return c.rpc(ctx, procRevokeSession, map[string]any{"session_id": sessionID}, nil)
}

// LogoutEvent is a back-channel logout: sign this subject or session out.
type LogoutEvent struct {
	// SessionID is the session that ended. Prefer it: signing out by subject
	// ends sessions on devices the user did not ask about.
	SessionID SessionID
	Subject   SubjectID
	Tenant    TenantID
	Issuer    string
	TokenID   string
}

// BackchannelLogout returns the handler for the URI registered as the
// application's backchannel_logout_uri.
//
// This half of sign-out is the one applications skip, because it is the half
// they have to write themselves — and an application with its own session
// cookie keeps a user signed in after they signed out everywhere. So it ships
// as a handler:
//
//	mux.Handle("/anubis/backchannel-logout", client.BackchannelLogout(verifier,
//	    func(ctx context.Context, ev anubis.LogoutEvent) error {
//	        return sessions.KillBySID(ctx, ev.SessionID)
//	    }))
//
// The verifier is the same one guarding your API: the logout token is signed
// with the same key ring and carries your application slug as its audience, so
// nothing new needs configuring.
func (c *Client) BackchannelLogout(v *Verifier, fn func(context.Context, LogoutEvent) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ev, err := VerifyLogoutToken(r.Context(), v, r.PostFormValue("logout_token"))
		if err != nil {
			http.Error(w, "invalid logout token", http.StatusBadRequest)
			return
		}
		if err := fn(r.Context(), *ev); err != nil {
			// Anubis's delivery is best-effort and asynchronous; a 5xx tells it
			// the notification failed rather than pretending it landed.
			http.Error(w, "logout handler failed", http.StatusInternalServerError)
			return
		}
		// No Cache-Control by accident: a cached logout notification is a
		// notification that only works once.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
}

// VerifyLogoutToken checks a back-channel logout token and returns the event.
//
// It verifies the signature, issuer, audience and expiry through the ordinary
// verifier, and then insists on the back-channel event claim. That last check
// is what stops somebody replaying a captured ACCESS token to this endpoint to
// sign a user out at will — an access token passes every other check on this
// list, because it was minted by the same issuer for the same audience.
func VerifyLogoutToken(ctx context.Context, v *Verifier, token string) (*LogoutEvent, error) {
	if v == nil {
		return nil, errors.New("anubis: verifying a logout token needs a verifier")
	}
	if token == "" {
		return nil, errors.New("anubis: no logout token")
	}
	claims, err := v.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	// Safe to read the raw message now: Verify has already checked the
	// signature that covers it.
	msg, _, _, err := paseto.Parse(token)
	if err != nil {
		return nil, err
	}
	var body struct {
		Events map[string]json.RawMessage `json:"events"`
		SID    string                     `json:"sid"`
	}
	if err := json.Unmarshal(msg, &body); err != nil {
		return nil, fmt.Errorf("anubis: logout token body: %w", err)
	}
	if _, ok := body.Events[backchannelEvent]; !ok {
		return nil, errors.New("anubis: not a back-channel logout token (no logout event claim)")
	}
	if body.SID == "" && claims.Subject == "" {
		return nil, errors.New("anubis: logout token names neither a session nor a subject")
	}
	sid := SessionID(body.SID)
	if sid == "" {
		sid = claims.Session
	}
	return &LogoutEvent{
		SessionID: sid,
		Subject:   claims.Subject,
		Tenant:    claims.Tenant,
		Issuer:    claims.Issuer,
		TokenID:   claims.TokenID,
	}, nil
}
