// Package anubis integrates an application with an Anubis installation.
//
// It is two objects, because an integration is two jobs with nothing in
// common.
//
// # Verify — every request, offline
//
// A Verifier checks a v4.public access token against published Ed25519 public
// keys: signature, expiry, issuer, audience. Pure CPU, no network hop, no
// database, microseconds. This half depends on nothing outside the standard
// library, because what every service embeds must not drag a dependency tree
// behind it.
//
//	v, err := anubis.NewVerifier(anubis.Config{
//	    Issuer:   "https://anubis.internal",
//	    Audience: "billing-api",
//	    KeysURL:  "https://anubis.internal/.well-known/anubis-keys.json",
//	})
//	mux.Handle("/api/", v.Middleware(apiHandler))
//
// Audience has no default and no override. A verifier without one accepts
// tokens minted for the HR application in the payments application — the
// classic confused deputy — so the constructor refuses to build. That is the
// pattern the rest of this package follows: a check worth having is made
// structurally unskippable rather than documented.
//
// Offline verification cannot see revocation. A token stays valid until it
// expires even if its session died, which is why access tokens are short-lived.
// Where that window is unacceptable, Client.Introspect asks Anubis — at the
// cost of putting it back in your hot path.
//
// # Ask — before a privileged action
//
// A Client signs users in, keeps sessions alive, and asks whether somebody may
// do something. Authentication says who they are; whether they may act depends
// on grants, scopes and identity state that only Anubis holds and that change
// without your application redeploying.
//
//	if err := client.Require(ctx, "billing:invoice:approve", anubis.Scopes{
//	    "org":      invoice.OrgID,
//	    "customer": invoice.CustomerID,
//	}); err != nil {
//	    var stepUp *anubis.StepUpRequiredError
//	    if errors.As(err, &stepUp) {
//	        redirect, _ := client.BeginStepUp(w, err, anubis.LoginParams{RedirectURI: cb})
//	        http.Redirect(w, r, redirect.URL, http.StatusFound)
//	        return
//	    }
//	    return err
//	}
//
// The subject, the authentication methods and the authentication time are read
// from the principal the middleware verified, not passed by the caller.
// Assembling that request by hand is how amr and auth_time get left out, and
// leaving them out turns every step-up rule into a silent permanent denial
// that looks like a permissions bug.
//
// Supply every axis the action touches. On a strict axis an omitted axis is
// denied, not ignored: fail-closed is the design, and "I forgot an axis" and
// "they may not do this" are indistinguishable from outside.
//
// # Three things worth reading before you ship
//
// Refresh tokens are single-use and rotate. Two concurrent requests that both
// refresh will produce a reuse refusal, which Anubis correctly treats as theft
// and answers by revoking the family and the session. Use TokenSource, which
// serialises refreshes behind a single flight; do not call Refresh from
// concurrent handlers.
//
// A RefreshReuseError is not retryable and not a transient failure. It means
// two parties held one token. Drop the session and alert a human.
//
// Back-channel logout is the half of sign-out applications skip, because it is
// the half they have to write themselves — and an application with its own
// session cookie keeps a user signed in after they signed out everywhere.
// Client.BackchannelLogout is a ready handler; mount it.
//
// # Testing
//
// Package anubistest runs an in-process Anubis that signs real tokens and
// answers the real wire shapes, so an integration can be tested without a
// server or a network.
package anubis
