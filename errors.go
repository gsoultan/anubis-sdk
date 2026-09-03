package anubis

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/anubis-sdk/keys"
)

// Verification failures. These come off the offline path, so they never carry
// a request id — nothing was asked of Anubis.
var (
	ErrExpired      = errors.New("anubis: token expired")
	ErrNotYetValid  = errors.New("anubis: token not yet valid (check NTP)")
	ErrIssuer       = errors.New("anubis: issuer mismatch")
	ErrAudience     = errors.New("anubis: audience mismatch")
	ErrNoAudience   = errors.New("anubis: verifier requires an audience — refusing to skip the aud check")
	ErrTokenVersion = errors.New("anubis: unsupported token version")

	// ErrUnknownKid is re-exported so consumers need not import the keys
	// package to recognise the rejection.
	ErrUnknownKid = keys.ErrUnknownKid

	// ErrNoPrincipal means the context carried no verified principal. The
	// middleware puts one there; a call that needs the subject, amr and
	// auth_time cannot invent them.
	ErrNoPrincipal = errors.New("anubis: no verified principal in context (is the middleware mounted?)")

	// ErrNoCredential means the client has nothing to authenticate with and
	// the context carried no principal whose token it could present.
	ErrNoCredential = errors.New("anubis: no credential — use WithAPIKey, or call from a request the middleware has verified")
)

// APIError is a refusal the client has no more specific type for. Code is the
// stable machine-readable string from the error envelope — the same
// vocabulary on both transports — and RequestID correlates to audit_log and
// traces, which is the first thing anyone asks for.
type APIError struct {
	Code      string
	Message   string
	RequestID string
	Status    int
	Details   map[string]string
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("anubis: ")
	if e.Code != "" {
		b.WriteString(e.Code)
	} else {
		fmt.Fprintf(&b, "http %d", e.Status)
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " (request %s)", e.RequestID)
	}
	return b.String()
}

// DeniedError is a decision, not a transport failure: Anubis answered, and the
// answer was no. FailingAxis is always named on a scope refusal — that is the
// whole point of the multi-axis model reporting which axis failed.
//
// Returned by Require. Authorize returns the same information as data, for
// callers to whom a denial is an answer rather than an error.
type DeniedError struct {
	Reason      string
	FailingAxis Axis
	Message     string
	Permission  Permission
	Subject     SubjectID
}

func (e *DeniedError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Reason
	}
	if e.FailingAxis != "" {
		return fmt.Sprintf("anubis: denied %q: %s (failing axis %q)", e.Permission, msg, e.FailingAxis)
	}
	return fmt.Sprintf("anubis: denied %q: %s", e.Permission, msg)
}

// StepUpRequiredError is a denial the caller can do something about: the
// subject holds the permission but has not authenticated strongly enough, or
// recently enough.
//
// It is machine-readable so the application does not guess. Feed it to
// Client.StepUpURL and send the user back through sign-in; do not invent a
// second factor of your own.
type StepUpRequiredError struct {
	RequiredAMR AuthMethods
	CurrentAMR  AuthMethods
	MaxAuthAge  string
	AuthAge     string
	Permission  Permission
	Subject     SubjectID
}

// MaxAuthAgeDuration is how fresh the authentication has to be, parsed. Anubis
// sends it as a string; a caller comparing durations should not have to.
func (e *StepUpRequiredError) MaxAuthAgeDuration() (time.Duration, bool) {
	return parseAge(e.MaxAuthAge)
}

// AuthAgeDuration is how old the caller's authentication actually is.
func (e *StepUpRequiredError) AuthAgeDuration() (time.Duration, bool) {
	return parseAge(e.AuthAge)
}

func (e *StepUpRequiredError) Error() string {
	return fmt.Sprintf("anubis: step-up required for %q: have amr %v, need %v (max auth age %s)",
		e.Permission, e.CurrentAMR, e.RequiredAMR, e.MaxAuthAge)
}

// RefreshReuseError reports that a consumed refresh token was presented again.
//
// Do not retry. Two parties held this token and one of them is an attacker;
// the family and the session are already revoked. Drop the session, send the
// user to sign in, and alert — this is a security event, not a transient
// failure. It is the one error in this package that carries no retry advice,
// because there is none.
type RefreshReuseError struct{ err error }

func (e *RefreshReuseError) Error() string {
	return fmt.Sprintf("anubis: refresh token reuse detected — family and session revoked, this is theft: %v", e.err)
}
func (e *RefreshReuseError) Unwrap() error { return e.err }

// AuthError reports that the credential was missing, rejected, or lacks the
// scope the call needs.
type AuthError struct{ err error }

func (e *AuthError) Error() string {
	return fmt.Sprintf("anubis: the credential was not accepted: %v", e.err)
}
func (e *AuthError) Unwrap() error { return e.err }

// RateLimitedError reports that the caller is asking faster than its limits
// allow. Nothing was done, so repeating the call after RetryAfter is safe.
//
// Limits apply per IP, per account and per tenant; the per-account one is what
// stops credential stuffing, so seeing this on a login path may mean somebody
// is attacking that account rather than that your traffic grew.
type RateLimitedError struct {
	RetryAfter time.Duration
	err        error
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("anubis: rate limited, retry after %s: %v", e.RetryAfter, e.err)
}
func (e *RateLimitedError) Unwrap() error { return e.err }

// StateMismatchError means the callback's state did not match the one this
// client issued, or the login was never begun by this client.
//
// Treat it as an attack, not a bug: the state parameter exists to bind the
// callback to the browser that started the flow, and a mismatch is what CSRF
// against the sign-in flow looks like. The SDK will not exchange the code.
type StateMismatchError struct{ Reason string }

func (e *StateMismatchError) Error() string {
	return "anubis: login state did not match (" + e.Reason + ") — refusing to exchange the code"
}

// EnrolmentRequiredError reports that the realm requires a factor this member
// has not enrolled, and the deadline has passed. No session was issued — but
// the refusal carries the means to comply, which is what makes it
// enrol-or-deny rather than deny.
//
// Pass GrantToken to BeginTotpEnrollment and ConfirmTotpEnrollment in place of
// a session: the session is exactly what the policy is withholding.
type EnrolmentRequiredError struct {
	Factors    AuthMethods
	Deadline   time.Time
	GrantToken string
	ExpiresIn  int
}

func (e *EnrolmentRequiredError) Error() string {
	return fmt.Sprintf("anubis: enrolment required for %v (deadline %s) — use the grant token to enrol",
		e.Factors, e.Deadline.Format(time.RFC3339))
}

// UnavailableError means Anubis could not be reached, or answered that it is
// not ready. Retry with backoff.
//
// A readiness refusal is deliberate: an instance whose snapshot has outlived
// its maximum age fails /readyz first, so it leaves the load balancer before
// it starts denying decisions.
type UnavailableError struct{ err error }

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("anubis: unavailable: %v", e.err)
}
func (e *UnavailableError) Unwrap() error { return e.err }

// Stable codes this client acts on. The body is authoritative over the HTTP
// status: a proxy is free to rewrite a status, and some do.
const (
	codeRefreshReuse   = "refresh_token_reuse_detected"
	codeStepUpRequired = "step_up_required"
	codeRateLimited    = "rate_limited"
	codeUnauthct       = "unauthenticated"
	codeInvalidToken   = "invalid_token"
	codeInvalidCreds   = "invalid_credentials"
	codePermDenied     = "permission_denied"
	codeSessionRevoked = "session_revoked"
	codeInvalidRefresh = "invalid_refresh_token"
	codeUnavailable    = "unavailable"
)

// classify turns a refusal into something a caller can act on.
//
// Reuse detection is first and deliberately not folded in with the other
// authentication failures: every other one of them means "try again with a
// better credential", and this one means "stop, you have been robbed".
// Collapsing it into AuthError would put a theft signal on the same code path
// as a typo'd password.
func classify(e *APIError, header http.Header) error {
	code := e.Code
	if code == "" {
		switch e.Status {
		case http.StatusTooManyRequests:
			code = codeRateLimited
		case http.StatusUnauthorized:
			code = codeUnauthct
		case http.StatusForbidden:
			code = codePermDenied
		case http.StatusServiceUnavailable:
			code = codeUnavailable
		}
	}

	switch code {
	case codeRefreshReuse:
		return &RefreshReuseError{err: e}
	case codeRateLimited:
		return &RateLimitedError{RetryAfter: retryAfter(header), err: e}
	case codeUnauthct, codeInvalidToken, codeInvalidCreds, codePermDenied,
		codeSessionRevoked, codeInvalidRefresh:
		return &AuthError{err: e}
	case codeUnavailable:
		return &UnavailableError{err: e}
	default:
		return e
	}
}

// retryAfter reads the delay the server asked for. A header this client cannot
// parse is not a reason to call the refusal something else — it is still a
// rate limit, just one with no usable delay attached.
func retryAfter(header http.Header) time.Duration {
	v := header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
