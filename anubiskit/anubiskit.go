// Package anubiskit integrates Anubis with go-kit.
//
// It follows the shape of go-kit's own auth/jwt package, because a go-kit
// service already knows that shape: a RequestFunc lifts the credential off the
// transport into the context, and endpoint middleware does the rest. Nothing
// below the transport layer ever sees an *http.Request.
//
//	// transport
//	httptransport.NewServer(endpoints.Approve, decodeApprove, encodeResponse,
//	    httptransport.ServerBefore(anubiskit.HTTPToContext()),
//	    httptransport.ServerErrorEncoder(anubiskit.ErrorEncoder),
//	)
//
//	// endpoint
//	anubiskit.Authenticate(verifier)(
//	    anubiskit.Authorize(client, "billing:invoice:approve", scopesOf)(
//	        makeApproveEndpoint(svc)))
//
// This is a separate module. go-kit is a dependency, and the SDK it wraps
// promises to have none — a service that only verifies tokens should not pull
// in a framework it does not use.
package anubiskit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"

	anubis "github.com/gsoultan/anubis-sdk"
)

type contextKey string

// BearerTokenContextKey is where HTTPToContext leaves the raw credential, and
// where Authenticate looks for it. Exported so a transport this package does
// not cover — gRPC, NATS, AMQP — can populate it the same way.
const BearerTokenContextKey contextKey = "AnubisBearerToken"

var (
	// ErrTokenContextMissing means nothing put a credential in the context.
	// Almost always a missing ServerBefore rather than a missing header.
	ErrTokenContextMissing = errors.New(
		"anubiskit: no bearer token in the context — is HTTPToContext wired as a ServerBefore?")

	// ErrPrincipalContextMissing means Authorize ran without Authenticate in
	// front of it. It is deliberately not a fallback to "ask anyway": a
	// decision about an unauthenticated caller is a decision about nobody.
	ErrPrincipalContextMissing = errors.New(
		"anubiskit: no verified principal — Authorize must be wrapped by Authenticate")
)

// HTTPToContext moves the Authorization bearer credential into the context.
//
// Wire it with httptransport.ServerBefore. It does not verify anything: the
// transport layer's job is to carry the credential inward, and verification is
// a decision the endpoint layer makes, where it can be applied uniformly across
// every transport a service speaks.
func HTTPToContext() httptransport.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			return ctx
		}
		return context.WithValue(ctx, BearerTokenContextKey, token)
	}
}

// ContextToHTTP puts the credential back on an outgoing request, for a service
// calling another service on the caller's behalf.
//
// Forwarding a user's token preserves their authority — and their audience.
// The receiving service pins its own aud, so a token forwarded to a service it
// was not minted for is refused there, which is the behaviour you want.
func ContextToHTTP() httptransport.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		if token, ok := ctx.Value(BearerTokenContextKey).(string); ok && token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return ctx
	}
}

// Authenticate verifies the token from the context and stores the principal.
//
// Offline: signature, expiry, issuer and audience, no network hop. Put it
// outermost of the auth middlewares — everything after it can rely on there
// being a verified caller.
func Authenticate(v *anubis.Verifier) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request any) (any, error) {
			token, ok := ctx.Value(BearerTokenContextKey).(string)
			if !ok || token == "" {
				return nil, ErrTokenContextMissing
			}
			claims, err := v.Verify(ctx, token)
			if err != nil {
				return nil, err
			}
			ctx = anubis.WithPrincipal(ctx, &anubis.Principal{Claims: claims, Token: token})
			return next(ctx, request)
		}
	}
}

// RequireAMR refuses a caller whose token does not carry every listed
// authentication method — a step-up gate applied without asking Anubis.
//
// Cheaper than Authorize and strictly weaker: it can tell you the user typed a
// one-time code, not whether they may do the thing. Use it to close an obvious
// door early, not instead of a decision.
func RequireAMR(methods ...anubis.AuthMethod) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request any) (any, error) {
			p, ok := anubis.FromContext(ctx)
			if !ok {
				return nil, ErrPrincipalContextMissing
			}
			if !p.AuthMethods().HasAll(methods...) {
				return nil, &anubis.StepUpRequiredError{
					RequiredAMR: methods,
					CurrentAMR:  p.AuthMethods(),
				}
			}
			return next(ctx, request)
		}
	}
}

// ScopeFunc derives the scope set from the DECODED request.
//
// This is the difference between a go-kit integration and an http one. At the
// endpoint layer there is no *http.Request to pick a path parameter out of —
// and that is the point: the axes an action is scoped on are a property of the
// action, not of the URL it happened to arrive on. A service that also speaks
// gRPC gets the same scoping for free.
type ScopeFunc func(ctx context.Context, request any) anubis.Scopes

// Authorize asks Anubis whether the verified caller may run this endpoint.
//
// The subject, the authentication methods and the authentication time come off
// the principal Authenticate produced. Nothing here takes them from the caller:
// hand-assembling that request is how amr and auth_time get dropped, and
// dropping them turns every step-up rule into a permanent silent denial.
func Authorize(c *anubis.Client, permission anubis.Permission, scopes ScopeFunc) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request any) (any, error) {
			if _, ok := anubis.FromContext(ctx); !ok {
				return nil, ErrPrincipalContextMissing
			}
			var s anubis.Scopes
			if scopes != nil {
				s = scopes(ctx, request)
			}
			if err := c.Require(ctx, permission, s); err != nil {
				// Returned, not translated. The endpoint layer does not know
				// what a status code is; ErrorEncoder does that at the edge.
				return nil, err
			}
			return next(ctx, request)
		}
	}
}

// StatusCode maps an SDK error to the HTTP status it should leave as.
//
// Separate from ErrorEncoder so a service with its own encoder — or a
// non-HTTP transport that still needs a class of failure — can reuse the
// mapping without inheriting the body format.
func StatusCode(err error) int {
	var stepUp *anubis.StepUpRequiredError
	var denied *anubis.DeniedError
	var auth *anubis.AuthError
	var limited *anubis.RateLimitedError
	var down *anubis.UnavailableError

	switch {
	case errors.As(err, &stepUp):
		// 401, not 403: the caller can do something about it, and 403 tells
		// them not to bother trying.
		return http.StatusUnauthorized
	case errors.As(err, &denied):
		return http.StatusForbidden
	case errors.As(err, &auth):
		return http.StatusUnauthorized
	case errors.As(err, &limited):
		return http.StatusTooManyRequests
	case errors.As(err, &down):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrTokenContextMissing),
		errors.Is(err, anubis.ErrExpired),
		errors.Is(err, anubis.ErrAudience),
		errors.Is(err, anubis.ErrIssuer),
		errors.Is(err, anubis.ErrNotYetValid),
		errors.Is(err, anubis.ErrUnknownKid):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// errorEnvelope is the shape Anubis itself answers with. Speaking the same
// envelope means a client already handling Anubis's refusals handles this
// service's refusals with no second code path.
type errorEnvelope struct {
	Error     string            `json:"error"`
	Message   string            `json:"message"`
	RequestID string            `json:"request_id,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}

// ErrorEncoder renders an authentication or authorization failure.
//
// Wire it with httptransport.ServerErrorEncoder. Refusals that a caller can act
// on carry the machine-readable detail that says how: a step-up names the
// methods it wants, a denial names the axis that failed.
func ErrorEncoder(_ context.Context, err error, w http.ResponseWriter) {
	status := StatusCode(err)
	body := errorEnvelope{Error: "internal", Message: "internal error"}

	var stepUp *anubis.StepUpRequiredError
	var denied *anubis.DeniedError
	var limited *anubis.RateLimitedError
	var api *anubis.APIError

	switch {
	case errors.As(err, &stepUp):
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication"`)
		body = errorEnvelope{
			Error:   "step_up_required",
			Message: "stronger authentication is required for this action",
			Details: map[string]string{
				"required_amr": strings.Join(stepUp.RequiredAMR.Strings(), " "),
				"max_auth_age": stepUp.MaxAuthAge,
			},
		}
	case errors.As(err, &denied):
		body = errorEnvelope{Error: denied.Reason, Message: denied.Message}
		if denied.FailingAxis != "" {
			body.Details = map[string]string{"failing_axis": string(denied.FailingAxis)}
		}
	case errors.As(err, &limited):
		w.Header().Set("Retry-After", secondsOf(limited))
		body = errorEnvelope{Error: "rate_limited", Message: "slow down"}
	case status == http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		// Deliberately uninformative. "expired" versus "wrong audience" versus
		// "unknown key" is a map of your verification rules, drawn for whoever
		// is probing them.
		body = errorEnvelope{Error: "unauthenticated", Message: "authentication required"}
	case status == http.StatusServiceUnavailable:
		body = errorEnvelope{Error: "unavailable", Message: "authorization is unavailable"}
	}

	if errors.As(err, &api) && api.RequestID != "" {
		body.RequestID = api.RequestID
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func secondsOf(e *anubis.RateLimitedError) string {
	secs := int(e.RetryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	return itoa(secs)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func bearer(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}
