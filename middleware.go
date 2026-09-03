package anubis

import (
	"net/http"
	"strings"
)

// Middleware rejects requests without a valid bearer token and stores the
// principal in the request context. 401 responses carry WWW-Authenticate so
// standard clients know to re-authenticate.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(r)
		if !ok {
			unauthorized(w, "missing bearer token")
			return
		}
		claims, err := v.Verify(r.Context(), token)
		if err != nil {
			unauthorized(w, "invalid token")
			return
		}
		ctx := WithPrincipal(r.Context(), &Principal{Claims: claims, Token: token})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAMR wraps a handler with a step-up check: the token must carry every
// listed authentication method (e.g. "otp"). On failure it answers 401 with
// insufficient_user_authentication, the machine-readable signal for step-up.
func RequireAMR(methods ...AuthMethod) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				unauthorized(w, "missing bearer token")
				return
			}
			if !p.AuthMethods().HasAll(methods...) {
				w.Header().Set("WWW-Authenticate",
					`Bearer error="insufficient_user_authentication"`)
				http.Error(w, "step-up authentication required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BearerToken extracts the Authorization bearer credential.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	http.Error(w, msg, http.StatusUnauthorized)
}
