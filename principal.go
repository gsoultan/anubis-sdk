package anubis

import (
	"context"
	"time"
)

type ctxKey struct{}

// Principal is what a verified request carries: the claim set, and the token
// it came from.
//
// The accessors below are the ones a handler reaches for. Claims is still
// there for anything they do not cover, but a handler that reads Claims.AuthTime
// and converts it by hand is doing work this type already did.
type Principal struct {
	Claims *Claims
	Token  string
}

// Identity is who this caller is and what they hold.
func (p *Principal) Identity() Identity {
	if p == nil || p.Claims == nil {
		return Identity{}
	}
	return p.Claims.Identity()
}

// Subject is the caller's identity id.
func (p *Principal) Subject() SubjectID { return p.Identity().Subject }

// Session is the signed-in device this token belongs to. Empty for a
// client-credentials caller, which has no session by design.
func (p *Principal) Session() SessionID { return p.Identity().Session }

// Tenant is the tenant the token was minted within.
func (p *Principal) Tenant() TenantID { return p.Identity().Tenant }

// Roles are the roles this token was minted with, prefixed by the application
// that defined them: "billing.clerk", not "clerk".
func (p *Principal) Roles() Roles { return p.Identity().Roles }

// Scopes is the ACTIVE scope — one node per axis, what this session is acting
// as right now. It is not everything the person is entitled to; that lives in
// grants. Use SwitchScope to move, and Require to find out whether a move is
// allowed.
func (p *Principal) Scopes() Scopes { return p.Identity().Scopes }

// AuthMethods are the methods the caller authenticated with.
func (p *Principal) AuthMethods() AuthMethods { return p.Identity().Methods }

// AuthenticatedAt is when they last proved who they were — what a step-up rule
// with a maximum age is measured against.
func (p *Principal) AuthenticatedAt() time.Time { return p.Identity().AuthenticatedAt() }

// ExpiresAt is when this token stops being accepted.
func (p *Principal) ExpiresAt() time.Time { return p.Identity().ExpiresAt() }

// HasRole is the cheap local check; Client.Require is the real one.
func (p *Principal) HasRole(r Role) bool { return p.Identity().HasRole(r) }

// FromContext returns the verified principal, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// IdentityFromContext returns the verified caller's identity, and whether
// there was one. The common case, spelled once.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	p, ok := FromContext(ctx)
	if !ok {
		return Identity{}, false
	}
	return p.Identity(), true
}

// WithPrincipal is exported for tests and custom transports.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}
