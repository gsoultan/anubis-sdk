package anubis

import (
	"sort"
	"strings"
	"time"
)

// This file is the SDK's vocabulary. Every one of these was a string, a
// []string or a map[string]string once, and each of those was a place where a
// caller could pass the right shape with the wrong meaning and find out at
// runtime — or worse, not find out, because a mistyped axis is answered with a
// denial that looks exactly like a real one.

// SubjectID identifies a person or an application acting as itself: "usr_…"
// for an identity, "app_…" for a client-credentials caller.
type SubjectID string

func (s SubjectID) String() string { return string(s) }

// IsApplication reports whether this subject is an application rather than a
// person — which is worth knowing before writing "approved by" into a record.
func (s SubjectID) IsApplication() bool { return strings.HasPrefix(string(s), "app_") }

// SessionID identifies one signed-in device. It is what back-channel logout
// names, and what to sign out by: signing out by subject ends sessions on
// devices the user did not ask about.
type SessionID string

func (s SessionID) String() string { return string(s) }

// TenantID identifies the tenant a token was minted within.
type TenantID string

func (t TenantID) String() string { return string(t) }

// ---- permissions ----------------------------------------------------------

// Permission is a full permission key: "app:resource:action".
//
// The full key is what tokens carry and what Authorize takes. Inside an
// application manifest the same permission is written WITHOUT the application
// prefix — "invoice:approve" — and that asymmetry has cost people real time.
// Parse and Manifest below make the two forms convertible instead of a thing
// you have to remember.
type Permission string

func (p Permission) String() string { return string(p) }

// App is the application slug the permission belongs to.
func (p Permission) App() string { return p.part(0) }

// Resource is the thing being acted on.
func (p Permission) Resource() string { return p.part(1) }

// Action is what is being done to it.
func (p Permission) Action() string { return p.part(2) }

// Manifest renders the permission as a manifest writes it — "resource:action",
// with no application prefix.
func (p Permission) Manifest() string {
	if !p.IsValid() {
		return string(p)
	}
	return p.Resource() + ":" + p.Action()
}

// IsValid reports whether the permission has the three non-empty parts Anubis
// requires.
func (p Permission) IsValid() bool {
	_, ok := p.parts()
	return ok
}

// parts is the single rule App, Resource, Action and IsValid all answer from.
// Two rules would let a malformed key report an application anyway, which
// reads as "no application" rather than as the mistake it is.
func (p Permission) parts() ([3]string, bool) {
	segs := strings.Split(string(p), ":")
	if len(segs) != 3 || segs[0] == "" || segs[1] == "" || segs[2] == "" {
		return [3]string{}, false
	}
	return [3]string{segs[0], segs[1], segs[2]}, true
}

func (p Permission) part(i int) string {
	segs, ok := p.parts()
	if !ok {
		return ""
	}
	return segs[i]
}

// NewPermission builds a full key from its parts, so callers assembling one
// dynamically do not have to know the separator.
func NewPermission(app, resource, action string) Permission {
	return Permission(app + ":" + resource + ":" + action)
}

// Permissions is an effective permission set — what a caller may do, expanded
// from every role they hold.
type Permissions []Permission

func (ps Permissions) Has(want Permission) bool {
	for _, p := range ps {
		if p == want {
			return true
		}
	}
	return false
}

// HasAny reports whether any of the listed permissions is held — the check
// behind "show this menu item at all".
func (ps Permissions) HasAny(want ...Permission) bool {
	for _, w := range want {
		if ps.Has(w) {
			return true
		}
	}
	return false
}

// OfApp narrows to one application's permissions.
func (ps Permissions) OfApp(app string) Permissions {
	out := make(Permissions, 0, len(ps))
	for _, p := range ps {
		if p.App() == app {
			out = append(out, p)
		}
	}
	return out
}

func (ps Permissions) Strings() []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

// ---- roles ----------------------------------------------------------------

// Role is a granted role name, which Anubis returns prefixed with the
// application that defined it: a manifest declaring "clerk" for the billing
// application yields the role "billing.clerk".
//
// Comparing a returned role against the unprefixed name from the manifest is
// the mistake this type exists to make visible.
type Role string

func (r Role) String() string { return string(r) }

// App is the application that defined the role.
func (r Role) App() string {
	if i := strings.IndexByte(string(r), '.'); i >= 0 {
		return string(r)[:i]
	}
	return ""
}

// Name is the role as the manifest declared it, without the prefix.
func (r Role) Name() string {
	if i := strings.IndexByte(string(r), '.'); i >= 0 {
		return string(r)[i+1:]
	}
	return string(r)
}

// NewRole builds the prefixed form from an application slug and a manifest name.
func NewRole(app, name string) Role { return Role(app + "." + name) }

// Roles is the set a caller holds.
type Roles []Role

func (rs Roles) Has(want Role) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}

func (rs Roles) HasAny(want ...Role) bool {
	for _, w := range want {
		if rs.Has(w) {
			return true
		}
	}
	return false
}

// OfApp narrows to the roles one application defined.
func (rs Roles) OfApp(app string) Roles {
	out := make(Roles, 0, len(rs))
	for _, r := range rs {
		if r.App() == app {
			out = append(out, r)
		}
	}
	return out
}

func (rs Roles) Strings() []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// ---- scope axes -----------------------------------------------------------

// Axis names a scope dimension: "org", "customer", "product", or any dimension
// a tenant adds later without a deploy.
//
// It is a type rather than a string because the failure it guards is silent: a
// mistyped axis is not rejected, it is simply not supplied, and an unsupplied
// axis on a strict grant is DENIED. Declaring axes as constants once turns
// that into a compile error at the one place it is written.
type Axis string

func (a Axis) String() string { return string(a) }

// AxisOwner is the reserved axis for self-scoped access: the owner of the
// record being touched. A self-scoped grant with no owner supplied is denied.
const AxisOwner Axis = "_owner"

// Scopes names the target node on each axis an action touches.
//
// The node values stay plain strings deliberately: they are the caller's own
// identifiers, straight out of their own database, and wrapping them would add
// a conversion at every call site to prevent nothing.
type Scopes map[Axis]string

// Owner builds the scope set for self-scoped access, naming the reserved axis
// so it cannot be misspelt into a silent denial.
func Owner(subject SubjectID) Scopes { return Scopes{AxisOwner: string(subject)} }

// With returns a copy with one more axis set, for building a scope set in
// steps without mutating a shared map.
func (s Scopes) With(axis Axis, node string) Scopes {
	out := make(Scopes, len(s)+1)
	for k, v := range s {
		out[k] = v
	}
	out[axis] = node
	return out
}

// Merge returns a copy with other's axes laid over this one's.
func (s Scopes) Merge(other Scopes) Scopes {
	out := make(Scopes, len(s)+len(other))
	for k, v := range s {
		out[k] = v
	}
	for k, v := range other {
		out[k] = v
	}
	return out
}

// Node returns the target on one axis.
func (s Scopes) Node(axis Axis) (string, bool) {
	v, ok := s[axis]
	return v, ok
}

// Axes lists the axes supplied, sorted, so a scope set has one printable form.
func (s Scopes) Axes() []Axis {
	out := make([]Axis, 0, len(s))
	for axis := range s {
		out = append(out, axis)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s Scopes) IsEmpty() bool { return len(s) == 0 }

// String renders the scope set for logs and errors: "customer=c1 org=o1".
func (s Scopes) String() string {
	var b strings.Builder
	for i, axis := range s.Axes() {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(string(axis))
		b.WriteByte('=')
		b.WriteString(s[axis])
	}
	return b.String()
}

// wire renders the scope set as the map the API expects.
func (s Scopes) wire() map[string]string {
	out := make(map[string]string, len(s))
	for axis, node := range s {
		out[string(axis)] = node
	}
	return out
}

// ---- authentication methods ----------------------------------------------

// AuthMethod is one method a caller authenticated with — the "amr" claim.
type AuthMethod string

func (m AuthMethod) String() string { return string(m) }

// The methods Anubis mints today. A realm may require others later; the type
// is open, and these are the ones worth having a name for.
const (
	MethodPassword  AuthMethod = "pwd"
	MethodOTP       AuthMethod = "otp"
	MethodDeviceKey AuthMethod = "device_key"
)

// AuthMethods is the set a caller authenticated with. Step-up decisions turn
// on it, which is why it travels on every authorization request.
type AuthMethods []AuthMethod

func (ms AuthMethods) Has(want AuthMethod) bool {
	for _, m := range ms {
		if m == want {
			return true
		}
	}
	return false
}

// HasAll reports whether every listed method was used — the local form of a
// step-up check, answerable without asking Anubis.
func (ms AuthMethods) HasAll(want ...AuthMethod) bool {
	for _, w := range want {
		if !ms.Has(w) {
			return false
		}
	}
	return true
}

func (ms AuthMethods) Strings() []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = string(m)
	}
	return out
}

// ---- identity -------------------------------------------------------------

// Identity is who a caller is and what they hold, in one place.
//
// It answers the question every application asks first — "who is this, what
// roles do they have, and what are they scoped to right now" — without the
// caller reaching into a claim set and remembering which fields mean what.
//
// It is a VIEW OF A SESSION, not of a person. Roles and Scopes are what this
// token was minted with: the roles held at issuance, and the ONE node per axis
// the session is currently acting as. It is not the full set of nodes the
// person is entitled to — that lives in grants, and grants are the admin
// plane's business. See Scopes below and the note on Client.Me.
type Identity struct {
	Subject   SubjectID
	Session   SessionID
	Tenant    TenantID
	Realm     string
	Roles     Roles
	Scopes    Scopes
	Methods   AuthMethods
	Assurance int

	authenticatedAt time.Time
	expiresAt       time.Time
}

// AuthenticatedAt is when the caller last proved who they were. Step-up rules
// with a max age are decided against this, not against the token's issue time.
func (i Identity) AuthenticatedAt() time.Time { return i.authenticatedAt }

// ExpiresAt is when the access token stops being accepted.
func (i Identity) ExpiresAt() time.Time { return i.expiresAt }

// AuthAge is how long ago the caller authenticated.
func (i Identity) AuthAge() time.Duration {
	if i.authenticatedAt.IsZero() {
		return 0
	}
	return time.Since(i.authenticatedAt)
}

// HasRole is the cheap local check. It answers "does this token say so", which
// is not the same question as "may they do this" — roles are an input to a
// decision, not the decision. Reach for Client.Require when it matters.
func (i Identity) HasRole(r Role) bool { return i.Roles.Has(r) }

// ActiveScope is the node this session is acting as on one axis.
func (i Identity) ActiveScope(axis Axis) (string, bool) { return i.Scopes.Node(axis) }

// IsApplication reports whether this is a service acting as itself rather than
// a person — no session, no refresh, sub of "app_…".
func (i Identity) IsApplication() bool { return i.Subject.IsApplication() }

func (i Identity) String() string {
	if i.Scopes.IsEmpty() {
		return string(i.Subject)
	}
	return string(i.Subject) + " [" + i.Scopes.String() + "]"
}
