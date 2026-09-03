// Package admin reads the Anubis administration plane: identities, grants,
// roles and scope nodes.
//
// # This needs an operator, not an application
//
// The admin plane is not a matter of holding the right permission. Anubis's
// guard refuses any non-platform caller outright, and says why:
//
//	"Not a policy lookup that happens to deny — a different population.
//	 The permission strings this plane checks exist only in the operator role
//	 allow-lists; no tenant grant can confer them."
//
// So a tenant API key — the anb_live_ credential an application holds — is
// denied here at any scope, and no grant can change that. What you need is a
// PLATFORM operator's credential. Confusingly the two are the same shape:
// nothing in the string says which you hold, and the server decides by which
// store issued it. This package cannot tell them apart either, so it does the
// next best thing and turns the refusal into [ErrNotPlatformOperator] rather
// than a generic permission error.
//
// # What it is for
//
// The integration SDK answers "who is this caller and what is this session
// scoped to". It cannot answer "what is this person entitled to", because that
// lives in grants and grants are administrative data. Provisioning tools,
// access reviews, and the screen that renders a scope picker need this; a
// payments service does not.
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
)

const (
	procListGrants      = "/anubis.v1.AuthzAdminService/ListGrants"
	procSearchGrants    = "/anubis.v1.AuthzAdminService/SearchGrants"
	procListMemberships = "/anubis.v1.AuthzAdminService/ListMemberships"
	procListRoles       = "/anubis.v1.AuthzAdminService/ListRoles"
	procRoleEffective   = "/anubis.v1.AuthzAdminService/GetRoleEffective"
	procListPermissions = "/anubis.v1.AuthzAdminService/ListPermissions"
	procListIdentities  = "/anubis.v1.IdentityAdminService/ListIdentities"
	procGetIdentity     = "/anubis.v1.IdentityAdminService/GetIdentity"
	procListScopeNodes  = "/anubis.v1.ScopeAdminService/ListScopeNodes"
	procScopeAncestors  = "/anubis.v1.ScopeAdminService/ScopeAncestors"
	procListScopeAxes   = "/anubis.v1.ScopeAdminService/ListScopeAxes"
)

// ErrNotPlatformOperator means the credential is a tenant's, not an operator's.
//
// Not a missing permission — a different population. Granting something will
// not fix it; the call needs a platform operator's credential, and an
// application does not have one and should not be given one.
var ErrNotPlatformOperator = errors.New(
	"anubis/admin: the admin plane refuses non-platform callers — this needs a platform operator's credential, not a tenant api key")

// Client reads the administration plane.
//
// It wraps a configured [anubis.Client], so it inherits the credential, the
// headers, the timeout and the error vocabulary. Set the tenant being
// administered with anubis.WithTenant, which becomes the X-Anubis-Tenant
// header the operator plane requires for tenant-scoped calls.
type Client struct {
	rpc *anubis.Client
}

// New wraps a client configured with a platform operator's credential.
func New(c *anubis.Client) (*Client, error) {
	if c == nil {
		return nil, errors.New("anubis/admin: needs a client")
	}
	return &Client{rpc: c}, nil
}

func (c *Client) call(ctx context.Context, procedure string, in, out any) error {
	err := c.rpc.Call(ctx, procedure, in, out)
	if err == nil {
		return nil
	}
	// The server hands back a hint on exactly this refusal. Recognising it
	// turns "permission denied" — which reads as "ask for a grant" — into the
	// truth, which is that no grant exists to ask for.
	var api *anubis.APIError
	if errors.As(err, &api) && api.Details["hint"] == "administration is performed by platform users" {
		return fmt.Errorf("%w: %s", ErrNotPlatformOperator, api.Message)
	}
	var authErr *anubis.AuthError
	if errors.As(err, &authErr) && strings.Contains(err.Error(), "platform users") {
		return fmt.Errorf("%w: %v", ErrNotPlatformOperator, err)
	}
	return err
}

// ---- grants ---------------------------------------------------------------

// GrantScope is one axis a grant is constrained on.
//
// A grant may carry SEVERAL nodes on the same axis — which is why entitlement
// cannot be expressed as the flat one-node-per-axis map a token carries.
type GrantScope struct {
	Axis     anubis.Axis `json:"axis"`
	NodeID   string      `json:"nodeId"`
	NodeName string      `json:"nodeName"`
	// Inherit means the grant reaches descendants of this node, not only the
	// node itself.
	Inherit bool `json:"inherit"`
}

// Grant is one role conferred on one identity, over some scope, for some time.
type Grant struct {
	ID         string           `json:"id"`
	Subject    anubis.SubjectID `json:"identityId"`
	RoleID     string           `json:"roleId"`
	Role       anubis.Role      `json:"roleName"`
	SelfScoped bool             `json:"selfScoped"`
	ValidFrom  epoch            `json:"validFrom"`
	ValidUntil epoch            `json:"validUntil"`
	RevokedAt  epoch            `json:"revokedAt"`
	GrantedBy  string           `json:"grantedBy"`
	// ViaMembership is set when the grant came from a group rather than from
	// somebody granting it directly. Revoking it means changing the
	// membership, not the grant.
	ViaMembership string       `json:"viaMembershipId"`
	Reason        string       `json:"reason"`
	Scopes        []GrantScope `json:"scopes"`
}

// IsLive reports whether the grant confers anything at a given moment.
//
// A grant is not a boolean: it has a validity window and a revocation, and a
// list of "grants" that ignores both will show access that does not exist.
func (g Grant) IsLive(at time.Time) bool {
	if g.RevokedAt.time() != (time.Time{}) && !at.Before(g.RevokedAt.time()) {
		return false
	}
	if from := g.ValidFrom.time(); !from.IsZero() && at.Before(from) {
		return false
	}
	if until := g.ValidUntil.time(); !until.IsZero() && !at.Before(until) {
		return false
	}
	return true
}

// Nodes lists the nodes this grant reaches on one axis.
func (g Grant) Nodes(axis anubis.Axis) []string {
	var out []string
	for _, s := range g.Scopes {
		if s.Axis == axis {
			out = append(out, s.NodeID)
		}
	}
	return out
}

// Grants lists every grant held by one identity, revoked ones included.
//
// Revoked grants are returned because an access review that cannot see what
// was taken away, and when, is not a review. Filter with [Grant.IsLive].
func (c *Client) Grants(ctx context.Context, subject anubis.SubjectID) ([]Grant, error) {
	var out struct {
		Grants []Grant `json:"grants"`
	}
	req := map[string]any{"identity_id": string(subject), "include_revoked": true}
	if err := c.call(ctx, procListGrants, req, &out); err != nil {
		return nil, err
	}
	return out.Grants, nil
}

// Entitlements is what a person may do and where — the question the
// integration SDK cannot answer.
type Entitlements struct {
	Subject anubis.SubjectID
	Grants  []Grant
	at      time.Time
}

// Entitlements reads every live grant for an identity and assembles them.
func (c *Client) Entitlements(ctx context.Context, subject anubis.SubjectID) (*Entitlements, error) {
	grants, err := c.Grants(ctx, subject)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	live := make([]Grant, 0, len(grants))
	for _, g := range grants {
		if g.IsLive(now) {
			live = append(live, g)
		}
	}
	return &Entitlements{Subject: subject, Grants: live, at: now}, nil
}

// Roles is every role these grants confer, deduplicated.
func (e *Entitlements) Roles() anubis.Roles {
	seen := map[anubis.Role]bool{}
	out := anubis.Roles{}
	for _, g := range e.Grants {
		if g.Role != "" && !seen[g.Role] {
			seen[g.Role] = true
			out = append(out, g.Role)
		}
	}
	return out
}

// Nodes is every node this person is granted on one axis.
//
// This is what a scope picker needs and what nothing on the integration plane
// can supply: a token carries the ONE node a session is acting as, while a
// person may hold many. Feed the result to anubis.Client.SwitchScope.
func (e *Entitlements) Nodes(axis anubis.Axis) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range e.Grants {
		for _, node := range g.Nodes(axis) {
			if !seen[node] {
				seen[node] = true
				out = append(out, node)
			}
		}
	}
	return out
}

// Axes lists every axis any grant constrains, sorted.
func (e *Entitlements) Axes() []anubis.Axis {
	seen := map[anubis.Axis]bool{}
	var out []anubis.Axis
	for _, g := range e.Grants {
		for _, s := range g.Scopes {
			if !seen[s.Axis] {
				seen[s.Axis] = true
				out = append(out, s.Axis)
			}
		}
	}
	sortAxes(out)
	return out
}

// IsUnscoped reports whether any grant is unconstrained on every axis — which
// is worth knowing before believing a tidy-looking scope list.
func (e *Entitlements) IsUnscoped() bool {
	for _, g := range e.Grants {
		if len(g.Scopes) == 0 && !g.SelfScoped {
			return true
		}
	}
	return false
}

// GrantQuery searches grants across identities.
type GrantQuery struct {
	// Query matches a username or role name substring.
	Query    string
	Subject  anubis.SubjectID
	RoleID   string
	Source   string // "direct" | "membership" | "" for both
	Revoked  bool
	PageSize int
	Page     string
}

// GrantPage is one page of a grant search.
type GrantPage struct {
	Grants []Grant `json:"grants"`
	// Usernames rides alongside Grants, one per row: resolving them per grant
	// would be one lookup per line.
	Usernames []string `json:"usernames"`
	NextPage  string   `json:"nextPageToken"`
}

// SearchGrants finds grants across identities — the access-review query.
func (c *Client) SearchGrants(ctx context.Context, q GrantQuery) (*GrantPage, error) {
	req := map[string]any{
		"query":           q.Query,
		"identity_id":     string(q.Subject),
		"role_id":         q.RoleID,
		"source":          q.Source,
		"include_revoked": q.Revoked,
		"page_size":       q.PageSize,
		"page_token":      q.Page,
	}
	var out GrantPage
	if err := c.call(ctx, procSearchGrants, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- roles ----------------------------------------------------------------

// Role is a role definition, as opposed to a grant of one.
type Role struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	ApplicationSlug string   `json:"applicationSlug"`
	IsSystem        bool     `json:"isSystem"`
	RealmKinds      []string `json:"allowedRealmKinds"`
	AssignableAt    []string `json:"assignableAt"`
	ParentIDs       []string `json:"parentIds"`
	Patterns        []string `json:"patterns"`
}

// Qualified is the role as tokens and grants spell it: "<app>.<name>".
func (r Role) Qualified() anubis.Role {
	if r.ApplicationSlug == "" {
		return anubis.Role(r.Name)
	}
	return anubis.NewRole(r.ApplicationSlug, r.Name)
}

// Roles lists role definitions, optionally filtered by a substring.
func (c *Client) Roles(ctx context.Context, query string) ([]Role, error) {
	var out struct {
		Roles []Role `json:"roles"`
	}
	if err := c.call(ctx, procListRoles, map[string]any{"query": query}, &out); err != nil {
		return nil, err
	}
	return out.Roles, nil
}

// RolePermissions is the effective permission set a role confers, including
// everything inherited from its parents.
func (c *Client) RolePermissions(ctx context.Context, roleID string) (anubis.Permissions, error) {
	var out struct {
		Permissions []struct {
			Key string `json:"key"`
		} `json:"permissions"`
	}
	if err := c.call(ctx, procRoleEffective, map[string]any{"role_id": roleID}, &out); err != nil {
		return nil, err
	}
	perms := make(anubis.Permissions, 0, len(out.Permissions))
	for _, p := range out.Permissions {
		perms = append(perms, anubis.Permission(p.Key))
	}
	return perms, nil
}

// Membership is a group that confers grants on its members.
type Membership struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MemberCount int    `json:"memberCount"`
}

// Memberships lists the groups defined for the tenant.
func (c *Client) Memberships(ctx context.Context) ([]Membership, error) {
	var out struct {
		Memberships []Membership `json:"memberships"`
	}
	if err := c.call(ctx, procListMemberships, struct{}{}, &out); err != nil {
		return nil, err
	}
	return out.Memberships, nil
}

// ---- identities -----------------------------------------------------------

// Identity is an administrative view of a person or service account.
type Identity struct {
	ID           anubis.SubjectID `json:"id"`
	Username     string           `json:"username"`
	Email        string           `json:"email"`
	Realm        string           `json:"realm"`
	RealmKind    string           `json:"realmKind"`
	Status       string           `json:"status"`
	Category     string           `json:"category"`
	ExternalRef  string           `json:"externalRef"`
	Assurance    int              `json:"assuranceLevel"`
	TokenEpoch   int              `json:"tokenEpoch"`
	CreatedAt    epoch            `json:"createdAt"`
	LastLoginAt  epoch            `json:"lastLoginAt"`
	DisabledAt   epoch            `json:"disabledAt"`
	AnonymizedAt epoch            `json:"anonymizedAt"`
}

// IsActive reports whether the identity may authenticate at all. A disabled
// identity is denied on the next decision whatever tokens it still holds.
func (i Identity) IsActive() bool { return i.Status == "active" && i.DisabledAt.time().IsZero() }

// Created is when the identity was created.
func (i Identity) Created() time.Time { return i.CreatedAt.time() }

// LastLogin is when it last signed in. Zero if never.
func (i Identity) LastLogin() time.Time { return i.LastLoginAt.time() }

// IdentityQuery filters a listing.
type IdentityQuery struct {
	Realm    string
	Query    string // username or email substring
	Status   string
	PageSize int
	Page     string
}

// IdentityPage is one page of identities.
type IdentityPage struct {
	Identities []Identity `json:"identities"`
	NextPage   string     `json:"nextPageToken"`
}

// Identities lists identities in the tenant being administered.
func (c *Client) Identities(ctx context.Context, q IdentityQuery) (*IdentityPage, error) {
	req := map[string]any{
		"realm": q.Realm, "query": q.Query, "status": q.Status,
		"page_size": q.PageSize, "page_token": q.Page,
	}
	var out IdentityPage
	if err := c.call(ctx, procListIdentities, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Identity reads one identity.
func (c *Client) Identity(ctx context.Context, id anubis.SubjectID) (*Identity, error) {
	var out struct {
		Identity *Identity `json:"identity"`
	}
	if err := c.call(ctx, procGetIdentity, map[string]any{"id": string(id)}, &out); err != nil {
		return nil, err
	}
	if out.Identity == nil {
		return nil, fmt.Errorf("anubis/admin: no identity %q", id)
	}
	return out.Identity, nil
}

// ---- scope nodes ----------------------------------------------------------

// ScopeNode is one node on a scope axis.
type ScopeNode struct {
	ID          string      `json:"id"`
	Axis        anubis.Axis `json:"axis"`
	NodeType    string      `json:"nodeType"`
	ParentID    string      `json:"parentId"`
	Slug        string      `json:"slug"`
	Name        string      `json:"name"`
	ExternalRef string      `json:"externalRef"`
	Status      string      `json:"status"`
	IsAxisRoot  bool        `json:"isAxisRoot"`
}

// IsArchived reports whether the node has been retired. Archived nodes keep
// deciding for existing grants but should not be offered in a picker.
func (n ScopeNode) IsArchived() bool { return n.Status == "archived" }

// ScopeNodeQuery filters a node listing.
type ScopeNodeQuery struct {
	Axis     anubis.Axis
	ParentID string // empty means the whole axis
	Query    string
	Archived bool
}

// ScopeNodes lists nodes on an axis — what a scope picker renders.
func (c *Client) ScopeNodes(ctx context.Context, q ScopeNodeQuery) ([]ScopeNode, error) {
	req := map[string]any{
		"axis": string(q.Axis), "parent_id": q.ParentID,
		"query": q.Query, "include_archived": q.Archived,
	}
	var out struct {
		Nodes []ScopeNode `json:"nodes"`
	}
	if err := c.call(ctx, procListScopeNodes, req, &out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}

// ---- small helpers --------------------------------------------------------

// epoch decodes a proto int64, which protojson renders as a JSON string.
type epoch int64

func (e *epoch) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*e = 0
		return nil
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return fmt.Errorf("anubis/admin: %q is not an int64", s)
	}
	*e = epoch(n)
	return nil
}

func (e epoch) time() time.Time {
	if e == 0 {
		return time.Time{}
	}
	return time.Unix(int64(e), 0).UTC()
}

func sortAxes(a []anubis.Axis) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
