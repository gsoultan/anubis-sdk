// Package admin reads and configures the Anubis administration plane:
// identities, grants, roles, scope nodes, the sources those are synced from,
// and the sign-in pages a tenant serves.
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
	"strconv"
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

	procSetSyncSchedule = "/anubis.v1.ScopeAdminService/SetSyncSchedule"

	procListCatalogSources  = "/anubis.v1.AuthzAdminService/ListCatalogSources"
	procCreateCatalogSource = "/anubis.v1.AuthzAdminService/CreateCatalogSource"
	procUpdateCatalogSource = "/anubis.v1.AuthzAdminService/UpdateCatalogSource"
	procDeleteCatalogSource = "/anubis.v1.AuthzAdminService/DeleteCatalogSource"
	procRunCatalogSource    = "/anubis.v1.AuthzAdminService/RunCatalogSource"
	procListCatalogRuns     = "/anubis.v1.AuthzAdminService/ListCatalogRuns"
	procApplyManifest       = "/anubis.v1.AuthzAdminService/ApplyManifest"

	procListAuthPages      = "/anubis.v1.TenantAdminService/ListAuthPages"
	procGetAuthPage        = "/anubis.v1.TenantAdminService/GetAuthPage"
	procCreateAuthPage     = "/anubis.v1.TenantAdminService/CreateAuthPage"
	procUpdateAuthPage     = "/anubis.v1.TenantAdminService/UpdateAuthPage"
	procDeleteAuthPage     = "/anubis.v1.TenantAdminService/DeleteAuthPage"
	procSetDefaultAuthPage = "/anubis.v1.TenantAdminService/SetDefaultAuthPage"

	procListTenants        = "/anubis.v1.TenantAdminService/ListTenants"
	procCreateTenant       = "/anubis.v1.TenantAdminService/CreateTenant"
	procUpdateTenant       = "/anubis.v1.TenantAdminService/UpdateTenant"
	procSetTenantStatus    = "/anubis.v1.TenantAdminService/SetTenantStatus"
	procListRealms         = "/anubis.v1.TenantAdminService/ListRealms"
	procCreateRealm        = "/anubis.v1.TenantAdminService/CreateRealm"
	procUpdateRealm        = "/anubis.v1.TenantAdminService/UpdateRealm"
	procListApplications   = "/anubis.v1.TenantAdminService/ListApplications"
	procCreateApplication  = "/anubis.v1.TenantAdminService/CreateApplication"
	procUpdateApplication  = "/anubis.v1.TenantAdminService/UpdateApplication"
	procRotateClientSecret = "/anubis.v1.TenantAdminService/RotateClientSecret"
	procListAPIKeys        = "/anubis.v1.TenantAdminService/ListApiKeys"
	procCreateAPIKey       = "/anubis.v1.TenantAdminService/CreateApiKey"
	procRevokeAPIKey       = "/anubis.v1.TenantAdminService/RevokeApiKey"
)

// MinScheduleInterval is the floor the server puts under any non-zero schedule,
// for both a scope sync source and a catalog source. A structure is an org
// chart and a catalog is a document a team edits; anything faster is polling
// somebody else's system for rows that did not move.
//
// Zero always means manual: the scheduler will never pick the source up.
const MinScheduleInterval = 5 * time.Minute

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
	// Deprecated is set when a manifest stops naming a role it owns. The role
	// cannot be granted to anybody new and every grant that already names it
	// keeps working, so authorize() never reads this — but a picker that
	// offers it is offering a dead end.
	Deprecated bool `json:"deprecated"`
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
	// RetentionUntil is the deadline a statutory retention limit gives the
	// sweeper to anonymise this identity. Zero when the realm sets no limit,
	// which is the case for employees.
	RetentionUntil epoch `json:"retentionUntil"`
}

// IsActive reports whether the identity may authenticate at all. A disabled
// identity is denied on the next decision whatever tokens it still holds.
func (i Identity) IsActive() bool { return i.Status == "active" && i.DisabledAt.time().IsZero() }

// Created is when the identity was created.
func (i Identity) Created() time.Time { return i.CreatedAt.time() }

// LastLogin is when it last signed in. Zero if never.
func (i Identity) LastLogin() time.Time { return i.LastLoginAt.time() }

// RetentionDeadline is when the sweeper will anonymise this identity under the
// realm's statutory retention limit. Zero when there is no limit — an access
// review that renders this as a dash for everyone has stopped reading it.
func (i Identity) RetentionDeadline() time.Time { return i.RetentionUntil.time() }

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
	PageSize int
	Page     string
}

// ScopeNodePage is one page of scope nodes.
type ScopeNodePage struct {
	Nodes    []ScopeNode `json:"nodes"`
	NextPage string      `json:"nextPageToken"`
}

// ScopeNodes lists one page of nodes on an axis.
//
// An axis can hold hundreds of thousands of nodes, so this listing is paged. A
// caller that reads Nodes and ignores NextPage renders a truncated picker and
// gets no error saying so — use AllScopeNodes unless you are doing your own
// paging.
func (c *Client) ScopeNodes(ctx context.Context, q ScopeNodeQuery) (*ScopeNodePage, error) {
	req := map[string]any{
		"axis": string(q.Axis), "parent_id": q.ParentID,
		"query": q.Query, "include_archived": q.Archived,
		"page_size": q.PageSize, "page_token": q.Page,
	}
	var out ScopeNodePage
	if err := c.call(ctx, procListScopeNodes, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// maxScopeNodes bounds AllScopeNodes. Past this many, an axis is not something
// a picker should be rendering at all: the caller wants a search term, or its
// own paging.
const maxScopeNodes = 50_000

// AllScopeNodes walks every page of a node listing — the whole axis, which is
// what a scope picker renders and what feeds SwitchScope.
//
// This exists because the single-page form is the shape that truncates
// silently: an axis holding more nodes than one page answers with a short list
// and no error, and the user simply cannot find the org they hold.
func (c *Client) AllScopeNodes(ctx context.Context, q ScopeNodeQuery) ([]ScopeNode, error) {
	var all []ScopeNode
	seen := map[string]bool{}
	for {
		page, err := c.ScopeNodes(ctx, q)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Nodes...)
		if page.NextPage == "" {
			return all, nil
		}
		if len(all) > maxScopeNodes {
			return nil, fmt.Errorf(
				"anubis/admin: axis %q holds more than %d nodes; narrow it with Query, or page it with ScopeNodes",
				q.Axis, maxScopeNodes)
		}
		// A server that hands back a token it has already given would
		// otherwise spin here forever.
		if seen[page.NextPage] {
			return nil, fmt.Errorf("anubis/admin: axis %q repeated page token %q", q.Axis, page.NextPage)
		}
		seen[page.NextPage] = true
		q.Page = page.NextPage
	}
}

// ---- catalog sources ------------------------------------------------------

// CatalogSource is a configured origin for ONE application's catalog — the
// permissions and roles it declares — read on a schedule when nobody is
// pushing them.
//
// The application is a pin, not a parameter: it is fixed when the source is
// created, and [Client.UpdateCatalogSource] has no field for it because the
// server ignores any attempt to move one.
type CatalogSource struct {
	ID              string `json:"id"`
	ApplicationSlug string `json:"applicationSlug"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`   // http
	Format          string `json:"format"` // json | csv
	Status          string `json:"status"` // active | disabled
	// ConfigJSON holds the kind's own settings — for http,
	// {"url":…, "auth_header":…}.
	ConfigJSON      string `json:"configJson"`
	IntervalSeconds int    `json:"intervalSeconds"`
	LastRunAt       epoch  `json:"lastRunAt"`
	NextRunAt       epoch  `json:"nextRunAt"`
	// LastStatus is how the most recent attempt ended — ok, failed, skipped,
	// dry_run, running — or empty if it has never run. It rides on the source
	// so a listing can show a broken feed without a request per row.
	LastStatus string `json:"lastStatus"`
}

// Every reports how often the source is scheduled. Zero means manual: the
// scheduler will never pick it up.
func (s CatalogSource) Every() time.Duration {
	return time.Duration(s.IntervalSeconds) * time.Second
}

// IsManual reports whether the source only runs when somebody asks.
func (s CatalogSource) IsManual() bool { return s.IntervalSeconds == 0 }

// LastRun is when the source was last read. Zero if never.
func (s CatalogSource) LastRun() time.Time { return s.LastRunAt.time() }

// NextRun is when the scheduler will read it next. Zero for a manual source.
func (s CatalogSource) NextRun() time.Time { return s.NextRunAt.time() }

// IsBroken reports whether the most recent run failed. A source that has never
// run is not broken.
func (s CatalogSource) IsBroken() bool { return s.LastStatus == "failed" }

// CatalogRun is one attempt to read a source and apply what it returned.
type CatalogRun struct {
	ID        string `json:"id"`
	SourceID  string `json:"sourceId"`
	StartedAt epoch  `json:"startedAt"`
	// FinishedAt is zero while a run is in flight — or if the process died
	// mid-run, and a row stuck like that is itself the diagnosis.
	FinishedAt epoch `json:"finishedAt"`
	Dry        bool  `json:"dry"`
	// Status is running | ok | failed | dry_run | skipped. "skipped" means the
	// document was byte-identical to the one already installed: nothing was
	// written and no manifest version was burned.
	Status string `json:"status"`
	// Actor is "system" for a scheduled run, or the operator's id when
	// somebody pressed the button.
	Actor       string `json:"actor"`
	DocumentSHA string `json:"documentSha"`
	ReportJSON  string `json:"reportJson"`
	Error       string `json:"error"`
}

// Started is when the run began.
func (r CatalogRun) Started() time.Time { return r.StartedAt.time() }

// Finished is when it ended. Zero while in flight.
func (r CatalogRun) Finished() time.Time { return r.FinishedAt.time() }

// InFlight reports whether the run has not finished. A run left like this by a
// process that died reads the same way, which is the intent.
func (r CatalogRun) InFlight() bool { return r.FinishedAt.time().IsZero() }

// Applied reports whether the run wrote anything. A dry run and a skipped run
// both succeeded without changing the catalog.
func (r CatalogRun) Applied() bool { return r.Status == "ok" }

// CatalogSources lists every configured catalog source for the tenant.
func (c *Client) CatalogSources(ctx context.Context) ([]CatalogSource, error) {
	var out struct {
		Sources []CatalogSource `json:"sources"`
	}
	if err := c.call(ctx, procListCatalogSources, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Sources, nil
}

// NewCatalogSource describes a source to create.
type NewCatalogSource struct {
	// ApplicationSlug is pinned at creation and cannot be changed afterwards.
	ApplicationSlug string
	Name            string
	Kind            string // http
	Format          string // json | csv; empty means json
	ConfigJSON      string
	// Every is how often to read it. Zero means manual. Anything else must be
	// at least MinScheduleInterval.
	Every time.Duration
}

// CreateCatalogSource configures a new source.
func (c *Client) CreateCatalogSource(ctx context.Context, s NewCatalogSource) (*CatalogSource, error) {
	secs, err := scheduleSeconds(s.Every)
	if err != nil {
		return nil, err
	}
	if s.ApplicationSlug == "" {
		return nil, fmt.Errorf("anubis/admin: a catalog source needs an application; it is pinned at creation and cannot be moved later")
	}
	req := map[string]any{
		"application_slug": s.ApplicationSlug,
		"name":             s.Name,
		"kind":             s.Kind,
		"format":           s.Format,
		"config_json":      s.ConfigJSON,
		"interval_seconds": secs,
	}
	var out struct {
		Source *CatalogSource `json:"source"`
	}
	if err := c.call(ctx, procCreateCatalogSource, req, &out); err != nil {
		return nil, err
	}
	if out.Source == nil {
		return nil, fmt.Errorf("anubis/admin: the server created no catalog source")
	}
	return out.Source, nil
}

// CatalogSourceUpdate changes a source. There is no application field: the
// application is pinned at creation.
type CatalogSourceUpdate struct {
	ID         string
	Name       string
	Status     string // active | disabled
	Format     string
	ConfigJSON string
	// Every is how often to read it. Zero means manual. Anything else must be
	// at least MinScheduleInterval.
	Every time.Duration
}

// UpdateCatalogSource replaces a source's configuration.
//
// This writes config wholesale. To change only when a source runs, use
// [Client.SetSyncSchedule] for a scope sync source; a catalog source carries
// its schedule here.
func (c *Client) UpdateCatalogSource(ctx context.Context, u CatalogSourceUpdate) (*CatalogSource, error) {
	secs, err := scheduleSeconds(u.Every)
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"id": u.ID, "name": u.Name, "status": u.Status,
		"format": u.Format, "config_json": u.ConfigJSON,
		"interval_seconds": secs,
	}
	var out struct {
		Source *CatalogSource `json:"source"`
	}
	if err := c.call(ctx, procUpdateCatalogSource, req, &out); err != nil {
		return nil, err
	}
	if out.Source == nil {
		return nil, fmt.Errorf("anubis/admin: no catalog source %q", u.ID)
	}
	return out.Source, nil
}

// DeleteCatalogSource removes a source and its run history. What the runs
// applied survives in the audit log.
func (c *Client) DeleteCatalogSource(ctx context.Context, id string) error {
	var out struct{}
	return c.call(ctx, procDeleteCatalogSource, map[string]any{"id": id}, &out)
}

// RunCatalogSource reads a source now, rather than waiting for the scheduler.
//
// A dry run reports what it would do and writes nothing — which is the call to
// make first against a source nobody has run before.
func (c *Client) RunCatalogSource(ctx context.Context, sourceID string, dry bool) (*CatalogRun, error) {
	var out struct {
		Run *CatalogRun `json:"run"`
	}
	req := map[string]any{"source_id": sourceID, "dry": dry}
	if err := c.call(ctx, procRunCatalogSource, req, &out); err != nil {
		return nil, err
	}
	if out.Run == nil {
		return nil, fmt.Errorf("anubis/admin: no run started for catalog source %q", sourceID)
	}
	return out.Run, nil
}

// CatalogRuns lists a source's run history, most recent first. A limit of zero
// leaves the count to the server.
func (c *Client) CatalogRuns(ctx context.Context, sourceID string, limit int) ([]CatalogRun, error) {
	var out struct {
		Runs []CatalogRun `json:"runs"`
	}
	req := map[string]any{"source_id": sourceID, "limit": limit}
	if err := c.call(ctx, procListCatalogRuns, req, &out); err != nil {
		return nil, err
	}
	return out.Runs, nil
}

// ---- scope sync schedules -------------------------------------------------

// SyncSource is where a scope axis's nodes are read from — an org chart that
// lives in somebody else's system.
type SyncSource struct {
	ID              string      `json:"id"`
	Axis            anubis.Axis `json:"axis"`
	Kind            string      `json:"kind"` // http | db_query | db_table
	Status          string      `json:"status"`
	ConfigJSON      string      `json:"configJson"`
	LastRunAt       epoch       `json:"lastRunAt"`
	IntervalSeconds int         `json:"intervalSeconds"`
	NextRunAt       epoch       `json:"nextRunAt"`
}

// Every reports how often the source is scheduled. Zero means manual.
func (s SyncSource) Every() time.Duration {
	return time.Duration(s.IntervalSeconds) * time.Second
}

// IsManual reports whether the source only runs when somebody asks.
func (s SyncSource) IsManual() bool { return s.IntervalSeconds == 0 }

// LastRun is when the axis was last synced. Zero if never.
func (s SyncSource) LastRun() time.Time { return s.LastRunAt.time() }

// NextRun is when the scheduler will sync it next. Zero for a manual source.
func (s SyncSource) NextRun() time.Time { return s.NextRunAt.time() }

// SetSyncSchedule changes WHEN a scope sync source runs, and nothing else.
//
// It is separate from updating the source because that replaces configuration
// wholesale, and a client is never sent a source's dsn or auth header to send
// back — so a read-modify-write through the update call would blank them.
//
// Zero means manual: the scheduler will never pick the source up. Anything
// else must be at least [MinScheduleInterval].
func (c *Client) SetSyncSchedule(ctx context.Context, sourceID string, every time.Duration) (*SyncSource, error) {
	secs, err := scheduleSeconds(every)
	if err != nil {
		return nil, err
	}
	req := map[string]any{"source_id": sourceID, "interval_seconds": secs}
	var out struct {
		Source *SyncSource `json:"source"`
	}
	if err := c.call(ctx, procSetSyncSchedule, req, &out); err != nil {
		return nil, err
	}
	if out.Source == nil {
		return nil, fmt.Errorf("anubis/admin: no sync source %q", sourceID)
	}
	return out.Source, nil
}

// scheduleSeconds converts a schedule to the wire's int32 seconds, refusing an
// interval the server would refuse anyway — with a message that says what the
// floor is, rather than a round trip that says "invalid argument".
func scheduleSeconds(every time.Duration) (int, error) {
	if every == 0 {
		return 0, nil
	}
	if every < 0 {
		return 0, fmt.Errorf("anubis/admin: a schedule cannot be negative; use 0 for manual")
	}
	if every < MinScheduleInterval {
		return 0, fmt.Errorf(
			"anubis/admin: schedule %s is below the %s floor; use 0 for manual, or a longer interval",
			every, MinScheduleInterval)
	}
	return int(every / time.Second), nil
}

// ---- auth pages -----------------------------------------------------------

// ErrAuthPageBinding means a page named both an application and a realm.
//
// The database refuses the row (auth_pages_one_binding), so this is caught
// here rather than spent on a round trip: a page is the door ONE population
// walks through, and naming two is not a stricter binding, it is an undefined
// one.
var ErrAuthPageBinding = errors.New(
	"anubis/admin: an auth page binds to an application OR a realm, never both")

// AuthPage is a sign-in or sign-out page a tenant serves.
//
// A page is bound to an application or to a realm, never both. A realm binding
// is the door that whole population sees; resolution runs slug → application →
// realm → tenant default.
type AuthPage struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`   // signin | signout
	Slug   string `json:"slug"`   // the URL segment: /p/{tenant}/{kind}/{slug}
	Name   string `json:"name"`   // admin-facing label
	Status string `json:"status"` // active | disabled
	// IsDefault marks the page a population falls back to.
	IsDefault       bool   `json:"isDefault"`
	ApplicationID   string `json:"applicationId"`
	ApplicationSlug string `json:"applicationSlug"`
	RealmID         string `json:"realmId"`
	RealmCode       string `json:"realmCode"`
	ConfigJSON      string `json:"configJson"`
	CreatedAt       epoch  `json:"createdAt"`
	UpdatedAt       epoch  `json:"updatedAt"`
	// URL is where the page is actually served. Read-only.
	URL string `json:"url"`
}

// Created is when the page was created.
func (p AuthPage) Created() time.Time { return p.CreatedAt.time() }

// Updated is when it was last changed.
func (p AuthPage) Updated() time.Time { return p.UpdatedAt.time() }

// BoundToRealm reports whether this page is a whole population's door rather
// than one application's.
func (p AuthPage) BoundToRealm() bool { return p.RealmID != "" || p.RealmCode != "" }

// BoundToApplication reports whether the page belongs to one application.
func (p AuthPage) BoundToApplication() bool {
	return p.ApplicationID != "" || p.ApplicationSlug != ""
}

// AuthPages lists the tenant's pages. An empty kind returns both signin and
// signout pages.
func (c *Client) AuthPages(ctx context.Context, kind string) ([]AuthPage, error) {
	var out struct {
		Pages []AuthPage `json:"pages"`
	}
	if err := c.call(ctx, procListAuthPages, map[string]any{"kind": kind}, &out); err != nil {
		return nil, err
	}
	return out.Pages, nil
}

// AuthPage reads one page.
func (c *Client) AuthPage(ctx context.Context, id string) (*AuthPage, error) {
	var out struct {
		Page *AuthPage `json:"page"`
	}
	if err := c.call(ctx, procGetAuthPage, map[string]any{"id": id}, &out); err != nil {
		return nil, err
	}
	if out.Page == nil {
		return nil, fmt.Errorf("anubis/admin: no auth page %q", id)
	}
	return out.Page, nil
}

// UpdateAuthPage writes a page back.
//
// It refuses a page that names both an application and a realm with
// [ErrAuthPageBinding], because the database refuses that row and the error it
// returns does not say which of the two bindings was the accident.
func (c *Client) UpdateAuthPage(ctx context.Context, p AuthPage) (*AuthPage, error) {
	if p.BoundToApplication() && p.BoundToRealm() {
		return nil, ErrAuthPageBinding
	}
	var out struct {
		Page *AuthPage `json:"page"`
	}
	if err := c.call(ctx, procUpdateAuthPage, map[string]any{"page": p}, &out); err != nil {
		return nil, err
	}
	if out.Page == nil {
		return nil, fmt.Errorf("anubis/admin: no auth page %q", p.ID)
	}
	return out.Page, nil
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

// MarshalJSON writes the protojson form: int64 is a JSON string on the wire.
func (e epoch) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatInt(int64(e), 10) + `"`), nil
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
