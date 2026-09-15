package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// # What a manifest is
//
// A manifest is one application's access catalog, written down: the
// permissions the application defines, the roles that bundle them, and the
// route rules that say which HTTP paths need which permission. Applying it is
// a reconcile, not an insert — the server diffs the document against what is
// installed and moves the catalog to match, the way a migration does.
//
// It is the answer to "where do permissions come from?". Nobody types
// billing:invoice:approve into a console: an application declares the
// permissions it has, and the manifest is that declaration.
//
// # The one rule that matters
//
// A manifest has three sections and they are INDEPENDENT. What decides whether
// a section is touched is whether the document DECLARES it — not whether it has
// any content:
//
//	declared, with entries    the catalog is reconciled to match
//	not declared at all       that part of the catalog is left alone
//
// So a document carrying only roles is not saying "this application has no
// permissions and no routes". It is saying "here are the roles; leave the rest
// alone". That is why a CSV export of roles is a legal manifest.
//
// # What reconciling does to what you left out
//
// Within a declared section, anything the document stops naming is retired
// rather than removed — except routes, which are replaced wholesale:
//
//	permissions   named ones upserted; the rest DEPRECATED, never deleted
//	roles         named ones upserted; the rest RETIRED — existing grants
//	              keep deciding exactly as they did, nobody new can be granted
//	routes        the whole route table is REPLACED by what the document says
//
// The asymmetry is deliberate on the server's side and dangerous on yours. A
// permissions or roles section that is present but empty is refused by the
// server — it will not deprecate an entire catalog in one apply. The route
// table has no such rail: an empty routes section empties it.
//
// This package refuses all three cases before they are sent. Emptying the
// route table on purpose is [Manifest.ClearRoutes], which exists so that the
// destructive thing has to be typed out.
//
// # Naming permissions inside a manifest
//
// Roles and routes refer to permissions as "resource:action" — WITHOUT the
// application slug, because the manifest is already scoped to one application.
// Write "invoice:approve", not "billing:invoice:approve". Getting this wrong is
// the most common way an apply fails, so [Manifest.Validate] catches it here
// and says which form to use.
//
// # Start with a dry run
//
// [Client.DryRunManifest] runs the whole apply inside a transaction that always
// rolls back, and returns the same report the real thing would. Print it. It
// says how many permissions moved and what got deprecated, which is the fastest
// way to find out that a document says something you did not mean.

// ManifestPermission is one permission an application defines.
type ManifestPermission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	// Description is what an access review reads. It is the only part of a
	// permission a non-engineer sees.
	Description string `json:"description,omitempty"`
	// Risk is normal, sensitive or critical. Empty means normal.
	Risk string `json:"risk,omitempty"`
	// MinAssurance is 1, 2 or 3, or 0 for unset.
	MinAssurance int `json:"min_assurance,omitempty"`
	// RequiresAMR names authentication methods the session must already have
	// — the step-up requirement, declared with the permission rather than
	// scattered through handlers.
	RequiresAMR []string `json:"requires_amr,omitempty"`
	// MaxAuthAge caps how stale the authentication may be, as a duration the
	// server parses, e.g. "5m".
	MaxAuthAge string `json:"max_auth_age,omitempty"`
}

// Key is how a role or a route names this permission: resource:action, without
// the application slug.
func (p ManifestPermission) Key() string { return p.Resource + ":" + p.Action }

// ManifestRole is a role the application declares, bundling its permissions.
type ManifestRole struct {
	// Name is the bare name — "clerk". The application slug is added by the
	// server, so the role a token carries is "billing.clerk".
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Permissions names permissions as resource:action, WITHOUT the
	// application slug. It may name permissions a previous manifest installed.
	Permissions       []string `json:"permissions,omitempty"`
	Patterns          []string `json:"patterns,omitempty"`
	AllowedRealmKinds []string `json:"allowed_realm_kinds,omitempty"`
}

// ManifestRoute is one rule in the route table: which paths need what.
type ManifestRoute struct {
	// Priority orders the table and must be unique within it.
	Priority    int    `json:"priority"`
	PathPattern string `json:"path_pattern"`
	HostPattern string `json:"host_pattern,omitempty"`
	// Methods defaults to every method when empty.
	Methods []string `json:"methods,omitempty"`
	// Effect is public, require_auth, require_permission or deny.
	Effect string `json:"effect"`
	// Permission is required when Effect is require_permission, as
	// resource:action without the application slug.
	Permission    string            `json:"permission,omitempty"`
	ScopeBindings map[string]string `json:"scope_bindings,omitempty"`
}

// Route effects.
const (
	RoutePublic            = "public"
	RouteRequireAuth       = "require_auth"
	RouteRequirePermission = "require_permission"
	RouteDeny              = "deny"
)

// Permission risk levels.
const (
	RiskNormal    = "normal"
	RiskSensitive = "sensitive"
	RiskCritical  = "critical"
)

// Manifest is an application's catalog document.
//
// Build it by naming only the sections you mean to change. A section you never
// set is not written into the document at all, and the server leaves that part
// of the catalog alone — see the package notes on [ManifestPermission] for why
// that distinction is the whole design.
//
//	m := admin.Manifest{}.
//		WithRoles(admin.ManifestRole{Name: "clerk", Permissions: []string{"invoice:approve"}})
//
// That document changes roles and touches nothing else.
type Manifest struct {
	permissions *[]ManifestPermission
	roles       *[]ManifestRole
	routes      *[]ManifestRoute
	// clearRoutes records that emptying the route table was asked for rather
	// than arrived at by passing an empty slice.
	clearRoutes bool
}

// WithPermissions declares the permissions section.
//
// Permissions the document does not name are deprecated — not deleted, and not
// revoked from anybody holding them.
func (m Manifest) WithPermissions(p ...ManifestPermission) Manifest {
	c := append([]ManifestPermission(nil), p...)
	m.permissions = &c
	return m
}

// WithRoles declares the roles section.
//
// Roles the document does not name are retired: nobody new can be granted one,
// and every grant that already names one keeps deciding exactly as it did.
func (m Manifest) WithRoles(r ...ManifestRole) Manifest {
	c := append([]ManifestRole(nil), r...)
	m.roles = &c
	return m
}

// WithRoutes declares the routes section, REPLACING the application's whole
// route table with what is passed.
//
// This is not a merge. Routes are ordered and shadow-checked as a set, so they
// are applied as a set: whatever is not in this call stops existing. To empty
// the table deliberately, use [Manifest.ClearRoutes] — passing no routes here
// is refused, because that is far more often an empty slice than an intention.
func (m Manifest) WithRoutes(r ...ManifestRoute) Manifest {
	c := append([]ManifestRoute(nil), r...)
	m.routes = &c
	m.clearRoutes = false
	return m
}

// ClearRoutes declares an empty routes section, which deletes the
// application's route table.
//
// It exists so that the one destructive thing a manifest can do has to be
// written on purpose. Nothing else in a manifest removes anything.
func (m Manifest) ClearRoutes() Manifest {
	empty := []ManifestRoute{}
	m.routes = &empty
	m.clearRoutes = true
	return m
}

// Sections lists which parts of the catalog this document declares, and so
// which parts an apply will touch.
func (m Manifest) Sections() []string {
	var s []string
	if m.permissions != nil {
		s = append(s, "permissions")
	}
	if m.roles != nil {
		s = append(s, "roles")
	}
	if m.routes != nil {
		s = append(s, "routes")
	}
	return s
}

// MarshalJSON writes only the declared sections. An undeclared section is an
// absent key, which is what tells the server to leave that part alone.
func (m Manifest) MarshalJSON() ([]byte, error) {
	doc := map[string]any{}
	if m.permissions != nil {
		doc["permissions"] = *m.permissions
	}
	if m.roles != nil {
		doc["roles"] = *m.roles
	}
	if m.routes != nil {
		doc["routes"] = *m.routes
	}
	return json.Marshal(doc)
}

// ErrEmptyManifest means the document declares no section at all, so applying
// it could not change anything.
var ErrEmptyManifest = errors.New(
	"anubis/admin: manifest declares no permissions, roles or routes — there is nothing to apply")

// ErrRouteTableWipe means a routes section was declared with no routes in it.
//
// That empties the application's route table, and unlike permissions and roles
// the server has no rail against it. If it is what you meant, say so with
// [Manifest.ClearRoutes].
var ErrRouteTableWipe = errors.New(
	"anubis/admin: a routes section with no routes deletes the whole route table; use ClearRoutes if that is intended, or omit the section to leave routes alone")

// ErrCatalogWipe means a permissions or roles section was declared empty.
//
// The server refuses to deprecate a whole catalog in one apply, so this never
// does what it looks like it does. Omit the section to leave that part alone.
var ErrCatalogWipe = errors.New(
	"anubis/admin: a permissions or roles section that names nothing would retire the whole catalog; the server refuses it — omit the section to leave it alone")

// Validate reports what the server would reject, before a request is sent.
//
// Every check here mirrors one the server makes. They are done locally because
// a manifest is usually somebody's export of four hundred rows, and "invalid
// argument" against a file that size is not a fault report.
func (m Manifest) Validate() error {
	if len(m.Sections()) == 0 {
		return ErrEmptyManifest
	}
	if m.routes != nil && len(*m.routes) == 0 && !m.clearRoutes {
		return ErrRouteTableWipe
	}
	if (m.permissions != nil && len(*m.permissions) == 0) ||
		(m.roles != nil && len(*m.roles) == 0) {
		return ErrCatalogWipe
	}

	if m.permissions != nil {
		seen := map[string]bool{}
		for i, p := range *m.permissions {
			at := fmt.Sprintf("permission %d", i+1)
			if p.Resource == "" || p.Action == "" {
				return fmt.Errorf("anubis/admin: %s needs a resource and an action", at)
			}
			if seen[p.Key()] {
				// A spreadsheet merged from two teams names the same
				// permission twice, the second row wins, and the description
				// everybody reviewed is not the one that landed.
				return fmt.Errorf("anubis/admin: %s declares %q twice in one document", at, p.Key())
			}
			seen[p.Key()] = true
			switch strings.ToLower(p.Risk) {
			case "", RiskNormal, RiskSensitive, RiskCritical:
			default:
				return fmt.Errorf("anubis/admin: %s has risk %q; expected normal, sensitive or critical", at, p.Risk)
			}
			if p.MinAssurance < 0 || p.MinAssurance > 3 {
				return fmt.Errorf("anubis/admin: %s has min_assurance %d; expected 0 (unset), 1, 2 or 3", at, p.MinAssurance)
			}
		}
	}

	if m.roles != nil {
		seen := map[string]bool{}
		for i, r := range *m.roles {
			at := fmt.Sprintf("role %d", i+1)
			if strings.TrimSpace(r.Name) == "" {
				return fmt.Errorf("anubis/admin: %s needs a name", at)
			}
			if seen[r.Name] {
				return fmt.Errorf("anubis/admin: %s declares %q twice in one document", at, r.Name)
			}
			seen[r.Name] = true
			for _, ref := range r.Permissions {
				if err := checkPermissionRef(ref, "role "+r.Name); err != nil {
					return err
				}
			}
		}
	}

	if m.routes != nil {
		priorities := map[int]string{}
		for i, rt := range *m.routes {
			at := fmt.Sprintf("route %d", i+1)
			if rt.PathPattern == "" {
				return fmt.Errorf("anubis/admin: %s needs a path pattern", at)
			}
			switch rt.Effect {
			case RoutePublic, RouteRequireAuth, RouteRequirePermission, RouteDeny:
			default:
				return fmt.Errorf("anubis/admin: %s (%s) has effect %q; expected %s, %s, %s or %s",
					at, rt.PathPattern, rt.Effect,
					RoutePublic, RouteRequireAuth, RouteRequirePermission, RouteDeny)
			}
			if rt.Effect == RouteRequirePermission {
				if rt.Permission == "" {
					return fmt.Errorf("anubis/admin: %s (%s) is %s but names no permission",
						at, rt.PathPattern, RouteRequirePermission)
				}
				if err := checkPermissionRef(rt.Permission, "route "+rt.PathPattern); err != nil {
					return err
				}
			}
			if prev, dup := priorities[rt.Priority]; dup {
				// Priority orders the table, so two rules sharing one have no
				// defined order between them.
				return fmt.Errorf("anubis/admin: %s (%s) shares priority %d with %q",
					at, rt.PathPattern, rt.Priority, prev)
			}
			priorities[rt.Priority] = rt.PathPattern
		}
	}
	return nil
}

// checkPermissionRef catches the mistake the server calls out by name: writing
// the full permission key where the manifest wants resource:action. The
// obvious guess is the string that appears in tokens and code, and "invalid
// argument" against a value that looks right is a long afternoon.
func checkPermissionRef(ref, where string) error {
	switch strings.Count(ref, ":") {
	case 1:
		if strings.HasPrefix(ref, ":") || strings.HasSuffix(ref, ":") {
			return fmt.Errorf("anubis/admin: %s names permission %q; expected resource:action", where, ref)
		}
		return nil
	case 2:
		parts := strings.SplitN(ref, ":", 2)
		return fmt.Errorf(
			"anubis/admin: %s names permission %q, which is the full key — a manifest is already scoped to its application, so write %q instead",
			where, ref, parts[1])
	default:
		return fmt.Errorf("anubis/admin: %s names permission %q; expected resource:action, without the application slug", where, ref)
	}
}

// ---- the report -----------------------------------------------------------

// ManifestReport is what an apply did, or what a dry run would have done.
type ManifestReport struct {
	// Dry is true when nothing was written.
	Dry bool `json:"dry"`
	// Sections are the parts of the catalog the document declared. Anything
	// not listed here was left alone.
	Sections []string `json:"sections"`
	// Permissions is nil when the document did not declare the section.
	Permissions *ManifestPermissionsReport `json:"permissions,omitempty"`
	Roles       *ManifestRolesReport       `json:"roles,omitempty"`
	Routes      *ManifestRoutesReport      `json:"routes,omitempty"`
	// Version is the application's manifest version after the apply. A dry run
	// reports the version it would have produced.
	Version int `json:"-"`
}

// ManifestPermissionsReport is what happened to the permission catalog.
type ManifestPermissionsReport struct {
	Applied        int `json:"applied"`
	AddedOrUpdated int `json:"added_or_updated"`
	// Deprecated names permissions the document stopped naming. They are not
	// deleted and nobody loses one they hold.
	Deprecated []string `json:"deprecated"`
}

// ManifestRolesReport is what happened to the role catalog.
type ManifestRolesReport struct {
	Applied int `json:"applied"`
	// Deprecated names roles the document stopped naming. Existing grants keep
	// deciding; the role simply cannot be granted to anybody new.
	Deprecated []string `json:"deprecated"`
}

// ManifestRoutesReport is what happened to the route table.
type ManifestRoutesReport struct {
	// Replaced is how many rules the table now holds. It was replaced whole.
	Replaced int `json:"replaced"`
}

// Retired reports whether the apply took anything out of the catalog —
// permissions deprecated, roles retired, or a route table shrunk to nothing.
// It is the part of a report worth reading before a real apply.
func (r ManifestReport) Retired() bool {
	if r.Permissions != nil && len(r.Permissions.Deprecated) > 0 {
		return true
	}
	if r.Roles != nil && len(r.Roles.Deprecated) > 0 {
		return true
	}
	return r.Routes != nil && r.Routes.Replaced == 0
}

// String renders the report as something worth printing after a dry run.
func (r ManifestReport) String() string {
	var b strings.Builder
	if r.Dry {
		b.WriteString("dry run — nothing was written\n")
	} else {
		fmt.Fprintf(&b, "applied — manifest version %d\n", r.Version)
	}
	declared := map[string]bool{}
	for _, s := range r.Sections {
		declared[s] = true
	}
	line := func(name, detail string) {
		fmt.Fprintf(&b, "  %-12s %s\n", name, detail)
	}
	if p := r.Permissions; p != nil {
		detail := fmt.Sprintf("%d applied", p.Applied)
		if n := len(p.Deprecated); n > 0 {
			detail += fmt.Sprintf(", %d deprecated (kept, not deleted)", n)
		}
		line("permissions", detail)
	} else {
		line("permissions", "not declared — left alone")
	}
	if ro := r.Roles; ro != nil {
		detail := fmt.Sprintf("%d applied", ro.Applied)
		if n := len(ro.Deprecated); n > 0 {
			detail += fmt.Sprintf(", %d retired (existing grants keep working)", n)
		}
		line("roles", detail)
	} else {
		line("roles", "not declared — left alone")
	}
	if rt := r.Routes; rt != nil {
		line("routes", fmt.Sprintf("table replaced, now %d rules", rt.Replaced))
	} else {
		line("routes", "not declared — left alone")
	}
	return b.String()
}

// ---- applying -------------------------------------------------------------

// ApplyManifest reconciles an application's catalog to the document.
//
// Run [Client.DryRunManifest] first and read the report. An apply is not
// reversible by re-applying the previous document: deprecating a permission
// and re-adding it are both forward moves, and a retired role stays retired
// for anybody granted it in between.
func (c *Client) ApplyManifest(ctx context.Context, applicationSlug string, m Manifest) (*ManifestReport, error) {
	return c.applyManifest(ctx, applicationSlug, m, false)
}

// DryRunManifest reports what applying the document would do, and writes
// nothing. The server runs the whole apply inside a transaction it then rolls
// back, so the report is the real one, including what would have been retired.
func (c *Client) DryRunManifest(ctx context.Context, applicationSlug string, m Manifest) (*ManifestReport, error) {
	return c.applyManifest(ctx, applicationSlug, m, true)
}

func (c *Client) applyManifest(ctx context.Context, applicationSlug string, m Manifest, dry bool) (*ManifestReport, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	doc, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("anubis/admin: encoding manifest: %w", err)
	}
	return c.ApplyManifestDocument(ctx, applicationSlug, doc, "json", dry)
}

// ApplyManifestDocument applies a document you already have — a JSON file in a
// repository, or a CSV somebody exported from a spreadsheet.
//
// Format is "json" or "csv"; empty means json. A CSV carries ONE section per
// file, decided by its header: a permission sheet or a role sheet. Routes are
// JSON only, because a route's ordering and scope bindings do not survive being
// flattened into cells.
//
// This does not validate locally — it cannot, since the document is opaque
// here — so the server's error is what you get. Prefer [Client.ApplyManifest]
// when you are building the document in Go.
func (c *Client) ApplyManifestDocument(ctx context.Context, applicationSlug string, document []byte, format string, dry bool) (*ManifestReport, error) {
	if applicationSlug == "" {
		return nil, fmt.Errorf("anubis/admin: a manifest applies to one application; name it")
	}
	req := map[string]any{
		"application_slug": applicationSlug,
		"manifest_json":    string(document),
		"dry":              dry,
		"format":           format,
	}
	var out struct {
		ReportJSON string `json:"reportJson"`
		Version    int    `json:"manifestVersion"`
	}
	if err := c.call(ctx, procApplyManifest, req, &out); err != nil {
		return nil, err
	}
	report := &ManifestReport{Version: out.Version}
	if out.ReportJSON != "" {
		if err := json.Unmarshal([]byte(out.ReportJSON), report); err != nil {
			return nil, fmt.Errorf("anubis/admin: the server's manifest report did not decode: %w", err)
		}
	}
	report.Version = out.Version
	sort.Strings(report.Sections)
	return report, nil
}
