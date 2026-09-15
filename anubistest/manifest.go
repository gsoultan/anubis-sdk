package anubistest

import (
	"encoding/json"
	"net/http"
	"sort"
)

// ApplyManifest, as a fake.
//
// The behaviour worth reproducing exactly is how a SECTION is detected. The
// server decodes into pointer slices, so a nil pointer is a key that was never
// written — which is the whole difference between "leave my routes alone" and
// "delete my routes". A fake that decoded into plain slices would accept a
// client that always sends all three sections, and that client would empty a
// route table the first time somebody used it.

// ManifestCatalog is an application's installed catalog, for assertions.
type ManifestCatalog struct {
	// Permissions and Roles are live entries, by key. Deprecated ones move to
	// the Deprecated sets rather than disappearing.
	Permissions          []string
	Roles                []string
	DeprecatedPermission []string
	DeprecatedRole       []string
	Routes               int
	Version              int
}

type manifestApp struct {
	permissions    map[string]bool
	roles          map[string]bool
	deprecatedPerm map[string]bool
	deprecatedRole map[string]bool
	routes         int
	version        int
}

// SeedCatalog installs a starting catalog for an application, so a test can
// assert what an apply retires.
func (s *Server) SeedCatalog(applicationSlug string, permissions, roles []string, routes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manifests == nil {
		s.manifests = map[string]*manifestApp{}
	}
	a := &manifestApp{
		permissions: map[string]bool{}, roles: map[string]bool{},
		deprecatedPerm: map[string]bool{}, deprecatedRole: map[string]bool{},
		routes: routes,
	}
	for _, p := range permissions {
		a.permissions[p] = true
	}
	for _, r := range roles {
		a.roles[r] = true
	}
	s.manifests[applicationSlug] = a
}

// Catalog reads an application's installed catalog.
func (s *Server) Catalog(applicationSlug string) ManifestCatalog {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.manifests[applicationSlug]
	if a == nil {
		return ManifestCatalog{}
	}
	return ManifestCatalog{
		Permissions:          keys(a.permissions),
		Roles:                keys(a.roles),
		DeprecatedPermission: keys(a.deprecatedPerm),
		DeprecatedRole:       keys(a.deprecatedRole),
		Routes:               a.routes,
		Version:              a.version,
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) manifestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/anubis.v1.AuthzAdminService/ApplyManifest", s.guarded(s.applyManifest))
}

func (s *Server) applyManifest(w http.ResponseWriter, r *http.Request) {
	s.count("ApplyManifest")
	var req struct {
		ApplicationSlug string `json:"application_slug"`
		ManifestJSON    string `json:"manifest_json"`
		Dry             bool   `json:"dry"`
		Format          string `json:"format"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.Format != "" && req.Format != "json" && req.Format != "csv" {
		httpError(w, http.StatusBadRequest, "invalid_argument", "format must be json or csv")
		return
	}
	if req.Format == "csv" {
		// A CSV carries one section, decided by its header. The fake does not
		// parse spreadsheets; it only proves the format reaches the server.
		writeJSON(w, http.StatusOK, map[string]any{
			"reportJson":      `{"dry":` + boolStr(req.Dry) + `,"sections":["permissions"],"permissions":{"applied":1,"added_or_updated":1,"deprecated":[]}}`,
			"manifestVersion": 1,
		})
		return
	}

	// Pointer slices: a nil pointer is a key that was never written.
	var doc struct {
		Permissions *[]struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"permissions"`
		Roles *[]struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		} `json:"roles"`
		Routes *[]struct {
			Priority   int    `json:"priority"`
			Effect     string `json:"effect"`
			Permission string `json:"permission"`
		} `json:"routes"`
	}
	if err := json.Unmarshal([]byte(req.ManifestJSON), &doc); err != nil {
		httpError(w, http.StatusBadRequest, "invalid_argument", "manifest is not valid JSON")
		return
	}

	var sections []string
	if doc.Permissions != nil {
		sections = append(sections, "permissions")
	}
	if doc.Roles != nil {
		sections = append(sections, "roles")
	}
	if doc.Routes != nil {
		sections = append(sections, "routes")
	}
	if len(sections) == 0 {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"document declares no permissions, roles or routes")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manifests == nil {
		s.manifests = map[string]*manifestApp{}
	}
	app := s.manifests[req.ApplicationSlug]
	if app == nil {
		app = &manifestApp{
			permissions: map[string]bool{}, roles: map[string]bool{},
			deprecatedPerm: map[string]bool{}, deprecatedRole: map[string]bool{},
		}
		s.manifests[req.ApplicationSlug] = app
	}

	report := map[string]any{"dry": req.Dry, "sections": sections}

	// Work on copies so a dry run can produce a real report and write nothing.
	perms := copySet(app.permissions)
	roles := copySet(app.roles)
	routes := app.routes
	deprecatedPerm, deprecatedRole := []string{}, []string{}

	if doc.Permissions != nil {
		// The rail: an empty section on a populated catalog is a broken export,
		// not somebody retiring a catalog one afternoon.
		if len(*doc.Permissions) == 0 && len(perms) > 0 {
			httpError(w, http.StatusBadRequest, "invalid_argument",
				"refusing to deprecate an entire catalog in one apply")
			return
		}
		named := map[string]bool{}
		for _, p := range *doc.Permissions {
			named[p.Resource+":"+p.Action] = true
		}
		for k := range perms {
			if !named[k] {
				deprecatedPerm = append(deprecatedPerm, k)
				delete(perms, k)
			}
		}
		for k := range named {
			perms[k] = true
		}
		sort.Strings(deprecatedPerm)
		report["permissions"] = map[string]any{
			"applied": len(named), "added_or_updated": len(named),
			"deprecated": deprecatedPerm,
		}
	}

	if doc.Roles != nil {
		if len(*doc.Roles) == 0 && len(roles) > 0 {
			httpError(w, http.StatusBadRequest, "invalid_argument",
				"refusing to retire an entire role catalog in one apply")
			return
		}
		named := map[string]bool{}
		for _, r := range *doc.Roles {
			named[r.Name] = true
			// Roles name permissions as resource:action, resolved against what
			// is in the catalog — including what a previous manifest put there.
			for _, ref := range r.Permissions {
				if !perms[ref] {
					httpError(w, http.StatusBadRequest, "invalid_argument",
						"role "+r.Name+" names unknown permission "+ref)
					return
				}
			}
		}
		for k := range roles {
			if !named[k] {
				deprecatedRole = append(deprecatedRole, k)
				delete(roles, k)
			}
		}
		for k := range named {
			roles[k] = true
		}
		sort.Strings(deprecatedRole)
		report["roles"] = map[string]any{
			"applied": len(named), "deprecated": deprecatedRole,
		}
	}

	if doc.Routes != nil {
		// Full replacement, and no rail. An empty section empties the table.
		for _, rt := range *doc.Routes {
			if rt.Effect == "require_permission" && !perms[rt.Permission] {
				httpError(w, http.StatusBadRequest, "invalid_argument",
					"route names unknown permission "+rt.Permission)
				return
			}
		}
		routes = len(*doc.Routes)
		report["routes"] = map[string]any{"replaced": routes}
	}

	version := app.version + 1
	if !req.Dry {
		app.permissions, app.roles, app.routes, app.version = perms, roles, routes, version
		for _, k := range deprecatedPerm {
			app.deprecatedPerm[k] = true
		}
		for _, k := range deprecatedRole {
			app.deprecatedRole[k] = true
		}
	}

	raw, _ := json.Marshal(report)
	writeJSON(w, http.StatusOK, map[string]any{
		"reportJson": string(raw), "manifestVersion": version,
	})
}

func copySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
