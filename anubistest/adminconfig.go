package anubistest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
)

// The configuration half of the admin plane: catalog sources, scope sync
// schedules and auth pages.
//
// Three server behaviours are reproduced deliberately, because a client that
// only meets a permissive fake gets them wrong and nothing fails:
//
//   - a catalog source's application is PINNED at creation, so an update
//     leaves it alone;
//   - next_run_at is DERIVED from the interval, so a client that tries to set
//     it is writing to a read-only field;
//   - an auth page bound to both an application and a realm is refused, the
//     way the auth_pages_one_binding constraint refuses the row.

// CatalogSourceRow is a catalog source to register with AddCatalogSource.
type CatalogSourceRow struct {
	ID              string
	ApplicationSlug string
	Name            string
	Kind            string // http
	Format          string // json | csv
	Status          string // active | disabled
	ConfigJSON      string
	IntervalSeconds int
	LastRunAt       int64
	LastStatus      string
}

// SyncSourceRow is a scope sync source to register with AddSyncSource.
type SyncSourceRow struct {
	ID              string
	Axis            anubis.Axis
	Kind            string // http | db_query | db_table
	Status          string
	ConfigJSON      string
	LastRunAt       int64
	IntervalSeconds int
}

// AuthPageRow is an auth page to register with AddAuthPage.
type AuthPageRow struct {
	ID     string
	Kind   string // signin | signout
	Slug   string
	Name   string
	Status string
	// Bind to an application OR a realm, never both.
	ApplicationSlug string
	RealmCode       string
	IsDefault       bool
	ConfigJSON      string
}

// AddCatalogSource registers a configured catalog source.
func (s *Server) AddCatalogSource(row CatalogSourceRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.catalogSources == nil {
		s.catalogSources = map[string]*CatalogSourceRow{}
	}
	r := row
	s.catalogSources[r.ID] = &r
}

// AddSyncSource registers a scope sync source.
func (s *Server) AddSyncSource(row SyncSourceRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syncSources == nil {
		s.syncSources = map[string]*SyncSourceRow{}
	}
	r := row
	s.syncSources[r.ID] = &r
}

// AddAuthPage registers an auth page.
func (s *Server) AddAuthPage(row AuthPageRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authPages == nil {
		s.authPages = map[string]*AuthPageRow{}
	}
	r := row
	s.authPages[r.ID] = &r
}

func (s *Server) adminConfigRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/anubis.v1.ScopeAdminService/SetSyncSchedule", s.guarded(s.setSyncSchedule))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/ListCatalogSources", s.guarded(s.listCatalogSources))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/CreateCatalogSource", s.guarded(s.createCatalogSource))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/UpdateCatalogSource", s.guarded(s.updateCatalogSource))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/DeleteCatalogSource", s.guarded(s.deleteCatalogSource))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/RunCatalogSource", s.guarded(s.runCatalogSource))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/ListCatalogRuns", s.guarded(s.listCatalogRuns))
	mux.HandleFunc("/anubis.v1.TenantAdminService/ListAuthPages", s.guarded(s.listAuthPages))
	mux.HandleFunc("/anubis.v1.TenantAdminService/GetAuthPage", s.guarded(s.getAuthPage))
	mux.HandleFunc("/anubis.v1.TenantAdminService/UpdateAuthPage", s.guarded(s.updateAuthPage))
}

// nextRun derives the read-only next_run_at from an interval, as the scheduler
// does. Zero interval is a manual source the scheduler never picks up.
func nextRun(intervalSeconds int, now time.Time) int64 {
	if intervalSeconds <= 0 {
		return 0
	}
	return now.Add(time.Duration(intervalSeconds) * time.Second).Unix()
}

func catalogSourceJSON(r *CatalogSourceRow) map[string]any {
	return map[string]any{
		"id": r.ID, "applicationSlug": r.ApplicationSlug, "name": r.Name,
		"kind": r.Kind, "format": r.Format, "status": r.Status,
		"configJson":      r.ConfigJSON,
		"intervalSeconds": r.IntervalSeconds,
		"lastRunAt":       itoa64(r.LastRunAt),
		"nextRunAt":       itoa64(nextRun(r.IntervalSeconds, time.Now())),
		"lastStatus":      r.LastStatus,
	}
}

func syncSourceJSON(r *SyncSourceRow) map[string]any {
	return map[string]any{
		"id": r.ID, "axis": string(r.Axis), "kind": r.Kind,
		"status": r.Status, "configJson": r.ConfigJSON,
		"lastRunAt":       itoa64(r.LastRunAt),
		"intervalSeconds": r.IntervalSeconds,
		"nextRunAt":       itoa64(nextRun(r.IntervalSeconds, time.Now())),
	}
}

func authPageJSON(r *AuthPageRow) map[string]any {
	return map[string]any{
		"id": r.ID, "kind": r.Kind, "slug": r.Slug, "name": r.Name,
		"status": r.Status, "isDefault": r.IsDefault,
		"applicationSlug": r.ApplicationSlug,
		"realmCode":       r.RealmCode,
		"configJson":      r.ConfigJSON,
		"createdAt":       "1735689600",
		"updatedAt":       "1767225600",
		"url":             "https://anubis.test/p/impack/" + r.Kind + "/" + r.Slug,
	}
}

func (s *Server) setSyncSchedule(w http.ResponseWriter, r *http.Request) {
	s.count("SetSyncSchedule")
	var req struct {
		SourceID        string `json:"source_id"`
		IntervalSeconds int    `json:"interval_seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.IntervalSeconds != 0 && req.IntervalSeconds < 300 {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"interval_seconds must be 0 or at least 300")
		return
	}

	s.mu.Lock()
	row, ok := s.syncSources[req.SourceID]
	if ok {
		// Only the schedule. A dsn or auth_header in config_json is untouched,
		// which is the reason this RPC exists apart from UpdateSyncSource.
		row.IntervalSeconds = req.IntervalSeconds
	}
	s.mu.Unlock()

	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such sync source")
		return
	}
	s.mu.Lock()
	out := syncSourceJSON(row)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"source": out})
}

func (s *Server) listCatalogSources(w http.ResponseWriter, _ *http.Request) {
	s.count("ListCatalogSources")
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.catalogSources))
	for id := range s.catalogSources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, catalogSourceJSON(s.catalogSources[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": out})
}

func (s *Server) createCatalogSource(w http.ResponseWriter, r *http.Request) {
	s.count("CreateCatalogSource")
	var req struct {
		ApplicationSlug string `json:"application_slug"`
		Name            string `json:"name"`
		Kind            string `json:"kind"`
		Format          string `json:"format"`
		ConfigJSON      string `json:"config_json"`
		IntervalSeconds int    `json:"interval_seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.ApplicationSlug == "" {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"a catalog source belongs to an application")
		return
	}
	if req.IntervalSeconds != 0 && req.IntervalSeconds < 300 {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"interval_seconds must be 0 or at least 300")
		return
	}
	if req.Format == "" {
		req.Format = "json"
	}

	s.mu.Lock()
	if s.catalogSources == nil {
		s.catalogSources = map[string]*CatalogSourceRow{}
	}
	id := s.freshID("cat", func(id string) bool { _, ok := s.catalogSources[id]; return ok })
	row := &CatalogSourceRow{
		ID: id, ApplicationSlug: req.ApplicationSlug,
		Name: req.Name, Kind: req.Kind, Format: req.Format, Status: "active",
		ConfigJSON: req.ConfigJSON, IntervalSeconds: req.IntervalSeconds,
	}
	s.catalogSources[row.ID] = row
	out := catalogSourceJSON(row)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"source": out})
}

func (s *Server) updateCatalogSource(w http.ResponseWriter, r *http.Request) {
	s.count("UpdateCatalogSource")
	var req struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Status          string `json:"status"`
		Format          string `json:"format"`
		ConfigJSON      string `json:"config_json"`
		IntervalSeconds int    `json:"interval_seconds"`
		// Accepted and ignored: the application is pinned at creation. A
		// client that tries to move a source must not appear to succeed.
		ApplicationSlug string `json:"application_slug"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.IntervalSeconds != 0 && req.IntervalSeconds < 300 {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"interval_seconds must be 0 or at least 300")
		return
	}

	s.mu.Lock()
	row, ok := s.catalogSources[req.ID]
	if ok {
		row.Name, row.Status = req.Name, req.Status
		row.ConfigJSON, row.IntervalSeconds = req.ConfigJSON, req.IntervalSeconds
		if req.Format != "" {
			row.Format = req.Format
		}
		// ApplicationSlug deliberately untouched.
	}
	var out map[string]any
	if ok {
		out = catalogSourceJSON(row)
	}
	s.mu.Unlock()

	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such catalog source")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": out})
}

func (s *Server) deleteCatalogSource(w http.ResponseWriter, r *http.Request) {
	s.count("DeleteCatalogSource")
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	_, ok := s.catalogSources[req.ID]
	delete(s.catalogSources, req.ID)
	// Removing a source takes its run history with it.
	delete(s.catalogRuns, req.ID)
	s.mu.Unlock()

	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such catalog source")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) runCatalogSource(w http.ResponseWriter, r *http.Request) {
	s.count("RunCatalogSource")
	var req struct {
		SourceID string `json:"source_id"`
		Dry      bool   `json:"dry"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	src, ok := s.catalogSources[req.SourceID]
	var run map[string]any
	if ok {
		s.seq++
		now := time.Now().Unix()
		status := "ok"
		if req.Dry {
			status = "dry_run"
		}
		run = map[string]any{
			"id": fmt.Sprintf("run_%d", s.seq), "sourceId": req.SourceID,
			"startedAt": itoa64(now), "finishedAt": itoa64(now),
			"dry": req.Dry, "status": status, "actor": "op_1",
			"documentSha": "sha256:deadbeef", "reportJson": `{"permissions":3,"roles":1}`,
			"error": "",
		}
		if s.catalogRuns == nil {
			s.catalogRuns = map[string][]map[string]any{}
		}
		// Most recent first, as the server lists them.
		s.catalogRuns[req.SourceID] = append([]map[string]any{run}, s.catalogRuns[req.SourceID]...)
		// A dry run reports and writes nothing, so it does not become the
		// source's last status.
		if !req.Dry {
			src.LastStatus, src.LastRunAt = status, now
		}
	}
	s.mu.Unlock()

	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such catalog source")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run})
}

func (s *Server) listCatalogRuns(w http.ResponseWriter, r *http.Request) {
	s.count("ListCatalogRuns")
	var req struct {
		SourceID string `json:"source_id"`
		Limit    int    `json:"limit"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	runs := append([]map[string]any(nil), s.catalogRuns[req.SourceID]...)
	s.mu.Unlock()

	if req.Limit > 0 && req.Limit < len(runs) {
		runs = runs[:req.Limit]
	}
	if runs == nil {
		runs = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *Server) listAuthPages(w http.ResponseWriter, r *http.Request) {
	s.count("ListAuthPages")
	var req struct {
		Kind string `json:"kind"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.authPages))
	for id := range s.authPages {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		row := s.authPages[id]
		if req.Kind != "" && row.Kind != req.Kind {
			continue
		}
		out = append(out, authPageJSON(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"pages": out})
}

func (s *Server) getAuthPage(w http.ResponseWriter, r *http.Request) {
	s.count("GetAuthPage")
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	row, ok := s.authPages[req.ID]
	var out map[string]any
	if ok {
		out = authPageJSON(row)
	}
	s.mu.Unlock()

	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such auth page")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"page": out})
}

func (s *Server) updateAuthPage(w http.ResponseWriter, r *http.Request) {
	s.count("UpdateAuthPage")
	var req struct {
		Page struct {
			ID              string `json:"id"`
			Kind            string `json:"kind"`
			Slug            string `json:"slug"`
			Name            string `json:"name"`
			Status          string `json:"status"`
			IsDefault       bool   `json:"isDefault"`
			ApplicationSlug string `json:"applicationSlug"`
			ApplicationID   string `json:"applicationId"`
			RealmCode       string `json:"realmCode"`
			RealmID         string `json:"realmId"`
			ConfigJSON      string `json:"configJson"`
		} `json:"page"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	p := req.Page

	// auth_pages_one_binding. The database refuses the row, and its error does
	// not say which of the two bindings was the accident.
	app := p.ApplicationSlug != "" || p.ApplicationID != ""
	realm := p.RealmCode != "" || p.RealmID != ""
	if app && realm {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"auth_pages_one_binding: a page binds to an application or a realm")
		return
	}

	s.mu.Lock()
	row, ok := s.authPages[p.ID]
	if ok {
		row.Kind, row.Slug, row.Name = p.Kind, p.Slug, p.Name
		row.Status, row.IsDefault = p.Status, p.IsDefault
		row.ApplicationSlug, row.RealmCode = p.ApplicationSlug, p.RealmCode
		row.ConfigJSON = p.ConfigJSON
	}
	var out map[string]any
	if ok {
		out = authPageJSON(row)
	}
	s.mu.Unlock()

	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such auth page")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"page": out})
}
