package anubistest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Provisioning, as a fake: tenants, realms, applications and api keys.
//
// The behaviour worth reproducing exactly is that a secret is returned ONCE.
// CreateApplication and RotateClientSecret hand back a client secret and
// ListApplications never does; CreateApiKey hands back the usable key and
// ListApiKeys only ever shows a prefix. A fake that echoed secrets back in a
// listing would let a client treat them as fetchable, which they are not.

// TenantRow is a tenant to register with AddTenant.
type TenantRow struct {
	ID, Slug, Name, Status string
	CreatedAt              int64
}

// ApplicationRow is an application to register with AddApplication.
type ApplicationRow struct {
	ID, Slug, Name, Kind, Status string
	RedirectURIs                 []string
	ManifestVersion              int
}

// AddTenant registers a tenant.
func (s *Server) AddTenant(row TenantRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tenants == nil {
		s.tenants = map[string]*TenantRow{}
	}
	r := row
	if r.Status == "" {
		r.Status = "active"
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}
	s.tenants[r.ID] = &r
}

// AddApplication registers an application.
func (s *Server) AddApplication(row ApplicationRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applications == nil {
		s.applications = map[string]*ApplicationRow{}
	}
	r := row
	if r.Status == "" {
		r.Status = "active"
	}
	s.applications[r.Slug] = &r
}

// ApplicationPageSize sets how many applications one page returns, so a test
// can prove a client walks them.
func (s *Server) ApplicationPageSize(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 1 {
		n = 1
	}
	s.applicationPage = n
}

type realmRow struct {
	raw map[string]any
}

type apiKeyRow struct {
	id, label, prefix string
	createdAt         int64
	expiresAt         int64
	revokedAt         int64
}

func (s *Server) provisionRoutes(mux *http.ServeMux) {
	t := "/anubis.v1.TenantAdminService/"
	mux.HandleFunc(t+"ListTenants", s.guarded(s.listTenants))
	mux.HandleFunc(t+"CreateTenant", s.guarded(s.createTenant))
	mux.HandleFunc(t+"UpdateTenant", s.guarded(s.updateTenant))
	mux.HandleFunc(t+"SetTenantStatus", s.guarded(s.setTenantStatus))
	mux.HandleFunc(t+"ListRealms", s.guarded(s.listRealms))
	mux.HandleFunc(t+"CreateRealm", s.guarded(s.createRealm))
	mux.HandleFunc(t+"UpdateRealm", s.guarded(s.updateRealm))
	mux.HandleFunc(t+"ListApplications", s.guarded(s.listApplications))
	mux.HandleFunc(t+"CreateApplication", s.guarded(s.createApplication))
	mux.HandleFunc(t+"UpdateApplication", s.guarded(s.updateApplication))
	mux.HandleFunc(t+"RotateClientSecret", s.guarded(s.rotateClientSecret))
	mux.HandleFunc(t+"ListApiKeys", s.guarded(s.listAPIKeys))
	mux.HandleFunc(t+"CreateApiKey", s.guarded(s.createAPIKey))
	mux.HandleFunc(t+"RevokeApiKey", s.guarded(s.revokeAPIKey))
	mux.HandleFunc(t+"CreateAuthPage", s.guarded(s.createAuthPage))
	mux.HandleFunc(t+"DeleteAuthPage", s.guarded(s.deleteAuthPage))
	mux.HandleFunc(t+"SetDefaultAuthPage", s.guarded(s.setDefaultAuthPage))
}

func tenantJSON(r *TenantRow) map[string]any {
	return map[string]any{
		"id": r.ID, "slug": r.Slug, "name": r.Name, "status": r.Status,
		"createdAt": itoa64(r.CreatedAt),
	}
}

// applicationJSON deliberately carries NO client secret. It is returned once,
// by create and by rotate, and is not a field of an application.
func applicationJSON(r *ApplicationRow) map[string]any {
	uris := r.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	return map[string]any{
		"id": r.ID, "slug": r.Slug, "name": r.Name, "kind": r.Kind,
		"status": r.Status, "redirectUris": uris,
		"manifestVersion": r.ManifestVersion,
	}
}

func (s *Server) listTenants(w http.ResponseWriter, _ *http.Request) {
	s.count("ListTenants")
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.tenants))
	for id := range s.tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, tenantJSON(s.tenants[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	s.count("CreateTenant")
	var req struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tenants == nil {
		s.tenants = map[string]*TenantRow{}
	}
	for _, t := range s.tenants {
		if t.Slug == req.Slug {
			httpError(w, http.StatusConflict, "already_exists", "tenant slug is taken")
			return
		}
	}
	id := s.freshID("ten", func(id string) bool { _, ok := s.tenants[id]; return ok })
	row := &TenantRow{
		ID: id, Slug: req.Slug, Name: req.Name,
		Status: "active", CreatedAt: time.Now().Unix(),
	}
	s.tenants[row.ID] = row
	writeJSON(w, http.StatusOK, map[string]any{"tenant": tenantJSON(row)})
}

func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	s.count("UpdateTenant")
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		// Accepted and ignored. The slug is in URLs, tokens and page paths.
		Slug string `json:"slug"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	row, ok := s.tenants[req.ID]
	if ok {
		row.Name = req.Name
	}
	s.mu.Unlock()
	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such tenant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) setTenantStatus(w http.ResponseWriter, r *http.Request) {
	s.count("SetTenantStatus")
	var req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	switch req.Status {
	case "active", "suspended", "archived":
	default:
		httpError(w, http.StatusBadRequest, "invalid_argument", "bad status")
		return
	}
	s.mu.Lock()
	row, ok := s.tenants[req.ID]
	if ok {
		row.Status = req.Status
	}
	s.mu.Unlock()
	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such tenant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) listRealms(w http.ResponseWriter, _ *http.Request) {
	s.count("ListRealms")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.realms))
	codes := make([]string, 0, len(s.realms))
	for code := range s.realms {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		out = append(out, s.realms[code].raw)
	}
	writeJSON(w, http.StatusOK, map[string]any{"realms": out})
}

func (s *Server) createRealm(w http.ResponseWriter, r *http.Request) {
	s.count("CreateRealm")
	s.upsertRealm(w, r, true)
}

func (s *Server) updateRealm(w http.ResponseWriter, r *http.Request) {
	s.count("UpdateRealm")
	s.upsertRealm(w, r, false)
}

func (s *Server) upsertRealm(w http.ResponseWriter, r *http.Request, create bool) {
	var req struct {
		Realm map[string]any `json:"realm"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Realm == nil {
		httpError(w, http.StatusBadRequest, "invalid_argument", "no realm")
		return
	}
	code, _ := req.Realm["code"].(string)
	if code == "" {
		httpError(w, http.StatusBadRequest, "invalid_argument", "realm needs a code")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.realms == nil {
		s.realms = map[string]*realmRow{}
	}
	if create {
		if _, dup := s.realms[code]; dup {
			httpError(w, http.StatusConflict, "already_exists", "realm code is taken")
			return
		}
		s.seq++
		req.Realm["id"] = fmt.Sprintf("rlm_%d", s.seq)
	}
	s.realms[code] = &realmRow{raw: req.Realm}
	writeJSON(w, http.StatusOK, map[string]any{"realm": req.Realm})
}

func (s *Server) listApplications(w http.ResponseWriter, r *http.Request) {
	s.count("ListApplications")
	var req struct {
		Query     string `json:"query"`
		PageSize  int    `json:"page_size"`
		PageToken string `json:"page_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	slugs := make([]string, 0, len(s.applications))
	for slug := range s.applications {
		if req.Query != "" && !strings.Contains(slug, req.Query) &&
			!strings.Contains(s.applications[slug].Name, req.Query) {
			continue
		}
		slugs = append(slugs, slug)
	}
	// Keyset paging: the token is the slug of the last row on the previous
	// page, so the ordering has to be stable.
	sort.Strings(slugs)
	total := len(slugs)

	size := s.applicationPage
	if size < 1 {
		size = 50
	}
	if req.PageSize > 0 && req.PageSize < size {
		size = req.PageSize
	}
	start := 0
	if req.PageToken != "" {
		start = sort.SearchStrings(slugs, req.PageToken)
		// The token names the last row already seen, so resume after it.
		if start < len(slugs) && slugs[start] == req.PageToken {
			start++
		}
	}
	end := start + size
	if end > len(slugs) {
		end = len(slugs)
	}
	out := make([]map[string]any, 0, end-start)
	for _, slug := range slugs[start:end] {
		out = append(out, applicationJSON(s.applications[slug]))
	}
	resp := map[string]any{"applications": out, "total": total}
	if end < len(slugs) {
		resp["nextPageToken"] = slugs[end-1]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	s.count("CreateApplication")
	var req struct {
		Application struct {
			Slug         string   `json:"slug"`
			Name         string   `json:"name"`
			Kind         string   `json:"kind"`
			RedirectURIs []string `json:"redirectUris"`
		} `json:"application"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	a := req.Application

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applications == nil {
		s.applications = map[string]*ApplicationRow{}
	}
	if _, dup := s.applications[a.Slug]; dup {
		httpError(w, http.StatusConflict, "already_exists", "application slug is taken")
		return
	}
	id := s.freshID("app", func(id string) bool {
		for _, r := range s.applications {
			if r.ID == id {
				return true
			}
		}
		return false
	})
	row := &ApplicationRow{
		ID: id, Slug: a.Slug, Name: a.Name,
		Kind: a.Kind, Status: "active", RedirectURIs: a.RedirectURIs,
	}
	s.applications[a.Slug] = row

	resp := map[string]any{"application": applicationJSON(row)}
	// Only these two kinds get one, and this is the only time it exists.
	if a.Kind == "server" || a.Kind == "service" {
		s.seq++
		resp["clientSecret"] = fmt.Sprintf("anb_secret_%d", s.seq)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) updateApplication(w http.ResponseWriter, r *http.Request) {
	s.count("UpdateApplication")
	var req struct {
		Application struct {
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			Status       string   `json:"status"`
			RedirectURIs []string `json:"redirectUris"`
		} `json:"application"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.applications {
		if row.ID != req.Application.ID {
			continue
		}
		row.Name = req.Application.Name
		if req.Application.Status != "" {
			row.Status = req.Application.Status
		}
		row.RedirectURIs = req.Application.RedirectURIs
		writeJSON(w, http.StatusOK, map[string]any{"application": applicationJSON(row)})
		return
	}
	httpError(w, http.StatusNotFound, "not_found", "no such application")
}

func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	s.count("RotateClientSecret")
	var req struct {
		ApplicationID string `json:"application_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.applications {
		if row.ID != req.ApplicationID {
			continue
		}
		if row.Kind != "server" && row.Kind != "service" {
			httpError(w, http.StatusBadRequest, "invalid_argument",
				"this kind of application has no client secret")
			return
		}
		s.seq++
		writeJSON(w, http.StatusOK, map[string]any{
			"clientSecret": fmt.Sprintf("anb_secret_%d", s.seq),
		})
		return
	}
	httpError(w, http.StatusNotFound, "not_found", "no such application")
}

func (s *Server) listAPIKeys(w http.ResponseWriter, _ *http.Request) {
	s.count("ListApiKeys")
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.apiKeys))
	for id := range s.apiKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		k := s.apiKeys[id]
		// Prefix only. The usable key was returned once, at creation.
		out = append(out, map[string]any{
			"id": k.id, "label": k.label, "prefix": k.prefix,
			"createdBy": "op_1",
			"createdAt": itoa64(k.createdAt), "lastUsedAt": itoa64(0),
			"expiresAt": itoa64(k.expiresAt), "revokedAt": itoa64(k.revokedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	s.count("CreateApiKey")
	var req struct {
		Label     string `json:"label"`
		ExpiresAt int64  `json:"expires_at"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Label == "" {
		httpError(w, http.StatusBadRequest, "invalid_argument", "a key needs a label")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.apiKeys == nil {
		s.apiKeys = map[string]*apiKeyRow{}
	}
	id := s.freshID("key", func(id string) bool { _, ok := s.apiKeys[id]; return ok })
	prefix := "anb_live_" + strings.TrimPrefix(id, "key_")
	row := &apiKeyRow{
		id: id, label: req.Label, prefix: prefix,
		createdAt: time.Now().Unix(), expiresAt: req.ExpiresAt,
	}
	s.apiKeys[row.id] = row
	writeJSON(w, http.StatusOK, map[string]any{
		"apiKey": prefix + "_s3cr3t", "prefix": prefix, "id": row.id,
	})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	s.count("RevokeApiKey")
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	row, ok := s.apiKeys[req.ID]
	if ok {
		row.revokedAt = time.Now().Unix()
	}
	s.mu.Unlock()
	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such api key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) createAuthPage(w http.ResponseWriter, r *http.Request) {
	s.count("CreateAuthPage")
	var req struct {
		Page struct {
			Kind            string `json:"kind"`
			Slug            string `json:"slug"`
			Name            string `json:"name"`
			Status          string `json:"status"`
			ApplicationSlug string `json:"applicationSlug"`
			RealmCode       string `json:"realmCode"`
			ConfigJSON      string `json:"configJson"`
		} `json:"page"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	p := req.Page
	if p.ApplicationSlug != "" && p.RealmCode != "" {
		httpError(w, http.StatusBadRequest, "invalid_argument",
			"auth_pages_one_binding: a page binds to an application or a realm")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authPages == nil {
		s.authPages = map[string]*AuthPageRow{}
	}
	id := s.freshID("pag", func(id string) bool { _, ok := s.authPages[id]; return ok })
	row := &AuthPageRow{
		ID: id, Kind: p.Kind, Slug: p.Slug,
		Name: p.Name, Status: p.Status, ApplicationSlug: p.ApplicationSlug,
		RealmCode: p.RealmCode, ConfigJSON: p.ConfigJSON,
	}
	s.authPages[row.ID] = row
	writeJSON(w, http.StatusOK, map[string]any{"page": authPageJSON(row)})
}

func (s *Server) deleteAuthPage(w http.ResponseWriter, r *http.Request) {
	s.count("DeleteAuthPage")
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	_, ok := s.authPages[req.ID]
	delete(s.authPages, req.ID)
	s.mu.Unlock()
	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such auth page")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) setDefaultAuthPage(w http.ResponseWriter, r *http.Request) {
	s.count("SetDefaultAuthPage")
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.authPages[req.ID]
	if !ok {
		httpError(w, http.StatusNotFound, "not_found", "no such auth page")
		return
	}
	// One default per kind: setting this one clears whatever held it.
	for _, p := range s.authPages {
		if p.Kind == target.Kind {
			p.IsDefault = false
		}
	}
	target.IsDefault = true
	writeJSON(w, http.StatusOK, map[string]any{})
}

// freshID returns a prefixed id that nothing already holds. The fake hands out
// sequential ids while tests seed their own, so a plain counter will reissue
// one somebody already registered — and the second row silently replaces the
// first. A real server never does that.
//
// Callers must hold s.mu.
func (s *Server) freshID(prefix string, taken func(string) bool) string {
	for {
		s.seq++
		id := fmt.Sprintf("%s_%d", prefix, s.seq)
		if !taken(id) {
			return id
		}
	}
}
