package anubistest

import (
	"encoding/json"
	"net/http"

	anubis "github.com/gsoultan/anubis-sdk"
)

// The administration plane, as a fake.
//
// The one behaviour worth reproducing faithfully is the refusal: Anubis's
// guard turns away every non-platform caller before it looks at a permission,
// and an SDK that only ever meets a happy path will not have handled that.

// GrantRow is a grant to register with AddGrant.
type GrantRow struct {
	ID            string
	Role          anubis.Role
	SelfScoped    bool
	ValidFrom     int64
	ValidUntil    int64
	RevokedAt     int64
	ViaMembership string
	// Scopes maps an axis to the nodes the grant reaches on it. A grant may
	// hold SEVERAL nodes on one axis, which is the whole reason entitlement
	// cannot be expressed as the flat map a token carries.
	Scopes map[anubis.Axis][]string
}

// AddGrant registers a grant against an identity.
func (s *Server) AddGrant(subject anubis.SubjectID, g GrantRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		s.grants = map[anubis.SubjectID][]GrantRow{}
	}
	s.grants[subject] = append(s.grants[subject], g)
}

// AddScopeNode registers a node on an axis, for the picker query.
func (s *Server) AddScopeNode(n ScopeNodeRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scopeNodes = append(s.scopeNodes, n)
}

// ScopeNodeRow is a node to register with AddScopeNode.
type ScopeNodeRow struct {
	ID, Name, ParentID, Status string
	Axis                       anubis.Axis
}

// PlatformKey makes the admin plane behave like the real one: only this
// credential passes, and everything else is refused as a different population
// rather than as a missing permission.
func (s *Server) PlatformKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.platformKey = key
}

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/anubis.v1.AuthzAdminService/ListGrants", s.guarded(s.listGrants))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/SearchGrants", s.guarded(s.searchGrants))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/ListRoles", s.guarded(s.listRoles))
	mux.HandleFunc("/anubis.v1.AuthzAdminService/GetRoleEffective", s.guarded(s.roleEffective))
	mux.HandleFunc("/anubis.v1.IdentityAdminService/GetIdentity", s.guarded(s.getIdentity))
	mux.HandleFunc("/anubis.v1.ScopeAdminService/ListScopeNodes", s.guarded(s.listScopeNodes))
}

// guarded reproduces Guard.Require: a non-platform caller is refused with the
// hint the real server sends, which is what lets a client tell "you are the
// wrong population" from "you are missing a grant".
func (s *Server) guarded(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		want := s.platformKey
		s.mu.Unlock()
		if want != "" && r.Header.Get("Authorization") != "Bearer "+want {
			httpErrorWithDetails(w, http.StatusForbidden, "permission_denied",
				"administration is performed by platform users",
				map[string]string{"hint": "administration is performed by platform users"})
			return
		}
		next(w, r)
	}
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	s.count("ListGrants")
	var req struct {
		IdentityID     string `json:"identity_id"`
		IncludeRevoked bool   `json:"include_revoked"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	rows := s.grants[anubis.SubjectID(req.IdentityID)]
	s.mu.Unlock()

	out := make([]map[string]any, 0, len(rows))
	for _, g := range rows {
		if g.RevokedAt != 0 && !req.IncludeRevoked {
			continue
		}
		out = append(out, grantJSON(req.IdentityID, g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func (s *Server) searchGrants(w http.ResponseWriter, _ *http.Request) {
	s.count("SearchGrants")
	s.mu.Lock()
	defer s.mu.Unlock()
	var grants []map[string]any
	var usernames []string
	for subject, rows := range s.grants {
		for _, g := range rows {
			grants = append(grants, grantJSON(string(subject), g))
			usernames = append(usernames, string(subject))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"grants": grants, "usernames": usernames, "nextPageToken": "",
	})
}

func (s *Server) listRoles(w http.ResponseWriter, _ *http.Request) {
	s.count("ListRoles")
	writeJSON(w, http.StatusOK, map[string]any{"roles": []map[string]any{{
		"id": "rol_1", "name": "clerk", "applicationSlug": "billing",
		"description": "approves invoices", "isSystem": false,
	}}})
}

func (s *Server) roleEffective(w http.ResponseWriter, _ *http.Request) {
	s.count("GetRoleEffective")
	writeJSON(w, http.StatusOK, map[string]any{"permissions": []map[string]any{
		{"key": "billing:invoice:approve"},
		{"key": "billing:invoice:read"},
	}})
}

func (s *Server) getIdentity(w http.ResponseWriter, _ *http.Request) {
	s.count("GetIdentity")
	writeJSON(w, http.StatusOK, map[string]any{"identity": map[string]any{
		"id": "usr_1", "username": "alice", "email": "alice@example.com",
		"realm": "internal", "status": "active", "assuranceLevel": 2,
		// int64 as a JSON string, as protojson renders it.
		"createdAt": "1735689600", "lastLoginAt": "1767225600",
	}})
}

func (s *Server) listScopeNodes(w http.ResponseWriter, r *http.Request) {
	s.count("ListScopeNodes")
	var req struct {
		Axis            string `json:"axis"`
		IncludeArchived bool   `json:"include_archived"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	all := append([]ScopeNodeRow(nil), s.scopeNodes...)
	s.mu.Unlock()

	out := make([]map[string]any, 0, len(all))
	for _, n := range all {
		if string(n.Axis) != req.Axis {
			continue
		}
		if n.Status == "archived" && !req.IncludeArchived {
			continue
		}
		out = append(out, map[string]any{
			"id": n.ID, "axis": string(n.Axis), "name": n.Name,
			"parentId": n.ParentID, "status": n.Status,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

func grantJSON(subject string, g GrantRow) map[string]any {
	scopes := make([]map[string]any, 0)
	for axis, nodes := range g.Scopes {
		for _, node := range nodes {
			scopes = append(scopes, map[string]any{
				"axis": string(axis), "nodeId": node,
				"nodeName": node, "inherit": true,
			})
		}
	}
	return map[string]any{
		"id": g.ID, "identityId": subject, "roleId": "rol_" + g.ID,
		"roleName": string(g.Role), "selfScoped": g.SelfScoped,
		// Every timestamp as a string, as protojson renders int64.
		"validFrom":       itoa64(g.ValidFrom),
		"validUntil":      itoa64(g.ValidUntil),
		"revokedAt":       itoa64(g.RevokedAt),
		"viaMembershipId": g.ViaMembership,
		"scopes":          scopes,
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func httpErrorWithDetails(w http.ResponseWriter, status int, code, message string, details map[string]string) {
	writeJSON(w, status, map[string]any{
		"error": code, "message": message, "request_id": "req_test", "details": details,
	})
}
