package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/admin"
)

// GrantScope.Exclude was absent from this package while the wire carried it.
// Nothing broke, because no tenant had used a carve-out yet — which is exactly
// why it went unnoticed, and exactly why these tests exist.

func grantsServer(t *testing.T, grants []map[string]any) *admin.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/anubis.v1.AuthzAdminService/ListGrants",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{"grants": grants}); err != nil {
				t.Error(err)
			}
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := anubis.New(srv.URL,
		anubis.WithApplication("probe", ""),
		anubis.WithTenant("impack"),
		anubis.WithPlatformKey("anb_live_testpfx_0123456789abcdefghij"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := admin.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return ac
}

func grantWith(scopes []map[string]any) map[string]any {
	return map[string]any{
		"id": "grant_1", "identityId": "sub_1",
		"roleId": "role_1", "roleName": "hr.reader",
		"scopes": scopes,
	}
}

// TestAnExclusionSurvivesTheDecode is the whole bug.
//
// A consumer reading only Inherit gets a grant WIDER than the one Anubis holds.
// "Everywhere under Jakarta except Surabaya" decodes as "everywhere under
// Jakarta", and the difference is invisible until somebody reads a Surabaya
// record they should not have.
func TestAnExclusionSurvivesTheDecode(t *testing.T) {
	c := grantsServer(t, []map[string]any{grantWith([]map[string]any{
		{"axis": "org", "nodeId": "jakarta", "inherit": true},
		{"axis": "org", "nodeId": "surabaya", "exclude": true},
	})})

	grants, err := c.Grants(context.Background(), "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || len(grants[0].Scopes) != 2 {
		t.Fatalf("grants: %+v", grants)
	}

	var include, exclude *admin.GrantScope
	for i := range grants[0].Scopes {
		s := &grants[0].Scopes[i]
		if s.Exclude {
			exclude = s
		} else {
			include = s
		}
	}
	if include == nil || include.NodeID != "jakarta" || !include.Inherit {
		t.Fatalf("the include did not decode: %+v", grants[0].Scopes)
	}
	if exclude == nil {
		t.Fatal("the EXCLUSION was dropped — this grant now reads as wider than Anubis holds it")
	}
	if exclude.NodeID != "surabaya" {
		t.Fatalf("exclusion names %q, want surabaya", exclude.NodeID)
	}
}

// TestHasExclusionsIsOfferedBecauseTheCheckIsEasyToForget.
//
// The natural loop over Scopes reads Axis and NodeID; an exclusion looks
// exactly like an include to code that does not ask.
func TestHasExclusionsIsOfferedBecauseTheCheckIsEasyToForget(t *testing.T) {
	plain := grantWith([]map[string]any{{"axis": "org", "nodeId": "jakarta", "inherit": true}})
	carved := grantWith([]map[string]any{
		{"axis": "org", "nodeId": "jakarta", "inherit": true},
		{"axis": "org", "nodeId": "surabaya", "exclude": true},
	})

	c := grantsServer(t, []map[string]any{plain})
	got, err := c.Grants(context.Background(), "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].HasExclusions() {
		t.Fatal("a grant with no carve-out reported one")
	}

	c = grantsServer(t, []map[string]any{carved})
	got, err = c.Grants(context.Background(), "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].HasExclusions() {
		t.Fatal("a grant with a carve-out reported none")
	}
}

// TestAnAbsentExcludeIsFalseNotMissing — protojson omits false, so the common
// case arrives with the field absent and must decode as an include.
func TestAnAbsentExcludeIsFalse(t *testing.T) {
	c := grantsServer(t, []map[string]any{grantWith([]map[string]any{
		{"axis": "org", "nodeId": "jakarta", "inherit": true},
	})})

	got, err := c.Grants(context.Background(), "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Scopes[0].Exclude {
		t.Fatal("an absent exclude decoded as true — every include would become a carve-out")
	}
}

// TestEntitlementsCarriesExclusionsThrough. Entitlements filters by liveness
// and must not flatten scopes on the way.
func TestEntitlementsCarriesExclusionsThrough(t *testing.T) {
	c := grantsServer(t, []map[string]any{grantWith([]map[string]any{
		{"axis": "org", "nodeId": "jakarta", "inherit": true},
		{"axis": "org", "nodeId": "surabaya", "exclude": true},
	})})

	ent, err := c.Entitlements(context.Background(), "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ent.Grants) != 1 {
		t.Fatalf("%d live grants", len(ent.Grants))
	}
	if !ent.Grants[0].HasExclusions() {
		t.Fatal("Entitlements flattened the carve-out away")
	}
}
