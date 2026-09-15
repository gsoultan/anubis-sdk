package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/anubis-sdk/admin"
)

// TestAnUndeclaredSectionIsAnAbsentKey is the whole design in one assertion.
// The server detects a section with a pointer, so a key that was never written
// means "leave that part of the catalog alone" and a key written empty means
// "reconcile it to nothing". A client that always emitted all three sections
// would empty a route table the first time anybody changed a role.
func TestAnUndeclaredSectionIsAnAbsentKey(t *testing.T) {
	m := admin.Manifest{}.WithRoles(admin.ManifestRole{Name: "clerk"})

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["roles"]; !ok {
		t.Fatal("the declared section is missing")
	}
	for _, absent := range []string{"permissions", "routes"} {
		if _, ok := doc[absent]; ok {
			t.Errorf("%q was written into a document that never declared it: %s", absent, raw)
		}
	}
	if got := m.Sections(); len(got) != 1 || got[0] != "roles" {
		t.Errorf("Sections() = %v", got)
	}
}

func TestOnlyDeclaredSectionsAreTouched(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.SeedCatalog("billing", []string{"invoice:approve", "invoice:read"}, []string{"clerk"}, 4)

	// A roles-only document. Permissions and routes must survive untouched.
	rep, err := c.ApplyManifest(ctx, "billing", admin.Manifest{}.WithRoles(
		admin.ManifestRole{Name: "clerk", Permissions: []string{"invoice:approve"}},
		admin.ManifestRole{Name: "approver", Permissions: []string{"invoice:approve", "invoice:read"}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Permissions != nil || rep.Routes != nil {
		t.Errorf("a roles-only document reported on sections it never declared: %+v", rep)
	}
	if rep.Roles == nil || rep.Roles.Applied != 2 {
		t.Fatalf("roles report = %+v", rep.Roles)
	}

	cat := s.Catalog("billing")
	if len(cat.Permissions) != 2 {
		t.Errorf("permissions = %v — a roles document must not touch them", cat.Permissions)
	}
	if cat.Routes != 4 {
		t.Errorf("routes = %d — a roles document must not touch the route table", cat.Routes)
	}
}

// TestRolesTheDocumentStopsNamingAreRetiredNotDeleted is the semantic an
// operator most needs to trust: reconciling is not deleting, and somebody who
// already holds a retired role keeps working.
func TestRolesTheDocumentStopsNamingAreRetiredNotDeleted(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.SeedCatalog("billing", []string{"invoice:approve"}, []string{"clerk", "auditor"}, 0)

	rep, err := c.ApplyManifest(ctx, "billing", admin.Manifest{}.WithRoles(
		admin.ManifestRole{Name: "clerk", Permissions: []string{"invoice:approve"}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Roles == nil || len(rep.Roles.Deprecated) != 1 || rep.Roles.Deprecated[0] != "auditor" {
		t.Fatalf("roles report = %+v, want auditor retired", rep.Roles)
	}
	if !rep.Retired() {
		t.Error("Retired() is how a caller notices an apply took something out")
	}
	cat := s.Catalog("billing")
	if len(cat.DeprecatedRole) != 1 || cat.DeprecatedRole[0] != "auditor" {
		t.Errorf("auditor was deleted rather than retired: %+v", cat)
	}
}

// ---- the rails ------------------------------------------------------------

// TestAnEmptyRoutesSectionIsRefused guards the one destructive thing a
// manifest can do. Permissions and roles have a server-side rail; the route
// table does not, so an empty routes section empties it and nothing warns.
func TestAnEmptyRoutesSectionIsRefused(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.SeedCatalog("billing", []string{"invoice:approve"}, nil, 4)

	// The accident: a slice that happened to be empty.
	var none []admin.ManifestRoute
	_, err := c.ApplyManifest(ctx, "billing", admin.Manifest{}.WithRoutes(none...))
	if !errors.Is(err, admin.ErrRouteTableWipe) {
		t.Fatalf("err = %v, want ErrRouteTableWipe", err)
	}
	if n := s.Calls["ApplyManifest"]; n != 0 {
		t.Errorf("%d requests sent for a document that would empty a route table", n)
	}
	if s.Catalog("billing").Routes != 4 {
		t.Error("the route table was touched")
	}

	// Saying it on purpose works, and is the only way to.
	rep, err := c.ApplyManifest(ctx, "billing", admin.Manifest{}.ClearRoutes())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Routes == nil || rep.Routes.Replaced != 0 {
		t.Fatalf("routes report = %+v", rep.Routes)
	}
	if s.Catalog("billing").Routes != 0 {
		t.Error("ClearRoutes did not clear the table")
	}
}

func TestEmptyPermissionsOrRolesSectionIsRefused(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.SeedCatalog("billing", []string{"invoice:approve"}, []string{"clerk"}, 0)

	var noPerms []admin.ManifestPermission
	if _, err := c.ApplyManifest(ctx, "billing", admin.Manifest{}.WithPermissions(noPerms...)); !errors.Is(err, admin.ErrCatalogWipe) {
		t.Errorf("empty permissions: err = %v, want ErrCatalogWipe", err)
	}
	var noRoles []admin.ManifestRole
	if _, err := c.ApplyManifest(ctx, "billing", admin.Manifest{}.WithRoles(noRoles...)); !errors.Is(err, admin.ErrCatalogWipe) {
		t.Errorf("empty roles: err = %v, want ErrCatalogWipe", err)
	}
	if n := s.Calls["ApplyManifest"]; n != 0 {
		t.Errorf("%d requests sent for documents the server refuses anyway", n)
	}
}

func TestAManifestThatDeclaresNothingIsRefused(t *testing.T) {
	s, c := start(t, operatorKey)

	_, err := c.ApplyManifest(context.Background(), "billing", admin.Manifest{})
	if !errors.Is(err, admin.ErrEmptyManifest) {
		t.Fatalf("err = %v, want ErrEmptyManifest", err)
	}
	if n := s.Calls["ApplyManifest"]; n != 0 {
		t.Errorf("%d requests sent for a document that could not change anything", n)
	}
}

// ---- the permission-reference trap ----------------------------------------

// TestTheFullPermissionKeyIsCaughtWithTheFormToUse is the mistake the server
// calls out by name. The obvious guess is the string that appears in tokens and
// in code, and an "invalid argument" against a value that looks right is a long
// afternoon. The message has to say what to write instead.
func TestTheFullPermissionKeyIsCaughtWithTheFormToUse(t *testing.T) {
	s, c := start(t, operatorKey)

	_, err := c.ApplyManifest(context.Background(), "billing", admin.Manifest{}.WithRoles(
		admin.ManifestRole{Name: "clerk", Permissions: []string{"billing:invoice:approve"}},
	))
	if err == nil {
		t.Fatal("the full permission key was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"invoice:approve"`) {
		t.Errorf("the error does not say what to write instead: %s", msg)
	}
	if n := s.Calls["ApplyManifest"]; n != 0 {
		t.Errorf("%d requests sent for a reference the client can check itself", n)
	}

	// The same mistake in a route.
	_, err = c.ApplyManifest(context.Background(), "billing", admin.Manifest{}.WithRoutes(
		admin.ManifestRoute{
			Priority: 1, PathPattern: "/invoices/*", Effect: admin.RouteRequirePermission,
			Permission: "billing:invoice:approve",
		},
	))
	if err == nil || !strings.Contains(err.Error(), `"invoice:approve"`) {
		t.Errorf("route reference: %v", err)
	}
}

func TestManifestValidationCatchesWhatTheServerWould(t *testing.T) {
	cases := []struct {
		name string
		m    admin.Manifest
		want string
	}{
		{"permission without an action",
			admin.Manifest{}.WithPermissions(admin.ManifestPermission{Resource: "invoice"}),
			"resource and an action"},
		{"the same permission twice",
			admin.Manifest{}.WithPermissions(
				admin.ManifestPermission{Resource: "invoice", Action: "approve"},
				admin.ManifestPermission{Resource: "invoice", Action: "approve"}),
			"twice in one document"},
		{"a risk that is not a risk",
			admin.Manifest{}.WithPermissions(
				admin.ManifestPermission{Resource: "invoice", Action: "approve", Risk: "spicy"}),
			"normal, sensitive or critical"},
		{"assurance out of range",
			admin.Manifest{}.WithPermissions(
				admin.ManifestPermission{Resource: "invoice", Action: "approve", MinAssurance: 9}),
			"expected 0 (unset), 1, 2 or 3"},
		{"a role with no name",
			admin.Manifest{}.WithRoles(admin.ManifestRole{Description: "nameless"}),
			"needs a name"},
		{"an effect that is not an effect",
			admin.Manifest{}.WithRoutes(admin.ManifestRoute{
				Priority: 1, PathPattern: "/x", Effect: "maybe"}),
			"expected public"},
		{"require_permission naming none",
			admin.Manifest{}.WithRoutes(admin.ManifestRoute{
				Priority: 1, PathPattern: "/x", Effect: admin.RouteRequirePermission}),
			"names no permission"},
		{"two routes at one priority",
			admin.Manifest{}.WithRoutes(
				admin.ManifestRoute{Priority: 1, PathPattern: "/a", Effect: admin.RoutePublic},
				admin.ManifestRoute{Priority: 1, PathPattern: "/b", Effect: admin.RoutePublic}),
			"shares priority 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if err == nil {
				t.Fatalf("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// ---- dry run --------------------------------------------------------------

// TestADryRunReportsTheRealDiffAndWritesNothing is the call to make first. The
// server runs the whole apply in a transaction it rolls back, so the report
// includes what WOULD have been retired — which is the only cheap way to find
// out a document says something nobody meant.
func TestADryRunReportsTheRealDiffAndWritesNothing(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.SeedCatalog("billing", []string{"invoice:approve", "invoice:void"}, []string{"clerk"}, 2)
	before := s.Catalog("billing")

	rep, err := c.DryRunManifest(ctx, "billing", admin.Manifest{}.WithPermissions(
		admin.ManifestPermission{Resource: "invoice", Action: "approve", Risk: admin.RiskSensitive},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Dry {
		t.Error("the report does not say it was a dry run")
	}
	if rep.Permissions == nil || len(rep.Permissions.Deprecated) != 1 ||
		rep.Permissions.Deprecated[0] != "invoice:void" {
		t.Fatalf("permissions report = %+v, want invoice:void deprecated", rep.Permissions)
	}
	if !rep.Retired() {
		t.Error("Retired() should flag a dry run that would deprecate something")
	}

	after := s.Catalog("billing")
	if len(after.Permissions) != len(before.Permissions) || after.Version != before.Version {
		t.Fatalf("a dry run wrote something: before=%+v after=%+v", before, after)
	}

	// And the summary is meant to be printed.
	out := rep.String()
	for _, want := range []string{"dry run", "deprecated", "not declared — left alone"} {
		if !strings.Contains(out, want) {
			t.Errorf("String() = %q, want it to mention %q", out, want)
		}
	}
}

func TestApplyBumpsTheManifestVersion(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.SeedCatalog("billing", nil, nil, 0)

	m := admin.Manifest{}.WithPermissions(
		admin.ManifestPermission{Resource: "invoice", Action: "approve"})
	first, err := c.ApplyManifest(ctx, "billing", m)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.ApplyManifest(ctx, "billing", m)
	if err != nil {
		t.Fatal(err)
	}
	if second.Version <= first.Version {
		t.Errorf("version did not advance: %d then %d", first.Version, second.Version)
	}
	if strings.Contains(first.String(), "dry run") {
		t.Error("a real apply reported itself as a dry run")
	}
}

// TestApplyManifestDocumentCarriesAFormat covers the escape hatch: a CSV
// somebody exported, or a JSON file checked into a repository.
func TestApplyManifestDocumentCarriesAFormat(t *testing.T) {
	_, c := start(t, operatorKey)
	ctx := context.Background()

	csv := "resource,action,description\ninvoice,approve,Approve an invoice\n"
	rep, err := c.ApplyManifestDocument(ctx, "billing", []byte(csv), "csv", false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Permissions == nil || rep.Permissions.Applied != 1 {
		t.Fatalf("report = %+v", rep)
	}

	if _, err := c.ApplyManifestDocument(ctx, "", []byte("{}"), "json", false); err == nil {
		t.Error("a manifest applies to one application and must name it")
	}
}

// ExampleManifest shows the rule the rest of the design follows from: a
// section you do not set is not written into the document, and the server
// leaves that part of the catalog alone.
func ExampleManifest() {
	// Change this application's roles. Say nothing about its permissions or
	// its route table, so neither is touched.
	m := admin.Manifest{}.WithRoles(
		admin.ManifestRole{Name: "clerk", Permissions: []string{"invoice:approve"}},
	)

	doc, _ := json.Marshal(m)
	fmt.Println(string(doc))
	fmt.Println("sections:", m.Sections())

	// Output:
	// {"roles":[{"name":"clerk","permissions":["invoice:approve"]}]}
	// sections: [roles]
}
