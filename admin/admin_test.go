package admin_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/admin"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

const operatorKey = "anb_live_0p3rat0r_s3cr3t"

func start(t *testing.T, key string) (*anubistest.Server, *admin.Client) {
	t.Helper()
	s := anubistest.NewServer(t)
	s.PlatformKey(operatorKey)

	rpc, err := anubis.New(s.URL, anubis.WithAPIKey(key), anubis.WithTenant("impack"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	c, err := admin.New(rpc)
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	return s, c
}

// TestATenantKeyIsRefusedAsAPopulationNotAPermission is the test this package
// exists to make unmissable. An application's credential does not merely lack
// a grant here — no grant exists that would help.
func TestATenantKeyIsRefusedAsAPopulationNotAPermission(t *testing.T) {
	_, c := start(t, "anb_live_tenant00_s3cr3t")

	_, err := c.Grants(context.Background(), "usr_1")
	if !errors.Is(err, admin.ErrNotPlatformOperator) {
		t.Fatalf("err = %v, want ErrNotPlatformOperator", err)
	}
	// And it must not read as an ordinary authorization failure, or a caller
	// will go looking for a permission to grant itself.
	var denied *anubis.DeniedError
	if errors.As(err, &denied) {
		t.Error("the refusal was reported as a policy denial")
	}
}

func TestGrantsCarryScopesRolesAndValidity(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddGrant("usr_1", anubistest.GrantRow{
		ID: "g1", Role: "billing.clerk",
		Scopes: map[anubis.Axis][]string{"org": {"org-north", "org-south"}, "customer": {"cust-acme"}},
	})

	grants, err := c.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(grants))
	}
	g := grants[0]
	if g.Role != "billing.clerk" || g.Subject != "usr_1" {
		t.Fatalf("grant = %+v", g)
	}
	// The shape the integration plane cannot express: two nodes on ONE axis.
	nodes := g.Nodes("org")
	if len(nodes) != 2 {
		t.Fatalf("org nodes = %v, want two — a token can only ever carry one", nodes)
	}
	if !g.IsLive(time.Now()) {
		t.Error("an unbounded, unrevoked grant is live")
	}
}

func TestValidityWindowsAndRevocationAreHonoured(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		row  anubistest.GrantRow
		live bool
	}{
		{"unbounded", anubistest.GrantRow{ID: "a", Role: "billing.clerk"}, true},
		{"revoked", anubistest.GrantRow{ID: "b", Role: "billing.clerk",
			RevokedAt: now.Add(-time.Hour).Unix()}, false},
		{"not yet valid", anubistest.GrantRow{ID: "c", Role: "billing.clerk",
			ValidFrom: now.Add(time.Hour).Unix()}, false},
		{"expired", anubistest.GrantRow{ID: "d", Role: "billing.clerk",
			ValidUntil: now.Add(-time.Hour).Unix()}, false},
		{"inside its window", anubistest.GrantRow{ID: "e", Role: "billing.clerk",
			ValidFrom: now.Add(-time.Hour).Unix(), ValidUntil: now.Add(time.Hour).Unix()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, c := start(t, operatorKey)
			s.AddGrant("usr_1", tc.row)
			grants, err := c.Grants(context.Background(), "usr_1")
			if err != nil {
				t.Fatal(err)
			}
			if len(grants) != 1 {
				t.Fatalf("revoked grants must still be listed for a review, got %d", len(grants))
			}
			if got := grants[0].IsLive(now); got != tc.live {
				t.Errorf("IsLive = %v, want %v — a grant is not a boolean", got, tc.live)
			}
		})
	}
}

// TestEntitlementsAnswerTheScopePickerQuestion is the point of the package:
// which nodes may this person act on, which is what SwitchScope needs and what
// nothing on the integration plane can supply.
func TestEntitlementsAnswerTheScopePickerQuestion(t *testing.T) {
	s, c := start(t, operatorKey)
	now := time.Now()
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g1", Role: "billing.clerk",
		Scopes: map[anubis.Axis][]string{"org": {"org-north"}}})
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g2", Role: "billing.approver",
		Scopes: map[anubis.Axis][]string{"org": {"org-south"}, "customer": {"cust-acme"}}})
	// Two that must not appear: one revoked, one expired.
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g3", Role: "billing.admin",
		RevokedAt: now.Add(-time.Hour).Unix(),
		Scopes:    map[anubis.Axis][]string{"org": {"org-secret"}}})
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g4", Role: "billing.temp",
		ValidUntil: now.Add(-time.Minute).Unix(),
		Scopes:     map[anubis.Axis][]string{"org": {"org-expired"}}})

	ent, err := c.Entitlements(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ent.Grants) != 2 {
		t.Fatalf("got %d live grants, want 2 — dead grants would show access that does not exist", len(ent.Grants))
	}

	orgs := ent.Nodes("org")
	if len(orgs) != 2 {
		t.Fatalf("org nodes = %v, want org-north and org-south", orgs)
	}
	for _, unwanted := range []string{"org-secret", "org-expired"} {
		for _, got := range orgs {
			if got == unwanted {
				t.Errorf("%q came from a grant that is not live", unwanted)
			}
		}
	}

	roles := ent.Roles()
	if len(roles) != 2 || !roles.Has("billing.clerk") || !roles.Has("billing.approver") {
		t.Fatalf("roles = %v", roles.Strings())
	}
	// The vocabulary is shared with the integration SDK, so a role read here
	// compares equal to one read off a token.
	if roles[0].App() != "billing" {
		t.Errorf("roles are the same type the token carries: %q", roles[0])
	}

	if axes := ent.Axes(); len(axes) != 2 || axes[0] != "customer" || axes[1] != "org" {
		t.Errorf("axes = %v, want sorted [customer org]", axes)
	}
	if ent.IsUnscoped() {
		t.Error("every grant here is scoped")
	}
}

func TestUnscopedGrantIsVisible(t *testing.T) {
	s, c := start(t, operatorKey)
	// A grant with no axes at all reaches everything. A tidy-looking empty
	// scope list would otherwise read as "no access".
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g1", Role: "billing.admin"})

	ent, err := c.Entitlements(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if !ent.IsUnscoped() {
		t.Fatal("an unconstrained grant must be visible as such")
	}
	if len(ent.Nodes("org")) != 0 {
		t.Error("an unconstrained grant names no nodes")
	}
}

func TestRolesAndTheirEffectivePermissions(t *testing.T) {
	_, c := start(t, operatorKey)
	roles, err := c.Roles(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 {
		t.Fatalf("got %d roles", len(roles))
	}
	// A role definition carries the bare manifest name; grants and tokens
	// carry the prefixed form. Qualified() converts.
	if roles[0].Name != "clerk" {
		t.Errorf("definition name = %q, want the manifest form", roles[0].Name)
	}
	if got := roles[0].Qualified(); got != "billing.clerk" {
		t.Errorf("Qualified() = %q, want billing.clerk", got)
	}

	// A role retired from the catalog still decides for the grants that name
	// it, so it is listed — but a picker that offers it is offering a dead end.
	if roles[0].Deprecated {
		t.Error("clerk is live")
	}
	if !roles[1].Deprecated {
		t.Error("auditor was retired from the catalog and must say so")
	}

	perms, err := c.RolePermissions(context.Background(), roles[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !perms.Has("billing:invoice:approve") {
		t.Fatalf("permissions = %v", perms.Strings())
	}
	if perms[0].App() != "billing" {
		t.Error("permissions are the same type the integration SDK uses")
	}
}

func TestIdentityDecodesInt64Strings(t *testing.T) {
	_, c := start(t, operatorKey)
	id, err := c.Identity(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "alice" || !id.IsActive() {
		t.Fatalf("identity = %+v", id)
	}
	// protojson renders int64 as a JSON string; a client assuming a number
	// gets a zero time here.
	if id.Created().IsZero() || id.LastLogin().IsZero() {
		t.Fatalf("timestamps did not decode: created=%v last=%v", id.Created(), id.LastLogin())
	}
	// The column has existed since migrations/0008 and nothing read it, so a
	// console could print a dash for every identity and look right.
	if id.RetentionDeadline().IsZero() {
		t.Error("retention deadline did not decode — a realm with a statutory limit has one")
	}
}

func TestScopeNodesHideArchivedUnlessAsked(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-north", Axis: "org", Name: "North", Status: "active"})
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-old", Axis: "org", Name: "Old", Status: "archived"})
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "cust-acme", Axis: "customer", Name: "Acme", Status: "active"})

	live, err := c.AllScopeNodes(context.Background(), admin.ScopeNodeQuery{Axis: "org"})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].ID != "org-north" {
		t.Fatalf("nodes = %+v — an archived node keeps deciding but must not be offered", live)
	}

	all, err := c.AllScopeNodes(context.Background(), admin.ScopeNodeQuery{Axis: "org", Archived: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d nodes with archived included", len(all))
	}
	for _, n := range all {
		if n.ID == "org-old" && !n.IsArchived() {
			t.Error("IsArchived")
		}
	}
}

// TestAllScopeNodesWalksEveryPage is the regression test for a truncated
// picker. ListScopeNodes is paged because a real axis can hold hundreds of
// thousands of nodes; a client that reads the first page and stops renders a
// short list, reports no error, and the user cannot find an org they hold.
func TestAllScopeNodesWalksEveryPage(t *testing.T) {
	s, c := start(t, operatorKey)
	s.ScopeNodePageSize(2)

	const total = 7
	for i := 0; i < total; i++ {
		s.AddScopeNode(anubistest.ScopeNodeRow{
			ID: fmt.Sprintf("org-%d", i), Axis: "org",
			Name: fmt.Sprintf("Org %d", i), Status: "active",
		})
	}

	nodes, err := c.AllScopeNodes(context.Background(), admin.ScopeNodeQuery{Axis: "org"})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != total {
		t.Fatalf("got %d of %d nodes — the axis was silently truncated at a page boundary", len(nodes), total)
	}
	// 7 nodes at 2 per page is 4 requests. One request would mean the client
	// took the first page for the whole answer.
	if got := s.Calls["ListScopeNodes"]; got != 4 {
		t.Errorf("ListScopeNodes called %d times, want 4", got)
	}

	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n.ID] {
			t.Fatalf("node %q returned twice — paging overlapped", n.ID)
		}
		seen[n.ID] = true
	}
}

// TestScopeNodesHandsBackItsPageToken keeps the single-page form usable: a
// caller doing its own paging needs the token, and a caller that ignores it is
// the bug AllScopeNodes exists to prevent.
func TestScopeNodesHandsBackItsPageToken(t *testing.T) {
	s, c := start(t, operatorKey)
	s.ScopeNodePageSize(2)
	for i := 0; i < 3; i++ {
		s.AddScopeNode(anubistest.ScopeNodeRow{
			ID: fmt.Sprintf("org-%d", i), Axis: "org", Name: "Org", Status: "active",
		})
	}

	first, err := c.ScopeNodes(context.Background(), admin.ScopeNodeQuery{Axis: "org"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 2 || first.NextPage == "" {
		t.Fatalf("first page = %d nodes, next = %q; want 2 and a token", len(first.Nodes), first.NextPage)
	}

	second, err := c.ScopeNodes(context.Background(), admin.ScopeNodeQuery{Axis: "org", Page: first.NextPage})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Nodes) != 1 || second.NextPage != "" {
		t.Fatalf("second page = %d nodes, next = %q; want 1 and no token", len(second.Nodes), second.NextPage)
	}
}

func TestSearchGrantsCarriesUsernamesAlongside(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g1", Role: "billing.clerk"})

	page, err := c.SearchGrants(context.Background(), admin.GrantQuery{Query: "clerk"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Grants) != 1 || len(page.Usernames) != 1 {
		t.Fatalf("page = %+v", page)
	}
	// The username rides on the row rather than being resolved per grant,
	// which would be one lookup per line of an access review.
	if page.Usernames[0] != "usr_1" {
		t.Errorf("usernames = %v", page.Usernames)
	}
}
