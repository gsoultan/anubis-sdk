package admin_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/gsoultan/anubis-sdk/admin"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// TestARevokedGrantKeepsWhyItWasGiven guards the v0.5.0 split of a grant's
// reason. Root cause: from Anubis v0.5.0 a revoke writes revoke_reason and
// leaves reason alone, and a Grant without RevokeReason decoded the field into
// nothing, so a review printing Reason against a revoked grant showed why the
// access was given as though it were why it was taken away.
func TestARevokedGrantKeepsWhyItWasGiven(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddGrant("usr_1", anubistest.GrantRow{
		ID: "g1", Role: "billing.clerk", RevokedAt: time.Now().Add(-time.Hour).Unix(),
		Reason: "covering month-end close", RevokeReason: "close finished",
	})

	grants, err := c.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(grants))
	}
	g := grants[0]
	if g.Reason != "covering month-end close" {
		t.Errorf("Reason = %q, want why it was given", g.Reason)
	}
	if g.RevokeReason != "close finished" {
		t.Errorf("RevokeReason = %q, want why it was taken away", g.RevokeReason)
	}
}

// TestAGrantNamesTheAssignmentThatGaveIt guards via_assignment_id. Root cause:
// one person can hold a where-assigned membership at several places, and a
// grant that names only the membership cannot say which place to take away.
func TestAGrantNamesTheAssignmentThatGaveIt(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g1", Role: "marketing.member",
		ViaMembership: "mem_council", ViaAssignment: "asg_company_a"})
	s.AddGrant("usr_1", anubistest.GrantRow{ID: "g2", Role: "marketing.member",
		ViaMembership: "mem_council", ViaAssignment: "asg_company_b"})

	grants, err := c.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range grants {
		got = append(got, g.ViaAssignment)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"asg_company_a", "asg_company_b"}) {
		t.Fatalf("assignments = %v, want one per place", got)
	}
}

// TestAMembershipSaysWhetherItAppliesWhereAssigned guards anchor_axis. Root
// cause: a membership that places each member on a structure gives two members
// different reach, and without AnchorAxis it decoded as one that gives everyone
// the same places.
func TestAMembershipSaysWhetherItAppliesWhereAssigned(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddMembership(anubistest.MembershipRow{ID: "mem_council", Name: "Marketing Council",
		MemberCount: 3, AnchorAxis: "company"})
	s.AddMembership(anubistest.MembershipRow{ID: "mem_staff", Name: "All staff", MemberCount: 40})

	ms, err := c.Memberships(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]admin.Membership{}
	for _, m := range ms {
		byID[m.ID] = m
	}
	council := byID["mem_council"]
	if !council.AppliesWhereAssigned() || council.AnchorAxis != "company" {
		t.Errorf("council = %+v, want it to apply where each member is assigned on company", council)
	}
	if byID["mem_staff"].AppliesWhereAssigned() {
		t.Error("a membership with no anchor gives every member the same places")
	}
}

// TestASearchResultSaysWhichSales guards ScopeNode.Path. Root cause: two
// offices called "Sales" are indistinguishable in a search result unless the
// node carries where it sits, which the server sends from v0.5.0.
func TestASearchResultSaysWhichSales(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-a", Axis: "org", Name: "Company A", Status: "active"})
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-a-jkt", Axis: "org", Name: "Jakarta", ParentID: "org-a", Status: "active"})
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-a-sales", Axis: "org", Name: "Sales", ParentID: "org-a-jkt", Status: "active"})
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-b", Axis: "org", Name: "Company B", Status: "active"})
	s.AddScopeNode(anubistest.ScopeNodeRow{ID: "org-b-sales", Axis: "org", Name: "Sales", ParentID: "org-b", Status: "active"})

	page, err := c.ScopeNodes(context.Background(), admin.ScopeNodeQuery{Axis: "org", Query: "sales"})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string][]string{}
	for _, n := range page.Nodes {
		paths[n.ID] = n.Path
	}
	if got := paths["org-a-sales"]; !slices.Equal(got, []string{"Company A", "Jakarta"}) {
		t.Errorf("org-a-sales path = %v, want [Company A Jakarta]", got)
	}
	if got := paths["org-b-sales"]; !slices.Equal(got, []string{"Company B"}) {
		t.Errorf("org-b-sales path = %v, want [Company B]", got)
	}
}
