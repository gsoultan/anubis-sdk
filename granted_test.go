package anubis_test

import (
	"context"
	"errors"
	"testing"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// The question a list screen asks once: where may this person do this? The
// answer is the server's, decoded field for field — a filter built on a
// field that silently decoded to zero would show nothing, or everything.
func TestGrantedNodesDecodesEveryShape(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	ctx := signedIn("usr_1", "pwd")

	s.GrantNodes("usr_1", "training:request:approve", "org", anubis.GrantedNodes{
		OwnRecords: true,
		Nodes: []anubis.GrantedNode{
			{NodeID: "finance", Inherit: true, Except: []anubis.GrantedNode{{NodeID: "surabaya", Inherit: true}}},
			{NodeID: "jkt"},
		},
		AsOfUnix: 1_700_000_000,
	})
	got, err := c.GrantedNodes(ctx, "training:request:approve", "org", anubis.Scopes{"unit": "u-fin"})
	if err != nil {
		t.Fatalf("granted nodes: %v", err)
	}
	if got.Everywhere || !got.OwnRecords || got.Nowhere() || len(got.Nodes) != 2 {
		t.Fatalf("shape lost in transit: %+v", got)
	}
	if got.Nodes[0].NodeID != "finance" || !got.Nodes[0].Inherit ||
		len(got.Nodes[0].Except) != 1 || got.Nodes[0].Except[0].NodeID != "surabaya" {
		t.Fatalf("reach or exceptions lost: %+v", got.Nodes[0])
	}
	if got.AsOf().Unix() != 1_700_000_000 {
		t.Fatalf("as_of lost: %v", got.AsOf())
	}
	// The fixed axes travel with the ask; a grant limited on `unit` reaches
	// a place on `org` only where `unit` is satisfied.
	if ask := s.LastAsk(); ask.Subject != "usr_1" || ask.Scopes["unit"] != "u-fin" {
		t.Fatalf("ask did not carry the subject and fixed scopes: %+v", ask)
	}
	if s.Calls["ListGrantedNodes"] != 1 || s.Calls["Authorize"] != 0 {
		t.Fatalf("one list call, no per-row Authorize: %+v", s.Calls)
	}
}

// Everywhere arrives as "no list", and nowhere as none of the three — the
// two ends a filter must tell apart.
func TestGrantedNodesEverywhereAndNowhere(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	ctx := signedIn("usr_1", "pwd")

	s.GrantNodes("usr_1", "a:b:c", "org", anubis.GrantedNodes{Everywhere: true})
	all, err := c.GrantedNodes(ctx, "a:b:c", "org", nil)
	if err != nil || !all.Everywhere || len(all.Nodes) != 0 || all.Nowhere() {
		t.Fatalf("everywhere: %+v %v", all, err)
	}
	s.GrantNodes("usr_1", "a:b:d", "org", anubis.GrantedNodes{})
	none, err := c.GrantedNodes(ctx, "a:b:d", "org", nil)
	if err != nil || !none.Nowhere() {
		t.Fatalf("nowhere: %+v %v", none, err)
	}
}

// Unknown is a wiring mistake the caller must see, not an empty list it
// would read as "nowhere" and hide every row behind.
func TestGrantedNodesUnknownIsAnErrorNotAnEmptyList(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	_, err := c.GrantedNodesOf(context.Background(), "usr_1", "a:b:c", "org", nil)
	if err == nil {
		t.Fatal("an unknown subject/permission answered with a list")
	}
	var apiErr *anubis.APIError
	if errors.As(err, &apiErr) && apiErr.Code != "not_found" {
		t.Fatalf("want not_found, got %v", err)
	}
	// And the questions the client refuses before a round trip.
	if _, err := c.GrantedNodes(context.Background(), "a:b:c", "org", nil); !errors.Is(err, anubis.ErrNoPrincipal) {
		t.Fatalf("no principal: %v", err)
	}
	for name, bad := range map[string]struct {
		perm anubis.Permission
		axis anubis.Axis
	}{"no axis": {"a:b:c", ""}, "owner axis": {"a:b:c", anubis.AxisOwner}, "bad permission": {"nope", "org"}} {
		if _, err := c.GrantedNodesOf(context.Background(), "usr_1", bad.perm, bad.axis, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s.Calls["ListGrantedNodes"] != 1 {
		t.Fatalf("refused asks still travelled: %+v", s.Calls)
	}
}
