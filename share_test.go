package anubis_test

import (
	"context"
	"testing"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// The sharing round trip an application makes: open a record to somebody,
// mint the link for them, exchange the link for a record-bound token, and
// end the share — after which the link is dead.
func TestShareLinkOpenAndUnshare(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	ctx := signedIn("usr_1", "pwd")

	_, axis := anubis.RecordTarget("job_requisition", "JR-0142")
	if axis != "job_requisition/JR-0142" {
		t.Fatalf("record target: %q", axis)
	}
	sh, err := c.Share(ctx, anubis.ShareRequest{
		RecordKind: "job_requisition", RecordRef: "JR-0142",
		RecordScopes: anubis.Scopes{"org": "finance"},
		To:           "usr_2", Permissions: []anubis.Permission{"ats:requisition:comment"},
		ValidUntil: time.Now().Add(7 * 24 * time.Hour), Note: "please review",
	})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if sh.ID == "" || sh.ToIdentityID != "usr_2" || len(sh.Permissions) != 1 || sh.RecordRef != "JR-0142" {
		t.Fatalf("share decoded wrong: %+v", sh)
	}
	if sh.ValidUntil().Before(time.Now().Add(6 * 24 * time.Hour)) {
		t.Fatalf("valid_until lost: %v", sh.ValidUntil())
	}

	on, err := c.SharesOnRecord(ctx, "job_requisition", "JR-0142", anubis.Scopes{"org": "finance"})
	if err != nil || len(on) != 1 || on[0].ID != sh.ID {
		t.Fatalf("shares on record: %v %v", on, err)
	}
	mine, err := c.SharedWithMe(ctx)
	if err != nil || len(mine) != 1 {
		t.Fatalf("shared with me: %v %v", mine, err)
	}

	link, err := c.CreateAccessLink(ctx, sh.ID)
	if err != nil || link == "" {
		t.Fatalf("link: %q %v", link, err)
	}
	tokens, err := c.OpenAccessLink(context.Background(), link)
	if err != nil || tokens.AccessToken == "" || tokens.RefreshToken != "" {
		t.Fatalf("open: %+v %v", tokens, err)
	}
	// What came back is a record-bound token: amr link, the record named.
	claims, err := s.Verifier(app).Verify(context.Background(), tokens.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "usr_2" || claims.Scopes["_record"] != "job_requisition/JR-0142" ||
		len(claims.AMR) != 1 || claims.AMR[0] != "link" {
		t.Fatalf("link token claims: %+v", claims)
	}

	if err := c.Unshare(ctx, sh.ID, "done"); err != nil {
		t.Fatalf("unshare: %v", err)
	}
	if _, err := c.OpenAccessLink(context.Background(), link); err == nil {
		t.Fatal("a link outlived its share")
	}
	if s.Calls["Share"] != 1 || s.Calls["OpenAccessLink"] != 2 {
		t.Fatalf("calls: %+v", s.Calls)
	}
}

// The client refuses the shapes the server would refuse, before a trip.
func TestShareRefusesAnUnboundedOrEmptyRequest(t *testing.T) {
	s := anubistest.NewServer(t)
	c := newClient(t, s)
	ctx := signedIn("usr_1", "pwd")
	good := anubis.ShareRequest{RecordKind: "k", RecordRef: "r", To: "usr_2",
		Permissions: []anubis.Permission{"a:b:c"}, ValidUntil: time.Now().Add(time.Hour)}
	for name, mutate := range map[string]func(*anubis.ShareRequest){
		"no record":      func(r *anubis.ShareRequest) { r.RecordRef = "" },
		"nobody":         func(r *anubis.ShareRequest) { r.To = "" },
		"no permissions": func(r *anubis.ShareRequest) { r.Permissions = nil },
		"never ends":     func(r *anubis.ShareRequest) { r.ValidUntil = time.Time{} },
		"bad permission": func(r *anubis.ShareRequest) { r.Permissions = []anubis.Permission{"nope"} },
	} {
		in := good
		mutate(&in)
		if _, err := c.Share(ctx, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s.Calls["Share"] != 0 {
		t.Fatalf("refused shares travelled: %+v", s.Calls)
	}
}
