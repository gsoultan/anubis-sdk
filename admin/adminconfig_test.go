package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gsoultan/anubis-sdk/admin"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// ---- catalog sources ------------------------------------------------------

func TestCatalogSourceLifecycle(t *testing.T) {
	_, c := start(t, operatorKey)
	ctx := context.Background()

	src, err := c.CreateCatalogSource(ctx, admin.NewCatalogSource{
		ApplicationSlug: "billing",
		Name:            "billing catalog",
		Kind:            "http",
		ConfigJSON:      `{"url":"https://billing.example.com/catalog.json"}`,
		Every:           time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.ApplicationSlug != "billing" {
		t.Fatalf("source = %+v", src)
	}
	// Format defaults to json rather than being sent empty.
	if src.Format != "json" {
		t.Errorf("format = %q, want json", src.Format)
	}
	if src.Every() != time.Hour {
		t.Errorf("Every() = %s, want 1h", src.Every())
	}
	if src.IsManual() {
		t.Error("a scheduled source is not manual")
	}
	// next_run_at is derived server-side; a client that never reads it cannot
	// tell a scheduled source from one the scheduler will never pick up.
	if src.NextRun().IsZero() {
		t.Error("a scheduled source has a next run")
	}

	list, err := c.CatalogSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != src.ID {
		t.Fatalf("sources = %+v", list)
	}
}

// TestUpdateCatalogSourceCannotMoveTheApplication pins the shape of the update
// call. The application is fixed when the source is created, so
// CatalogSourceUpdate has no field for it — and the server ignores one anyway.
// A client that offered the field would let an operator believe they had moved
// a catalog between applications.
func TestUpdateCatalogSourceCannotMoveTheApplication(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddCatalogSource(anubistest.CatalogSourceRow{
		ID: "cat_1", ApplicationSlug: "billing", Name: "old",
		Kind: "http", Format: "json", Status: "active", IntervalSeconds: 3600,
	})

	got, err := c.UpdateCatalogSource(ctx, admin.CatalogSourceUpdate{
		ID: "cat_1", Name: "renamed", Status: "disabled",
		ConfigJSON: `{"url":"https://elsewhere.example.com/catalog.json"}`,
		Every:      0, // back to manual
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "renamed" || got.Status != "disabled" {
		t.Fatalf("update did not apply: %+v", got)
	}
	if got.ApplicationSlug != "billing" {
		t.Errorf("application = %q — it is pinned at creation", got.ApplicationSlug)
	}
	if !got.IsManual() || !got.NextRun().IsZero() {
		t.Errorf("a manual source has no next run: every=%s next=%v", got.Every(), got.NextRun())
	}
}

// TestDryRunDoesNotBecomeTheSourcesLastStatus is the distinction an operator
// screen gets wrong: a dry run reports what it would do and writes nothing, so
// it must not make a broken feed look like it has been fixed, nor a working one
// look untested.
func TestDryRunDoesNotBecomeTheSourcesLastStatus(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddCatalogSource(anubistest.CatalogSourceRow{
		ID: "cat_1", ApplicationSlug: "billing", Kind: "http",
		Format: "json", Status: "active", LastStatus: "failed",
	})

	dry, err := c.RunCatalogSource(ctx, "cat_1", true)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Status != "dry_run" || !dry.Dry {
		t.Fatalf("run = %+v, want a dry run", dry)
	}
	if dry.Applied() {
		t.Error("a dry run applies nothing")
	}

	after, err := c.CatalogSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after[0].LastStatus != "failed" || !after[0].IsBroken() {
		t.Errorf("last status = %q — a dry run must not clear a failure", after[0].LastStatus)
	}

	// A real run does move it.
	live, err := c.RunCatalogSource(ctx, "cat_1", false)
	if err != nil {
		t.Fatal(err)
	}
	if !live.Applied() || live.InFlight() {
		t.Fatalf("run = %+v, want a finished, applied run", live)
	}
	after, err = c.CatalogSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after[0].IsBroken() {
		t.Error("a successful run clears the failure")
	}
}

func TestCatalogRunsAreListedAndDeletingTakesThemWithIt(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddCatalogSource(anubistest.CatalogSourceRow{
		ID: "cat_1", ApplicationSlug: "billing", Kind: "http", Status: "active",
	})
	for i := 0; i < 3; i++ {
		if _, err := c.RunCatalogSource(ctx, "cat_1", false); err != nil {
			t.Fatal(err)
		}
	}

	runs, err := c.CatalogRuns(ctx, "cat_1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("got %d runs, want 3", len(runs))
	}
	if runs[0].Started().IsZero() {
		t.Error("timestamps did not decode — protojson renders int64 as a string")
	}
	if limited, err := c.CatalogRuns(ctx, "cat_1", 2); err != nil || len(limited) != 2 {
		t.Fatalf("limit ignored: %d runs, err %v", len(limited), err)
	}

	if err := c.DeleteCatalogSource(ctx, "cat_1"); err != nil {
		t.Fatal(err)
	}
	// Removing a source takes its run history with it; what it applied
	// survives in the audit log, which is not this surface.
	gone, err := c.CatalogRuns(ctx, "cat_1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 0 {
		t.Errorf("run history outlived its source: %d runs", len(gone))
	}
}

// ---- schedules ------------------------------------------------------------

// TestAScheduleBelowTheFloorIsRefusedWithoutARoundTrip checks the floor is
// enforced here rather than spent on a request. The server refuses it too, but
// "invalid argument" does not tell an operator what the floor is.
func TestAScheduleBelowTheFloorIsRefusedWithoutARoundTrip(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()

	for _, every := range []time.Duration{time.Minute, 299 * time.Second, -time.Hour} {
		if _, err := c.SetSyncSchedule(ctx, "syn_1", every); err == nil {
			t.Errorf("%s was accepted; the floor is %s", every, admin.MinScheduleInterval)
		}
	}
	if _, err := c.CreateCatalogSource(ctx, admin.NewCatalogSource{
		ApplicationSlug: "billing", Kind: "http", Every: time.Minute,
	}); err == nil {
		t.Error("a catalog source below the floor was accepted")
	}

	if n := s.Calls["SetSyncSchedule"] + s.Calls["CreateCatalogSource"]; n != 0 {
		t.Errorf("%d requests were sent for intervals the client could refuse itself", n)
	}
}

func TestSetSyncScheduleChangesOnlyTheSchedule(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	const secret = `{"dsn":"postgres://user:pw@host/db"}`
	s.AddSyncSource(anubistest.SyncSourceRow{
		ID: "syn_1", Axis: "org", Kind: "db_query", Status: "active",
		ConfigJSON: secret, IntervalSeconds: 0,
	})

	got, err := c.SetSyncSchedule(ctx, "syn_1", 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got.Every() != 6*time.Hour {
		t.Fatalf("Every() = %s, want 6h", got.Every())
	}
	if got.NextRun().IsZero() {
		t.Error("next run is derived from the interval and must be set")
	}
	if got.Axis != "org" {
		t.Errorf("axis = %q", got.Axis)
	}
	// This RPC exists apart from UpdateSyncSource precisely so a schedule change
	// cannot blank a credential the client was never sent.
	if got.ConfigJSON != secret {
		t.Errorf("config was rewritten by a schedule change: %q", got.ConfigJSON)
	}

	// Zero is manual, and manual has no next run.
	back, err := c.SetSyncSchedule(ctx, "syn_1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !back.IsManual() || !back.NextRun().IsZero() {
		t.Errorf("zero means manual: every=%s next=%v", back.Every(), back.NextRun())
	}
}

// ---- auth pages -----------------------------------------------------------

func TestAuthPagesListGetAndUpdate(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddAuthPage(anubistest.AuthPageRow{
		ID: "pag_1", Kind: "signin", Slug: "staff", Name: "Staff sign-in",
		Status: "active", RealmCode: "employees", IsDefault: true,
	})
	s.AddAuthPage(anubistest.AuthPageRow{
		ID: "pag_2", Kind: "signout", Slug: "bye", Name: "Goodbye",
		Status: "active", ApplicationSlug: "billing",
	})

	all, err := c.AuthPages(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d pages, want both kinds", len(all))
	}
	signin, err := c.AuthPages(ctx, "signin")
	if err != nil {
		t.Fatal(err)
	}
	if len(signin) != 1 || signin[0].ID != "pag_1" {
		t.Fatalf("kind filter = %+v", signin)
	}

	page, err := c.AuthPage(ctx, "pag_1")
	if err != nil {
		t.Fatal(err)
	}
	// A realm binding is the door a whole population sees.
	if !page.BoundToRealm() || page.BoundToApplication() {
		t.Errorf("page = %+v, want a realm binding only", page)
	}
	if page.Created().IsZero() || page.Updated().IsZero() {
		t.Error("timestamps did not decode")
	}
	if page.URL == "" {
		t.Error("a page says where it is served")
	}

	page.Name = "Employee sign-in"
	updated, err := c.UpdateAuthPage(ctx, *page)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Employee sign-in" {
		t.Fatalf("update did not apply: %+v", updated)
	}
	if !updated.BoundToRealm() {
		t.Error("the binding survived a round trip")
	}
}

// TestAnAuthPageCannotBindToBoth is refused here rather than by the database,
// whose constraint error does not say which of the two bindings was the
// accident.
func TestAnAuthPageCannotBindToBoth(t *testing.T) {
	s, c := start(t, operatorKey)

	_, err := c.UpdateAuthPage(context.Background(), admin.AuthPage{
		ID: "pag_1", Kind: "signin", Slug: "staff",
		ApplicationSlug: "billing", RealmCode: "employees",
	})
	if !errors.Is(err, admin.ErrAuthPageBinding) {
		t.Fatalf("err = %v, want ErrAuthPageBinding", err)
	}
	if n := s.Calls["UpdateAuthPage"]; n != 0 {
		t.Errorf("%d requests sent for a row the database would refuse", n)
	}
}
