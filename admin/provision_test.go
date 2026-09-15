package admin_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/anubis-sdk/admin"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// TestProvisioningATenantEndToEnd walks the order the package documents:
// tenant, realm, application, manifest, key. Each step names the one before it,
// and an application with no manifest has no permissions to grant.
func TestProvisioningATenantEndToEnd(t *testing.T) {
	_, c := start(t, operatorKey)
	ctx := context.Background()

	ten, err := c.CreateTenant(ctx, "impack", "Impack Ltd")
	if err != nil {
		t.Fatal(err)
	}
	if ten.Slug != "impack" || !ten.IsActive() || ten.Created().IsZero() {
		t.Fatalf("tenant = %+v", ten)
	}

	realm, err := c.CreateRealm(ctx, admin.Realm{
		Code: "employees", Kind: admin.RealmInternal, DisplayName: "Employees",
		SessionTTL: "8 hours", AccessTokenTTL: "10 minutes",
		RequiredFactors: []string{"otp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if realm.ID == "" || realm.Code != "employees" {
		t.Fatalf("realm = %+v", realm)
	}
	// Nothing was asked for, so nobody is locked out on a date.
	if !realm.EnrolmentDeadline().IsZero() {
		t.Error("a new realm must not have factor enrolment in force")
	}

	app, err := c.CreateApplication(ctx, admin.Application{
		Slug: "billing-api", Name: "Billing API", Kind: admin.AppService,
	})
	if err != nil {
		t.Fatal(err)
	}
	if app.ClientSecret == "" {
		t.Fatal("a service application is issued a client secret")
	}
	if !app.Application.NeedsClientSecret() {
		t.Error("NeedsClientSecret disagrees with what the server did")
	}

	if _, err := c.ApplyManifest(ctx, "billing-api", admin.Manifest{}.WithPermissions(
		admin.ManifestPermission{Resource: "invoice", Action: "approve"},
	)); err != nil {
		t.Fatal(err)
	}

	key, err := c.CreateAPIKey(ctx, "billing-api back end", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if key.Key == "" || !strings.HasPrefix(key.Key, key.Prefix) {
		t.Fatalf("key = %+v", key)
	}
}

// TestASecretIsReturnedOnceAndIsNotAField is the property the types are shaped
// around. A client secret and an api key come back from the call that creates
// them and from nowhere else — so a caller that discards the response has lost
// the value, and no later read recovers it.
func TestASecretIsReturnedOnceAndIsNotAField(t *testing.T) {
	_, c := start(t, operatorKey)
	ctx := context.Background()

	made, err := c.CreateApplication(ctx, admin.Application{
		Slug: "billing-api", Name: "Billing API", Kind: admin.AppServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	secret := made.ClientSecret
	if secret == "" {
		t.Fatal("no secret was issued")
	}

	// Listing applications must not hand it back.
	page, err := c.Applications(ctx, admin.ApplicationQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Applications) != 1 {
		t.Fatalf("applications = %+v", page.Applications)
	}
	// There is no field to carry it, which is the point — assert the value is
	// nowhere in the rendered application either.
	if strings.Contains(fmt.Sprintf("%+v", page.Applications[0]), secret) {
		t.Error("a listing returned the client secret")
	}

	// Rotating issues a different one, and invalidates whatever was deployed.
	rotated, err := c.RotateClientSecret(ctx, made.Application.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == secret {
		t.Error("rotation returned the same secret")
	}

	// An api key behaves the same way: the listing shows a prefix only.
	key, err := c.CreateAPIKey(ctx, "back end", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.APIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %+v", keys)
	}
	if keys[0].Prefix != key.Prefix {
		t.Errorf("prefix = %q, want %q", keys[0].Prefix, key.Prefix)
	}
	if strings.Contains(fmt.Sprintf("%+v", keys[0]), key.Key) {
		t.Error("a listing returned the usable api key")
	}
}

// TestOnlySomeKindsGetAClientSecret keeps NeedsClientSecret honest: a browser
// application cannot hold one, so asking for a rotation is a mistake worth a
// clear answer.
func TestOnlySomeKindsGetAClientSecret(t *testing.T) {
	_, c := start(t, operatorKey)
	ctx := context.Background()

	spa, err := c.CreateApplication(ctx, admin.Application{
		Slug: "billing-web", Name: "Billing", Kind: admin.AppSPA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spa.ClientSecret != "" {
		t.Error("a browser application cannot keep a secret and must not be issued one")
	}
	if spa.Application.NeedsClientSecret() {
		t.Error("NeedsClientSecret")
	}
	if _, err := c.RotateClientSecret(ctx, spa.Application.ID); err == nil {
		t.Error("rotating a secret that cannot exist should fail")
	}
}

// TestApplicationsArePagedAndReportTheTotal is the ScopeNodes lesson applied to
// a second listing: reading page one and stopping shows a partial list with no
// error. Total is what lets a caller notice.
func TestApplicationsArePagedAndReportTheTotal(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.ApplicationPageSize(2)
	for i := 0; i < 5; i++ {
		s.AddApplication(anubistest.ApplicationRow{
			ID: fmt.Sprintf("app_%d", i), Slug: fmt.Sprintf("app-%d", i),
			Name: "App", Kind: admin.AppServer,
		})
	}

	first, err := c.Applications(ctx, admin.ApplicationQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Applications) != 2 || first.NextPage == "" {
		t.Fatalf("first page = %d apps, next = %q", len(first.Applications), first.NextPage)
	}
	if first.Total != 5 {
		t.Errorf("Total = %d, want 5 — a page that cannot say how many there are implies it is all of them", first.Total)
	}

	all, err := c.AllApplications(ctx, admin.ApplicationQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("got %d of 5 applications — the listing was truncated at a page boundary", len(all))
	}
	seen := map[string]bool{}
	for _, a := range all {
		if seen[a.Slug] {
			t.Fatalf("%q returned twice — paging overlapped", a.Slug)
		}
		seen[a.Slug] = true
	}
	if n := s.Calls["ListApplications"]; n < 3 {
		t.Errorf("ListApplications called %d times; 5 apps at 2 per page needs more", n)
	}
}

// ---- what is refused locally ----------------------------------------------

func TestSlugAndCodeRulesAreCheckedBeforeSending(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()

	for _, bad := range []string{"", "A", "Impack", "im pack", "-impack", "x"} {
		if _, err := c.CreateTenant(ctx, bad, "x"); err == nil {
			t.Errorf("tenant slug %q was accepted", bad)
		}
	}
	// The difference that actually catches people: a hyphen is fine in a slug
	// and not in a realm code.
	if _, err := c.CreateTenant(ctx, "im-pack", "Impack"); err != nil {
		t.Errorf("a hyphen is legal in a slug: %v", err)
	}
	_, err := c.CreateRealm(ctx, admin.Realm{Code: "em-ployees", Kind: admin.RealmInternal})
	if err == nil {
		t.Fatal("a hyphen is not legal in a realm code")
	}
	if !strings.Contains(err.Error(), "hyphen") {
		t.Errorf("the error should say what the difference is: %v", err)
	}

	if n := s.Calls["CreateRealm"]; n != 0 {
		t.Errorf("%d requests sent for codes the client can check itself", n)
	}
}

func TestInvalidKindsAndStatusesAreRefusedLocally(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()

	if _, err := c.CreateApplication(ctx, admin.Application{Slug: "x-app", Kind: "webapp"}); err == nil {
		t.Error("application kind was not checked")
	}
	if _, err := c.CreateRealm(ctx, admin.Realm{Code: "staff", Kind: "humans"}); err == nil {
		t.Error("realm kind was not checked")
	}
	if err := c.SetTenantStatus(ctx, "ten_1", "paused"); err == nil {
		t.Error("tenant status was not checked")
	}
	if err := c.RenameTenant(ctx, "ten_1", ""); err == nil {
		t.Error("a tenant needs a name")
	}
	if _, err := c.CreateAPIKey(ctx, "", time.Time{}); err == nil {
		t.Error("a key needs a label")
	}
	if _, err := c.CreateAPIKey(ctx, "old", time.Now().Add(-time.Hour)); err == nil {
		t.Error("an expiry in the past was accepted")
	}
	total := s.Calls["CreateApplication"] + s.Calls["CreateRealm"] +
		s.Calls["SetTenantStatus"] + s.Calls["UpdateTenant"] + s.Calls["CreateApiKey"]
	if total != 0 {
		t.Errorf("%d requests sent for values the client rejects itself", total)
	}
}

// TestRenameTenantIsNamedForWhatItDoes guards the one thing an operator might
// expect and not get. A tenant's slug is in URLs, tokens and every hosted page
// path, so there is no call that changes it.
func TestRenameTenantIsNamedForWhatItDoes(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddTenant(anubistest.TenantRow{ID: "ten_1", Slug: "impack", Name: "Impack"})

	if err := c.RenameTenant(ctx, "ten_1", "Impack International"); err != nil {
		t.Fatal(err)
	}
	list, err := c.Tenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("tenants = %+v", list)
	}
	if list[0].Name != "Impack International" {
		t.Errorf("name = %q", list[0].Name)
	}
	if list[0].Slug != "impack" {
		t.Errorf("slug = %q — a rename must not move it", list[0].Slug)
	}
}

func TestTenantStatusAndKeyRevocation(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddTenant(anubistest.TenantRow{ID: "ten_1", Slug: "impack", Name: "Impack"})

	if err := c.SetTenantStatus(ctx, "ten_1", admin.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	list, _ := c.Tenants(ctx)
	if list[0].IsActive() {
		t.Error("a suspended tenant is not active")
	}

	key, err := c.CreateAPIKey(ctx, "temporary", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := c.APIKeys(ctx)
	if !keys[0].IsLive(time.Now()) {
		t.Fatal("a fresh key is live")
	}
	if keys[0].Expires().IsZero() {
		t.Error("the expiry did not decode")
	}
	if !keys[0].LastUsed().IsZero() {
		t.Error("a key that has never authenticated anything has no last use")
	}

	if err := c.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	keys, _ = c.APIKeys(ctx)
	if len(keys) != 1 {
		t.Fatal("a revoked key stays listed — a review that cannot see what was withdrawn is not a review")
	}
	if keys[0].IsLive(time.Now()) {
		t.Error("a revoked key is not live")
	}
}

// ---- auth pages, the rest of them -----------------------------------------

func TestAuthPageCreateDefaultAndDelete(t *testing.T) {
	s, c := start(t, operatorKey)
	ctx := context.Background()
	s.AddAuthPage(anubistest.AuthPageRow{
		ID: "pag_1", Kind: "signin", Slug: "old", Name: "Old",
		Status: "active", RealmCode: "employees", IsDefault: true,
	})

	made, err := c.CreateAuthPage(ctx, admin.AuthPage{
		Kind: "signin", Slug: "staff", Name: "Staff", Status: "active",
		RealmCode: "employees",
	})
	if err != nil {
		t.Fatal(err)
	}
	if made.ID == "" || !made.BoundToRealm() {
		t.Fatalf("page = %+v", made)
	}

	// Binding to both is refused here, as it is on update.
	if _, err := c.CreateAuthPage(ctx, admin.AuthPage{
		Kind: "signin", Slug: "x", ApplicationSlug: "billing", RealmCode: "employees",
	}); err == nil {
		t.Error("a page bound to both an application and a realm was accepted")
	}
	if _, err := c.CreateAuthPage(ctx, admin.AuthPage{Kind: "welcome", Slug: "x"}); err == nil {
		t.Error("an unknown page kind was accepted")
	}

	// One default per kind: setting this one clears the other.
	if err := c.SetDefaultAuthPage(ctx, made.ID); err != nil {
		t.Fatal(err)
	}
	pages, err := c.AuthPages(ctx, "signin")
	if err != nil {
		t.Fatal(err)
	}
	defaults := 0
	for _, p := range pages {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Errorf("%d default signin pages, want exactly 1", defaults)
	}

	if err := c.DeleteAuthPage(ctx, "pag_1"); err != nil {
		t.Fatal(err)
	}
	pages, _ = c.AuthPages(ctx, "")
	if len(pages) != 1 {
		t.Errorf("got %d pages after deleting one", len(pages))
	}
	if err := c.SetDefaultAuthPage(ctx, ""); err == nil {
		t.Error("setting a default needs an id")
	}
}
