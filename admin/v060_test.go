package admin_test

import (
	"context"
	"testing"

	"github.com/gsoultan/anubis-sdk/admin"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// Anubis v0.6.0 added three fields to messages this package already decodes.
// Each compiled and decoded into nothing: an operator could not see that an
// application admits only role holders, which company a tenant sits inside,
// or how many permissions a role carries.

// An app closed to role holders refuses everyone else at sign-in and refresh,
// so a console that cannot see it cannot say why somebody was refused.
func TestWhoMaySignInIsReadAndSurvivesARename(t *testing.T) {
	_, c := start(t, operatorKey)
	ctx := context.Background()
	if _, err := c.CreateApplication(ctx, admin.Application{
		Slug: "payroll", Name: "Payroll", Kind: admin.AppSPA, SignIn: admin.SignInRoleHolders,
	}); err != nil {
		t.Fatal(err)
	}
	page, err := c.Applications(ctx, admin.ApplicationQuery{})
	if err != nil {
		t.Fatal(err)
	}
	app := page.Applications[0]
	if app.SignIn != admin.SignInRoleHolders || !app.OnlyRoleHolders() {
		t.Fatalf("sign_in = %q", app.SignIn)
	}
	app.Name = "Payroll (new)"
	updated, err := c.UpdateApplication(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	if updated.SignIn != admin.SignInRoleHolders {
		t.Errorf("a rename reopened the app to anyone: %q", updated.SignIn)
	}
}

func TestATenantSaysWhichCompanyItSitsInside(t *testing.T) {
	s, c := start(t, operatorKey)
	s.AddTenant(anubistest.TenantRow{ID: "ten_1", Slug: "group", Name: "Group"})
	s.AddTenant(anubistest.TenantRow{ID: "ten_2", Slug: "impack", Name: "Impack", ParentID: "ten_1"})
	list, err := c.Tenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]admin.Tenant{}
	for _, tn := range list {
		byID[tn.ID] = tn
	}
	if byID["ten_2"].ParentID != "ten_1" || byID["ten_1"].ParentID != "" {
		t.Fatalf("parents = %q, %q", byID["ten_1"].ParentID, byID["ten_2"].ParentID)
	}
}

func TestARoleCarriesItsPermissionCount(t *testing.T) {
	_, c := start(t, operatorKey)
	roles, err := c.Roles(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) == 0 || roles[0].PermissionCount != 2 {
		t.Fatalf("roles = %+v", roles)
	}
}
