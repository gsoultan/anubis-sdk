package anubis_test

import (
	"testing"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
)

func TestPermissionParts(t *testing.T) {
	p := anubis.Permission("billing:invoice:approve")
	if p.App() != "billing" || p.Resource() != "invoice" || p.Action() != "approve" {
		t.Fatalf("parts = %q/%q/%q", p.App(), p.Resource(), p.Action())
	}
	// The naming rule that costs people real time: a manifest declares
	// permissions WITHOUT the application prefix, everything else uses the
	// full key. Both spellings of one permission, derivable from each other.
	if got := p.Manifest(); got != "invoice:approve" {
		t.Errorf("Manifest() = %q, want invoice:approve", got)
	}
	if got := anubis.NewPermission("billing", "invoice", "approve"); got != p {
		t.Errorf("NewPermission round trip = %q", got)
	}
}

func TestPermissionValidity(t *testing.T) {
	for _, bad := range []anubis.Permission{"", "approve", "invoice:approve", "a:b:c:d", "a::c"} {
		if bad.IsValid() {
			t.Errorf("%q was accepted as a permission key", bad)
		}
		// A malformed key must not silently become an empty app or resource,
		// because that reads as "no application" rather than as a mistake.
		if bad.App() != "" && !bad.IsValid() {
			t.Errorf("%q returned an App() despite being malformed", bad)
		}
	}
	if !anubis.Permission("billing:invoice:approve").IsValid() {
		t.Error("a well-formed key was rejected")
	}
}

// TestAuthorizeRejectsAMalformedPermission pins the reason IsValid exists: a
// denial for a permission that cannot exist is indistinguishable from one for
// a permission the caller does not hold, so it is refused before the call.
func TestAuthorizeRejectsAMalformedPermission(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)

	_, err := c.Authorize(signedIn("usr_1", anubis.MethodPassword), "invoice:approve", nil)
	if err == nil {
		t.Fatal("a malformed permission reached the server")
	}
	if s.Calls["Authorize"] != 0 {
		t.Error("spent a decision on a permission key that cannot exist")
	}
}

func TestRolePrefixing(t *testing.T) {
	// Roles come back prefixed with the application slug. Comparing a returned
	// role against the unprefixed manifest name is the mistake this type makes
	// visible.
	r := anubis.Role("billing.clerk")
	if r.App() != "billing" || r.Name() != "clerk" {
		t.Fatalf("app=%q name=%q", r.App(), r.Name())
	}
	if got := anubis.NewRole("billing", "clerk"); got != r {
		t.Errorf("NewRole = %q", got)
	}
	// An unprefixed role is still usable, and reports no application rather
	// than pretending the first segment is one.
	bare := anubis.Role("clerk")
	if bare.App() != "" || bare.Name() != "clerk" {
		t.Errorf("bare role: app=%q name=%q", bare.App(), bare.Name())
	}
}

func TestRolesCollection(t *testing.T) {
	rs := anubis.Roles{"billing.clerk", "billing.approver", "hr.viewer"}
	if !rs.Has("billing.clerk") || rs.Has("clerk") {
		t.Error("Has must compare the full prefixed name")
	}
	if !rs.HasAny("nope.none", "hr.viewer") {
		t.Error("HasAny")
	}
	if got := rs.OfApp("billing"); len(got) != 2 {
		t.Errorf("OfApp(billing) = %v, want 2", got)
	}
	if got := rs.Strings(); len(got) != 3 || got[0] != "billing.clerk" {
		t.Errorf("Strings() = %v", got)
	}
}

func TestScopes(t *testing.T) {
	base := anubis.Scopes{"org": "o1"}
	with := base.With("customer", "c1")

	if len(base) != 1 {
		t.Error("With mutated the receiver; a shared scope set must not change under a caller")
	}
	if node, ok := with.Node("customer"); !ok || node != "c1" {
		t.Errorf("Node(customer) = %q,%v", node, ok)
	}
	// Sorted, so one scope set has one printable form — and so the decision
	// cache does not key the same question many ways.
	if got := with.String(); got != "customer=c1 org=o1" {
		t.Errorf("String() = %q", got)
	}
	merged := with.Merge(anubis.Scopes{"org": "o2", "product": "p1"})
	if merged["org"] != "o2" || merged["product"] != "p1" || merged["customer"] != "c1" {
		t.Errorf("Merge = %v", merged)
	}
	if !(anubis.Scopes{}).IsEmpty() {
		t.Error("IsEmpty")
	}
}

func TestOwnerNamesTheReservedAxis(t *testing.T) {
	// Spelled through the constant so a typo is a compile error rather than a
	// self-scoped grant that silently never matches.
	s := anubis.Owner("usr_applicant")
	if node, ok := s.Node(anubis.AxisOwner); !ok || node != "usr_applicant" {
		t.Fatalf("Owner() = %v", s)
	}
	if anubis.AxisOwner != "_owner" {
		t.Fatalf("AxisOwner = %q, want _owner", anubis.AxisOwner)
	}
}

func TestAuthMethods(t *testing.T) {
	m := anubis.AuthMethods{anubis.MethodPassword, anubis.MethodOTP}
	if !m.Has(anubis.MethodOTP) || m.Has(anubis.MethodDeviceKey) {
		t.Error("Has")
	}
	if !m.HasAll(anubis.MethodPassword, anubis.MethodOTP) {
		t.Error("HasAll with everything present")
	}
	if m.HasAll(anubis.MethodPassword, anubis.MethodDeviceKey) {
		t.Error("HasAll must require every method, not any")
	}
	if got := m.Strings(); len(got) != 2 || got[1] != "otp" {
		t.Errorf("Strings() = %v", got)
	}
}

func TestPermissions(t *testing.T) {
	ps := anubis.Permissions{"billing:invoice:approve", "billing:invoice:read", "hr:person:read"}
	if !ps.Has("billing:invoice:approve") {
		t.Error("Has")
	}
	if !ps.HasAny("nope:a:b", "hr:person:read") {
		t.Error("HasAny")
	}
	if got := ps.OfApp("billing"); len(got) != 2 {
		t.Errorf("OfApp = %v", got)
	}
}

// TestIdentityFromClaims is the answer to "how do I get roles and scopes for
// the caller": one accessor off the verified request, no claim-set spelunking.
func TestIdentityFromClaims(t *testing.T) {
	authTime := time.Now().Add(-40 * time.Minute).Truncate(time.Second)
	claims := &anubis.Claims{
		Subject:  "usr_1",
		Session:  "ses_9",
		Tenant:   "tnt_impack",
		Realm:    "internal",
		Roles:    anubis.Roles{"billing.clerk"},
		Scopes:   anubis.Scopes{"org": "o1", "customer": "c1"},
		AMR:      anubis.AuthMethods{anubis.MethodPassword},
		IAL:      2,
		AuthTime: authTime.Unix(),
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	id := claims.Identity()

	if id.Subject != "usr_1" || id.Session != "ses_9" || id.Tenant != "tnt_impack" {
		t.Fatalf("identity = %+v", id)
	}
	if !id.HasRole("billing.clerk") {
		t.Error("HasRole")
	}
	if node, ok := id.ActiveScope("customer"); !ok || node != "c1" {
		t.Errorf("ActiveScope(customer) = %q,%v", node, ok)
	}
	if !id.AuthenticatedAt().Equal(authTime.UTC()) {
		t.Errorf("AuthenticatedAt() = %v, want %v", id.AuthenticatedAt(), authTime.UTC())
	}
	// The distinction that makes step-up decidable: authentication time is not
	// issue time, because a refresh mints a token with no fresh proof.
	if age := id.AuthAge(); age < 39*time.Minute || age > 41*time.Minute {
		t.Errorf("AuthAge() = %v, want about 40m", age)
	}
	if id.IsApplication() {
		t.Error("a usr_ subject is not an application")
	}
	if got := id.String(); got != "usr_1 [customer=c1 org=o1]" {
		t.Errorf("String() = %q", got)
	}
}

func TestApplicationSubjectIsRecognisable(t *testing.T) {
	// A client-credentials caller has no session and is not a person. Writing
	// one into an "approved by" column is a real mistake worth being able to
	// catch.
	id := (&anubis.Claims{Subject: "app_billing-batch"}).Identity()
	if !id.IsApplication() {
		t.Fatal("app_ subject was not recognised as an application")
	}
}

// TestPrincipalAccessors covers the path a handler actually takes.
func TestPrincipalAccessors(t *testing.T) {
	ctx := signedIn("usr_1", anubis.MethodPassword, anubis.MethodOTP)
	p, ok := anubis.FromContext(ctx)
	if !ok {
		t.Fatal("no principal")
	}
	if p.Subject() != "usr_1" {
		t.Errorf("Subject() = %q", p.Subject())
	}
	if !p.AuthMethods().HasAll(anubis.MethodPassword, anubis.MethodOTP) {
		t.Error("AuthMethods()")
	}
	id, ok := anubis.IdentityFromContext(ctx)
	if !ok || id.Subject != "usr_1" {
		t.Errorf("IdentityFromContext = %+v, %v", id, ok)
	}
	// A nil principal must answer rather than panic: handlers reach for these
	// on paths where the middleware may not have run.
	var nilP *anubis.Principal
	if nilP.Subject() != "" || nilP.Roles() != nil {
		t.Error("a nil principal must return zero values")
	}
}

func TestTokensAndSessionsExposeTimes(t *testing.T) {
	issued := time.Now().Truncate(time.Second)
	tok := anubis.Tokens{AccessToken: "a", RefreshToken: "r", ExpiresIn: 600, IssuedAt: issued}
	if tok.Lifetime() != 10*time.Minute {
		t.Errorf("Lifetime() = %v", tok.Lifetime())
	}
	if !tok.Expiry().Equal(issued.Add(10 * time.Minute)) {
		t.Errorf("Expiry() = %v", tok.Expiry())
	}
	if !tok.HasRefresh() {
		t.Error("HasRefresh")
	}
	if (anubis.Tokens{AccessToken: "a"}).HasRefresh() {
		t.Error("a client-credentials pair has no refresh token")
	}
}

func TestStepUpErrorParsesItsOwnDuration(t *testing.T) {
	e := &anubis.StepUpRequiredError{RequiredAMR: anubis.AuthMethods{anubis.MethodOTP}, MaxAuthAge: "2m"}
	d, ok := e.MaxAuthAgeDuration()
	if !ok || d != 2*time.Minute {
		t.Fatalf("MaxAuthAgeDuration() = %v,%v", d, ok)
	}
	if _, ok := (&anubis.StepUpRequiredError{MaxAuthAge: "nonsense"}).MaxAuthAgeDuration(); ok {
		t.Error("an unparseable age must report itself as such, not as zero")
	}
}
