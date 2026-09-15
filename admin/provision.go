package admin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Provisioning: standing a tenant up from nothing.
//
// The order matters, because each step names the one before it:
//
//  1. [Client.CreateTenant] — the tenant itself. Its slug is permanent.
//  2. [Client.CreateRealm] — a population. People belong to a realm, and the
//     realm decides their session TTLs, their factors and their retention.
//  3. [Client.CreateApplication] — a relying party. Returns the client secret
//     ONCE if the kind has one.
//  4. [Client.ApplyManifest] — the application's permissions, roles and routes.
//     An application with no manifest has no permissions to grant.
//  5. [Client.CreateAPIKey] — the anb_live_ credential a back end uses. Also
//     returned ONCE.
//
// Three values in that sequence are shown exactly once and are not recoverable:
// an application's client secret, a rotated client secret, and an API key. The
// types that carry them say so; see [NewApplication] and [NewAPIKey].

var (
	// Slugs are what appear in URLs, tokens and hosted page paths.
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)
	// Realm codes are stricter: they must start with a letter and may not
	// contain a hyphen. A slug that is valid is not necessarily a valid code,
	// which is exactly the sort of thing to find out locally.
	codeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,30}$`)
)

func checkSlug(kind, s string) error {
	if slugRe.MatchString(s) {
		return nil
	}
	return fmt.Errorf(
		"anubis/admin: %s slug %q is not valid: 2–63 characters, lower-case letters, digits, underscore or hyphen, starting with a letter or digit",
		kind, s)
}

func checkCode(s string) error {
	if codeRe.MatchString(s) {
		return nil
	}
	return fmt.Errorf(
		"anubis/admin: realm code %q is not valid: 2–31 characters, lower-case letters, digits or underscore, starting with a letter — note a realm code may not contain a hyphen, though a slug may",
		s)
}

// Tenant and application statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusArchived  = "archived"
)

// Application kinds. Only server and service are issued a client secret.
const (
	AppSPA     = "spa"
	AppNative  = "native"
	AppServer  = "server"
	AppService = "service"
)

// Realm kinds.
const (
	RealmInternal = "internal"
	RealmPartner  = "partner"
	RealmPublic   = "public"
	RealmService  = "service"
)

// ---- tenants --------------------------------------------------------------

// Tenant is one customer of the installation.
type Tenant struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	// Status is active, suspended or archived.
	Status    string `json:"status"`
	CreatedAt epoch  `json:"createdAt"`
}

// Created is when the tenant was created.
func (t Tenant) Created() time.Time { return t.CreatedAt.time() }

// IsActive reports whether the tenant may be used at all.
func (t Tenant) IsActive() bool { return t.Status == StatusActive }

// Tenants lists every tenant on the installation.
func (c *Client) Tenants(ctx context.Context) ([]Tenant, error) {
	var out struct {
		Tenants []Tenant `json:"tenants"`
	}
	if err := c.call(ctx, procListTenants, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Tenants, nil
}

// CreateTenant creates a tenant.
//
// The slug is permanent. It appears in URLs, in tokens and in every hosted page
// path, so there is no call that changes it — [Client.RenameTenant] changes
// only the display name.
func (c *Client) CreateTenant(ctx context.Context, slug, name string) (*Tenant, error) {
	if err := checkSlug("tenant", slug); err != nil {
		return nil, err
	}
	var out struct {
		Tenant *Tenant `json:"tenant"`
	}
	req := map[string]any{"slug": slug, "name": name}
	if err := c.call(ctx, procCreateTenant, req, &out); err != nil {
		return nil, err
	}
	if out.Tenant == nil {
		return nil, fmt.Errorf("anubis/admin: the server created no tenant")
	}
	return out.Tenant, nil
}

// RenameTenant changes a tenant's display name.
//
// It is named for what it does. The slug is not editable — it is already in
// URLs, tokens and hosted page paths, and changing it would break links that
// are out in the world.
func (c *Client) RenameTenant(ctx context.Context, id, name string) error {
	if name == "" {
		return fmt.Errorf("anubis/admin: a tenant needs a name")
	}
	var out struct{}
	return c.call(ctx, procUpdateTenant, map[string]any{"id": id, "name": name}, &out)
}

// SetTenantStatus suspends, archives or reactivates a tenant. Use the Status
// constants.
func (c *Client) SetTenantStatus(ctx context.Context, id, status string) error {
	switch status {
	case StatusActive, StatusSuspended, StatusArchived:
	default:
		return fmt.Errorf("anubis/admin: tenant status %q; expected %s, %s or %s",
			status, StatusActive, StatusSuspended, StatusArchived)
	}
	var out struct{}
	return c.call(ctx, procSetTenantStatus, map[string]any{"id": id, "status": status}, &out)
}

// ---- realms ---------------------------------------------------------------

// Realm is a population: who these people are, and the rules their sessions
// follow. An identity belongs to exactly one.
type Realm struct {
	ID string `json:"id"`
	// Code is the stable identifier. Stricter than a slug: letters, digits and
	// underscore only, starting with a letter.
	Code string `json:"code"`
	// Kind is internal, partner, public or service.
	Kind         string `json:"kind"`
	DisplayName  string `json:"displayName"`
	MinAssurance int    `json:"minAssurance"`
	// SelfRegistration lets people create their own identity in this realm.
	SelfRegistration          bool     `json:"selfRegistration"`
	EmailVerificationRequired bool     `json:"emailVerificationRequired"`
	PIIEncryption             bool     `json:"piiEncryption"`
	AllowedFactors            []string `json:"allowedFactors"`
	RequiredFactors           []string `json:"requiredFactors"`
	// SessionTTL, AccessTokenTTL and RefreshTokenTTL are Postgres interval
	// text, not Go durations — "8 hours", "10 minutes", "30 days".
	SessionTTL      string `json:"sessionTtl"`
	AccessTokenTTL  string `json:"accessTokenTtl"`
	RefreshTokenTTL string `json:"refreshTokenTtl"`
	// DefaultRetention is interval text too. Empty means no statutory limit,
	// and it is what populates Identity.RetentionDeadline.
	DefaultRetention   string `json:"defaultRetention"`
	PasswordPolicyJSON string `json:"passwordPolicyJson"`
	// FactorEnrolmentDeadline is a ROLLOUT SWITCH, not a flag. Zero means not
	// in force, which is where every realm starts. Before the date, sign-in
	// works and warns; on and after it, a member who has not enrolled the
	// required factors gets an enrolment challenge instead of a session.
	//
	// Setting it locks people out on a calendar date. Read the server's
	// docs/enrolment-rollout.md first.
	FactorEnrolmentDeadline epoch `json:"factorEnrolmentDeadline"`
}

// EnrolmentDeadline is when required factors start being enforced against
// members who have not enrolled. Zero means not in force.
func (r Realm) EnrolmentDeadline() time.Time { return r.FactorEnrolmentDeadline.time() }

// Realms lists the tenant's populations.
func (c *Client) Realms(ctx context.Context) ([]Realm, error) {
	var out struct {
		Realms []Realm `json:"realms"`
	}
	if err := c.call(ctx, procListRealms, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Realms, nil
}

// CreateRealm creates a population.
func (c *Client) CreateRealm(ctx context.Context, r Realm) (*Realm, error) {
	if err := checkCode(r.Code); err != nil {
		return nil, err
	}
	switch r.Kind {
	case RealmInternal, RealmPartner, RealmPublic, RealmService:
	default:
		return nil, fmt.Errorf("anubis/admin: realm kind %q; expected %s, %s, %s or %s",
			r.Kind, RealmInternal, RealmPartner, RealmPublic, RealmService)
	}
	return c.realmCall(ctx, procCreateRealm, r)
}

// UpdateRealm rewrites a realm, keyed on its id.
//
// Mind [Realm.FactorEnrolmentDeadline]: it is a date that starts refusing
// sign-ins, and a read-modify-write that carries it forward unexamined will set
// it again without anybody deciding to.
func (c *Client) UpdateRealm(ctx context.Context, r Realm) (*Realm, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("anubis/admin: updating a realm needs its id")
	}
	return c.realmCall(ctx, procUpdateRealm, r)
}

func (c *Client) realmCall(ctx context.Context, procedure string, r Realm) (*Realm, error) {
	var out struct {
		Realm *Realm `json:"realm"`
	}
	if err := c.call(ctx, procedure, map[string]any{"realm": r}, &out); err != nil {
		return nil, err
	}
	if out.Realm == nil {
		return nil, fmt.Errorf("anubis/admin: the server returned no realm")
	}
	return out.Realm, nil
}

// ---- applications ---------------------------------------------------------

// Application is a relying party: something that sends people to sign in and
// then asks whether they may act.
type Application struct {
	ID string `json:"id"`
	// Slug is also the client_id, and the aud its tokens carry.
	Slug string `json:"slug"`
	Name string `json:"name"`
	// Kind is spa, native, server or service. Only server and service are
	// issued a client secret.
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	RedirectURIs []string `json:"redirectUris"`
	// BackchannelLogoutURI is where Anubis posts a logout token. An
	// application that does not mount a receiver keeps people signed in after
	// they have signed out everywhere.
	BackchannelLogoutURI string `json:"backchannelLogoutUri"`
	// PostLogoutRedirectURIs is a SEPARATE exact-match allowlist. A login
	// callback is not a place to land after signing out, and an open redirect
	// here is a phishing primitive.
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	TokenFormat            string   `json:"tokenFormat"`
	// AccessTokenTTL and RefreshTokenTTL are Postgres interval text.
	AccessTokenTTL  string `json:"accessTokenTtl"`
	RefreshTokenTTL string `json:"refreshTokenTtl"`
	// ManifestVersion advances every time a manifest is applied.
	ManifestVersion int `json:"manifestVersion"`
}

// NeedsClientSecret reports whether this kind of application is issued one.
func (a Application) NeedsClientSecret() bool {
	return a.Kind == AppServer || a.Kind == AppService
}

// NewApplication is a created application and, for server and service kinds,
// its client secret.
//
// The secret is returned EXACTLY ONCE. Only a hash is stored, so if it is not
// captured here it cannot be recovered — the only remedy is
// [Client.RotateClientSecret], which invalidates whatever the previous secret
// was already configured into.
type NewApplication struct {
	Application Application
	// ClientSecret is empty for kinds that do not get one.
	ClientSecret string
}

// ApplicationQuery filters and pages an application listing.
type ApplicationQuery struct {
	// Query matches a slug or name substring.
	Query string
	// PageSize defaults to 50 server-side and is capped at 200.
	PageSize int
	Page     string
}

// ApplicationPage is one page of applications.
type ApplicationPage struct {
	Applications []Application `json:"applications"`
	NextPage     string        `json:"nextPageToken"`
	// Total is the tenant's whole application count, so a page can say
	// "20 of 138" rather than implying it is everything.
	Total int `json:"total"`
}

// Applications lists one page of the tenant's applications.
//
// The listing is paged. A caller that reads Applications and ignores NextPage
// shows a partial list and gets no error saying so — compare Total against
// what you have, or use [Client.AllApplications].
func (c *Client) Applications(ctx context.Context, q ApplicationQuery) (*ApplicationPage, error) {
	req := map[string]any{
		"query": q.Query, "page_size": q.PageSize, "page_token": q.Page,
	}
	var out ApplicationPage
	if err := c.call(ctx, procListApplications, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// maxApplications bounds AllApplications, as maxScopeNodes bounds its listing.
const maxApplications = 10_000

// AllApplications walks every page of an application listing.
func (c *Client) AllApplications(ctx context.Context, q ApplicationQuery) ([]Application, error) {
	var all []Application
	seen := map[string]bool{}
	for {
		page, err := c.Applications(ctx, q)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Applications...)
		if page.NextPage == "" {
			return all, nil
		}
		if len(all) > maxApplications {
			return nil, fmt.Errorf(
				"anubis/admin: more than %d applications; narrow it with Query, or page it with Applications",
				maxApplications)
		}
		if seen[page.NextPage] {
			return nil, fmt.Errorf("anubis/admin: repeated application page token %q", page.NextPage)
		}
		seen[page.NextPage] = true
		q.Page = page.NextPage
	}
}

// CreateApplication registers a relying party.
//
// Capture [NewApplication.ClientSecret] now if the kind has one. It is shown
// exactly once.
func (c *Client) CreateApplication(ctx context.Context, a Application) (*NewApplication, error) {
	if err := checkSlug("application", a.Slug); err != nil {
		return nil, err
	}
	switch a.Kind {
	case AppSPA, AppNative, AppServer, AppService:
	default:
		return nil, fmt.Errorf("anubis/admin: application kind %q; expected %s, %s, %s or %s",
			a.Kind, AppSPA, AppNative, AppServer, AppService)
	}
	var out struct {
		Application  *Application `json:"application"`
		ClientSecret string       `json:"clientSecret"`
	}
	if err := c.call(ctx, procCreateApplication, map[string]any{"application": a}, &out); err != nil {
		return nil, err
	}
	if out.Application == nil {
		return nil, fmt.Errorf("anubis/admin: the server created no application")
	}
	return &NewApplication{Application: *out.Application, ClientSecret: out.ClientSecret}, nil
}

// UpdateApplication rewrites an application, keyed on its id.
func (c *Client) UpdateApplication(ctx context.Context, a Application) (*Application, error) {
	if a.ID == "" {
		return nil, fmt.Errorf("anubis/admin: updating an application needs its id")
	}
	var out struct {
		Application *Application `json:"application"`
	}
	if err := c.call(ctx, procUpdateApplication, map[string]any{"application": a}, &out); err != nil {
		return nil, err
	}
	if out.Application == nil {
		return nil, fmt.Errorf("anubis/admin: no application %q", a.ID)
	}
	return out.Application, nil
}

// RotateClientSecret issues a new secret and invalidates the old one.
//
// The new secret is returned exactly once. Everything still configured with the
// previous one stops authenticating the moment this returns, so this is a
// deploy, not a maintenance task.
func (c *Client) RotateClientSecret(ctx context.Context, applicationID string) (string, error) {
	var out struct {
		ClientSecret string `json:"clientSecret"`
	}
	req := map[string]any{"application_id": applicationID}
	if err := c.call(ctx, procRotateClientSecret, req, &out); err != nil {
		return "", err
	}
	if out.ClientSecret == "" {
		return "", fmt.Errorf("anubis/admin: the server returned no client secret")
	}
	return out.ClientSecret, nil
}

// ---- api keys -------------------------------------------------------------

// APIKey is a tenant credential, as an operator sees it. The usable key itself
// is not here: only a prefix and a hash are stored.
type APIKey struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Prefix is the public half — enough to recognise a key in a config file
	// without being able to use it.
	Prefix string `json:"prefix"`
	// CreatedBy is the platform user's name, empty if they have since been
	// removed.
	CreatedBy  string `json:"createdBy"`
	CreatedAt  epoch  `json:"createdAt"`
	LastUsedAt epoch  `json:"lastUsedAt"`
	ExpiresAt  epoch  `json:"expiresAt"`
	RevokedAt  epoch  `json:"revokedAt"`
}

// Created is when the key was issued.
func (k APIKey) Created() time.Time { return k.CreatedAt.time() }

// LastUsed is when it last authenticated a request. Zero if never — which is
// the interesting case in an access review.
func (k APIKey) LastUsed() time.Time { return k.LastUsedAt.time() }

// Expires is when it stops working. Zero means it does not expire.
func (k APIKey) Expires() time.Time { return k.ExpiresAt.time() }

// IsLive reports whether the key authenticates anything at a given moment.
func (k APIKey) IsLive(at time.Time) bool {
	if !k.RevokedAt.time().IsZero() && !at.Before(k.RevokedAt.time()) {
		return false
	}
	exp := k.ExpiresAt.time()
	return exp.IsZero() || at.Before(exp)
}

// NewAPIKey is a created key.
//
// Key is the usable credential and is returned EXACTLY ONCE — only the prefix
// and a hash are kept. If it is not captured here, the only remedy is to revoke
// it and issue another.
type NewAPIKey struct {
	ID     string
	Prefix string
	Key    string
}

// APIKeys lists the tenant's keys, revoked ones included: an access review that
// cannot see what was withdrawn is not a review.
func (c *Client) APIKeys(ctx context.Context) ([]APIKey, error) {
	var out struct {
		Keys []APIKey `json:"keys"`
	}
	if err := c.call(ctx, procListAPIKeys, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// CreateAPIKey issues a tenant credential. A zero expiry means it never
// expires, which is worth a deliberate decision rather than a default.
//
// Capture [NewAPIKey.Key] now. It is shown exactly once.
func (c *Client) CreateAPIKey(ctx context.Context, label string, expires time.Time) (*NewAPIKey, error) {
	if label == "" {
		return nil, fmt.Errorf("anubis/admin: an api key needs a label; it is all an access review has to go on")
	}
	var expiresAt int64
	if !expires.IsZero() {
		if expires.Before(time.Now()) {
			return nil, fmt.Errorf("anubis/admin: api key expiry %s is in the past", expires.Format(time.RFC3339))
		}
		expiresAt = expires.Unix()
	}
	var out struct {
		APIKey string `json:"apiKey"`
		Prefix string `json:"prefix"`
		ID     string `json:"id"`
	}
	req := map[string]any{"label": label, "expires_at": expiresAt}
	if err := c.call(ctx, procCreateAPIKey, req, &out); err != nil {
		return nil, err
	}
	if out.APIKey == "" {
		return nil, fmt.Errorf("anubis/admin: the server returned no api key")
	}
	return &NewAPIKey{ID: out.ID, Prefix: out.Prefix, Key: out.APIKey}, nil
}

// RevokeAPIKey withdraws a key. It stays listed, revoked.
func (c *Client) RevokeAPIKey(ctx context.Context, id string) error {
	var out struct{}
	return c.call(ctx, procRevokeAPIKey, map[string]any{"id": id}, &out)
}

// ---- auth pages, the rest of them -----------------------------------------

// CreateAuthPage adds a sign-in or sign-out page.
//
// As with [Client.UpdateAuthPage], a page binds to an application or a realm,
// never both.
func (c *Client) CreateAuthPage(ctx context.Context, p AuthPage) (*AuthPage, error) {
	if p.BoundToApplication() && p.BoundToRealm() {
		return nil, ErrAuthPageBinding
	}
	if p.Kind != "signin" && p.Kind != "signout" {
		return nil, fmt.Errorf("anubis/admin: auth page kind %q; expected signin or signout", p.Kind)
	}
	var out struct {
		Page *AuthPage `json:"page"`
	}
	if err := c.call(ctx, procCreateAuthPage, map[string]any{"page": p}, &out); err != nil {
		return nil, err
	}
	if out.Page == nil {
		return nil, fmt.Errorf("anubis/admin: the server created no auth page")
	}
	return out.Page, nil
}

// DeleteAuthPage removes a page. The population it served falls back through
// slug → application → realm → tenant default.
func (c *Client) DeleteAuthPage(ctx context.Context, id string) error {
	var out struct{}
	return c.call(ctx, procDeleteAuthPage, map[string]any{"id": id}, &out)
}

// SetDefaultAuthPage makes a page the one its population falls back to.
func (c *Client) SetDefaultAuthPage(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("anubis/admin: setting a default auth page needs its id")
	}
	var out struct{}
	return c.call(ctx, procSetDefaultAuthPage, map[string]any{"id": id}, &out)
}
