package anubis

import "time"

// Tokens is an issued credential pair.
//
// RefreshToken is single-use: every refresh returns a rotated pair and kills
// the one presented. Store the new pair before discarding the old — see
// TokenSource, which does that for you and is the only safe way to hold these
// in a process serving concurrent requests.
type Tokens struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	TokenType    string    `json:"tokenType"`
	ExpiresIn    int       `json:"expiresIn"`
	SessionID    SessionID `json:"sessionId"`
	IssuedAt     time.Time `json:"-"`
}

// Lifetime is how long the access token is good for.
func (t Tokens) Lifetime() time.Duration { return time.Duration(t.ExpiresIn) * time.Second }

// Expiry is when the access token stops being accepted. Zero if unknown.
func (t Tokens) Expiry() time.Time {
	if t.IssuedAt.IsZero() || t.ExpiresIn == 0 {
		return time.Time{}
	}
	return t.IssuedAt.Add(t.Lifetime())
}

// HasRefresh reports whether this pair can be rotated. A client-credentials
// token cannot: it is re-minted from the application's own secret instead.
func (t Tokens) HasRefresh() bool { return t.RefreshToken != "" }

// httpTokens is the same pair as the browser-facing /v1/token endpoint spells
// it. That handler writes its JSON by hand in snake_case, while the Connect
// procedures answer in protojson's camelCase — so the two need separate
// structs. This is a property of the server, not a choice made here.
type httpTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	SessionID    string `json:"session_id"`
}

func (h httpTokens) tokens(now time.Time) *Tokens {
	return &Tokens{
		AccessToken:  h.AccessToken,
		RefreshToken: h.RefreshToken,
		TokenType:    h.TokenType,
		ExpiresIn:    h.ExpiresIn,
		SessionID:    SessionID(h.SessionID),
		IssuedAt:     now,
	}
}

// MFAChallenge is a sign-in that got as far as the password and stopped.
type MFAChallenge struct {
	Token     string      `json:"mfaToken"`
	Methods   AuthMethods `json:"methods"`
	ExpiresIn int         `json:"expiresIn"`
}

// Expires is how long the challenge is good for.
func (m MFAChallenge) Expires() time.Duration { return time.Duration(m.ExpiresIn) * time.Second }

// Enrolment is what a realm requires that this member has not enrolled.
//
// It arrives in two very different situations, and the difference is whether
// GrantToken is set. Alongside tokens, with no grant token, it is a warning:
// sign-in worked, and will stop working on Deadline. Instead of tokens, with a
// grant token, it is the refusal — and the grant token is the means to comply.
type Enrolment struct {
	Factors    AuthMethods `json:"factors"`
	Deadline   pbInt64     `json:"deadline"`
	GrantToken string      `json:"grantToken"`
}

// DeadlineTime is when enforcement starts, or started.
func (e Enrolment) DeadlineTime() time.Time { return unix(int64(e.Deadline)) }

// IsOverdue reports whether the deadline has already passed — the difference
// between a warning and a refusal.
func (e Enrolment) IsOverdue() bool { return e.GrantToken != "" }

// LoginResult is what a direct sign-in produced.
//
// It is a result rather than a token because LoginResponse is a oneof and
// three of its outcomes are steps rather than failures. Modelling "a second
// factor is required" as an error would be a lie about what happened, and
// would push callers into inspecting error strings to tell a challenge from a
// wrong password.
type LoginResult struct {
	Tokens *Tokens       `json:"tokens"`
	MFA    *MFAChallenge `json:"mfa"`
	// EnrolmentRequired means no session was issued. Use its GrantToken to
	// enrol the factor, then sign in again.
	EnrolmentRequired *Enrolment `json:"enrolmentRequired"`
	// EnrolmentDue rides ALONGSIDE Tokens while the deadline is still ahead.
	// A client that ignores it costs its user access on the deadline with no
	// notice, which is why it is a field and not a log line.
	EnrolmentDue *Enrolment `json:"enrolmentDue"`
}

// NeedsMFA reports whether a second factor is required to finish signing in.
func (r *LoginResult) NeedsMFA() bool { return r != nil && r.MFA != nil }

// Succeeded reports whether the caller now holds a session.
func (r *LoginResult) Succeeded() bool { return r != nil && r.Tokens != nil }

// Credentials are what a first-party native or CLI application signs in with.
//
// Browser applications must not collect these: a password typed anywhere but
// Anubis's own origin is a password your application is now responsible for.
type Credentials struct {
	Tenant   string
	Realm    string // empty means "internal"
	Username string
	Password string
	ClientID string // the application slug the tokens are minted for
	DeviceFP string
}

// Introspection is live token state, straight from Anubis.
//
// Use it only where "valid until expiry" is unacceptable — admin planes,
// irreversible actions. It puts Anubis in your hot path, which offline
// verification exists to avoid.
type Introspection struct {
	Active   bool        `json:"active"`
	Subject  SubjectID   `json:"sub"`
	Session  SessionID   `json:"sid"`
	Tenant   TenantID    `json:"tid"`
	Realm    string      `json:"realm"`
	Roles    Roles       `json:"roles"`
	Scopes   Scopes      `json:"scopes"`
	AMR      AuthMethods `json:"amr"`
	Audience []string    `json:"aud"`
	Expires  pbInt64     `json:"exp"`
	AuthTime pbInt64     `json:"authTime"`
	IAL      int         `json:"ial"`
	Epoch    int         `json:"epoch"`
}

// ExpiresAt is when the token stops being accepted.
func (in Introspection) ExpiresAt() time.Time { return unix(int64(in.Expires)) }

// AuthenticatedAt is when the subject last proved who they were.
func (in Introspection) AuthenticatedAt() time.Time { return unix(int64(in.AuthTime)) }

// Identity is the introspected token as an identity — the same shape a
// verified request carries, so code that takes an Identity works with either.
func (in Introspection) Identity() Identity {
	return Identity{
		Subject:         in.Subject,
		Session:         in.Session,
		Tenant:          in.Tenant,
		Realm:           in.Realm,
		Roles:           in.Roles,
		Scopes:          in.Scopes,
		Methods:         in.AMR,
		Assurance:       in.IAL,
		authenticatedAt: in.AuthenticatedAt(),
		expiresAt:       in.ExpiresAt(),
	}
}

// Me is the signed-in caller's own view of themselves.
//
// The one thing here the token does not carry is Permissions: the EFFECTIVE
// permission keys, expanded from every role held. That set is what a front end
// needs to decide which controls to draw — but drawing a control is not the
// same as being allowed to use it, and the use still goes through Require.
type Me struct {
	IdentityID   SubjectID   `json:"identityId"`
	Tenant       string      `json:"tenant"`
	Realm        string      `json:"realm"`
	Username     string      `json:"username"`
	Email        string      `json:"email"`
	Roles        Roles       `json:"roles"`
	Permissions  Permissions `json:"permissions"`
	ActiveScopes Scopes      `json:"activeScopes"`
	AMR          AuthMethods `json:"amr"`
	IAL          int         `json:"ial"`
	SessionID    SessionID   `json:"sessionId"`
}

// Can reports whether the effective permission set contains one.
//
// A local check against a set that was true when it was fetched. It is the
// right question for "should this button exist"; it is the wrong question for
// "may this action proceed", because it knows nothing about scope.
func (m *Me) Can(p Permission) bool { return m.Permissions.Has(p) }

// HasRole reports whether the caller holds a role.
func (m *Me) HasRole(r Role) bool { return m.Roles.Has(r) }

// Identity renders this view as an Identity, so the same code can read it or a
// verified request's principal.
func (m *Me) Identity() Identity {
	return Identity{
		Subject:   m.IdentityID,
		Session:   m.SessionID,
		Realm:     m.Realm,
		Roles:     m.Roles,
		Scopes:    m.ActiveScopes,
		Methods:   m.AMR,
		Assurance: m.IAL,
	}
}

// Session is one signed-in device.
type Session struct {
	ID         SessionID   `json:"id"`
	CreatedAt  pbInt64     `json:"createdAt"`
	LastSeenAt pbInt64     `json:"lastSeenAt"`
	ExpiresAt  pbInt64     `json:"expiresAt"`
	IP         string      `json:"ip"`
	UserAgent  string      `json:"userAgent"`
	AMR        AuthMethods `json:"amr"`
	Current    bool        `json:"current"`
}

// CreatedTime is when the session began.
func (s Session) CreatedTime() time.Time { return unix(int64(s.CreatedAt)) }

// LastSeenTime is when it was last used.
func (s Session) LastSeenTime() time.Time { return unix(int64(s.LastSeenAt)) }

// ExpiryTime is when it stops being accepted.
func (s Session) ExpiryTime() time.Time { return unix(int64(s.ExpiresAt)) }
