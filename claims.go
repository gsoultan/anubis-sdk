package anubis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Claims is the access-token claim set exactly as the token carries it.
//
// The struct mirrors the wire because that is its job — the times are unix
// seconds here because they are unix seconds in the token. Everything derived
// from them is a method, and Identity assembles the whole thing into the view
// most callers actually want.
//
// `scopes` is a map, never fixed fields: adding a scope axis must not change
// the token format.
type Claims struct {
	Issuer    string      `json:"iss"`
	Subject   SubjectID   `json:"sub"`
	Audience  []string    `json:"aud"`
	Expires   int64       `json:"exp"`
	IssuedAt  int64       `json:"iat"`
	NotBefore int64       `json:"nbf"`
	TokenID   string      `json:"jti"`
	Session   SessionID   `json:"sid"`
	Tenant    TenantID    `json:"tid"`
	Roles     Roles       `json:"roles,omitempty"`
	Scope     string      `json:"scp,omitempty"`
	Scopes    Scopes      `json:"scopes,omitempty"`
	Realm     string      `json:"realm,omitempty"`
	IAL       int         `json:"ial,omitempty"`
	AMR       AuthMethods `json:"amr,omitempty"`
	AuthTime  int64       `json:"auth_time,omitempty"`
	Epoch     int         `json:"epoch"`
	Version   int         `json:"ver"`
}

// Identity is the claim set as a caller wants to read it: who this is, what
// they hold, and what they are scoped to right now.
func (c *Claims) Identity() Identity {
	return Identity{
		Subject:         c.Subject,
		Session:         c.Session,
		Tenant:          c.Tenant,
		Realm:           c.Realm,
		Roles:           c.Roles,
		Scopes:          c.Scopes,
		Methods:         c.AMR,
		Assurance:       c.IAL,
		authenticatedAt: c.AuthenticatedAt(),
		expiresAt:       c.ExpiresAt(),
	}
}

// ExpiresAt is when this token stops being accepted.
func (c *Claims) ExpiresAt() time.Time { return unix(c.Expires) }

// IssuedAtTime is when this token was minted.
func (c *Claims) IssuedAtTime() time.Time { return unix(c.IssuedAt) }

// NotBeforeTime is when this token starts being accepted.
func (c *Claims) NotBeforeTime() time.Time { return unix(c.NotBefore) }

// AuthenticatedAt is when the caller last proved who they were.
//
// Not the same as IssuedAtTime: a refresh mints a new token without any fresh
// proof of identity, which is exactly why step-up rules with a maximum age are
// decided against this and not against issuance.
func (c *Claims) AuthenticatedAt() time.Time {
	if c.AuthTime == 0 {
		return time.Time{}
	}
	return unix(c.AuthTime)
}

// HasRole is the cheap local check. It answers "does this token say so", which
// is a different question from "may they do this" — reach for Client.Require
// when the answer has consequences.
func (c *Claims) HasRole(r Role) bool { return c.Roles.Has(r) }

// HasAuthMethod reports whether the caller authenticated with a given method.
func (c *Claims) HasAuthMethod(m AuthMethod) bool { return c.AMR.Has(m) }

// ActiveScope is the node this session is acting as on one axis.
func (c *Claims) ActiveScope(axis Axis) (string, bool) { return c.Scopes.Node(axis) }

// Validate applies the time and identity checks that make a
// cryptographically valid token an *acceptable* one.
func (c *Claims) Validate(now time.Time, issuer, audience string, leeway time.Duration) error {
	n := now.Unix()
	l := int64(leeway / time.Second)
	if c.Expires != 0 && n > c.Expires+l {
		return ErrExpired
	}
	if c.NotBefore != 0 && n < c.NotBefore-l {
		return ErrNotYetValid
	}
	if issuer != "" && c.Issuer != issuer {
		return ErrIssuer
	}
	if audience == "" {
		return ErrNoAudience
	}
	for _, a := range c.Audience {
		if a == audience {
			return nil
		}
	}
	return ErrAudience
}

func parseClaims(message []byte) (*Claims, error) {
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(message))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("anubis: claims decode: %w", err)
	}
	return &c, nil
}

func unix(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}
