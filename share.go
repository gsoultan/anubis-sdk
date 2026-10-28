package anubis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RecordShare is one person's access to ONE record, handed to another for a
// while. Anubis consults it only when Authorize is asked with the record
// named — Scopes{"_record": "kind/ref"} beside the record's places — and it
// always ends.
type RecordShare struct {
	ID             string            `json:"id"`
	RecordKind     string            `json:"recordKind"`
	RecordRef      string            `json:"recordRef"`
	FromIdentityID SubjectID         `json:"fromIdentityId"`
	ToIdentityID   SubjectID         `json:"toIdentityId"`
	Permissions    []Permission      `json:"permissions"`
	Note           string            `json:"note"`
	CreatedAtUnix  int64             `json:"createdAt"`
	ValidUntilUnix int64             `json:"validUntil"`
	RecordScopes   map[string]string `json:"recordScopes"`
}

// ValidUntil is when the share ends.
func (s RecordShare) ValidUntil() time.Time { return time.Unix(s.ValidUntilUnix, 0) }

// RecordTarget is the Scopes entry that names a record to Authorize.
func RecordTarget(kind, ref string) (Axis, string) { return "_record", kind + "/" + ref }

// ShareRequest opens one record to one person.
type ShareRequest struct {
	RecordKind string
	RecordRef  string
	// RecordScopes is where the record lives — the same Scopes you pass to
	// Authorize for it, Owner included when it has one. Anubis authorises
	// the caller for every permission at these places before the share
	// exists: you can only share what you can do.
	RecordScopes Scopes
	To           SubjectID
	Permissions  []Permission
	// ValidUntil is required and at most 90 days out.
	ValidUntil time.Time
	Note       string
}

// Share opens the record to the person, as the verified caller.
func (c *Client) Share(ctx context.Context, in ShareRequest) (*RecordShare, error) {
	switch {
	case in.RecordKind == "" || in.RecordRef == "":
		return nil, errors.New("anubis: share needs a record kind and ref")
	case in.To == "":
		return nil, errors.New("anubis: share needs somebody to share with")
	case len(in.Permissions) == 0:
		return nil, errors.New("anubis: share needs at least one permission")
	case in.ValidUntil.IsZero():
		return nil, errors.New("anubis: share needs an end; a share always ends")
	}
	perms := make([]string, 0, len(in.Permissions))
	for _, p := range in.Permissions {
		if !p.IsValid() {
			return nil, fmt.Errorf("anubis: %q is not a permission key — expected app:resource:action", p)
		}
		perms = append(perms, string(p))
	}
	req := map[string]any{
		"record_kind":    in.RecordKind,
		"record_ref":     in.RecordRef,
		"record_scopes":  in.RecordScopes.wire(),
		"to_identity_id": string(in.To),
		"permissions":    perms,
		"valid_until":    in.ValidUntil.Unix(),
		"note":           in.Note,
	}
	var out struct {
		Share *RecordShare `json:"share"`
	}
	if err := c.rpc(ctx, procShare, req, &out); err != nil {
		return nil, err
	}
	if out.Share == nil {
		return nil, errors.New("anubis: share returned nothing")
	}
	return out.Share, nil
}

// Unshare ends a share. The sharer may always; anybody else needs every
// permission the share confers, at the record's places.
func (c *Client) Unshare(ctx context.Context, shareID, reason string) error {
	return c.rpc(ctx, procUnshare, map[string]any{"share_id": shareID, "reason": reason}, &struct{}{})
}

// SharesOnRecord lists live shares on a record the caller may see.
func (c *Client) SharesOnRecord(ctx context.Context, kind, ref string, scopes Scopes) ([]RecordShare, error) {
	var out struct {
		Shares []RecordShare `json:"shares"`
	}
	req := map[string]any{"record_kind": kind, "record_ref": ref, "record_scopes": scopes.wire()}
	if err := c.rpc(ctx, procListSharesOnRecord, req, &out); err != nil {
		return nil, err
	}
	return out.Shares, nil
}

// SharedWithMe lists live shares to the verified caller.
func (c *Client) SharedWithMe(ctx context.Context) ([]RecordShare, error) {
	var out struct {
		Shares []RecordShare `json:"shares"`
	}
	if err := c.rpc(ctx, procListSharedWithMe, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Shares, nil
}

// CreateAccessLink mints the link a recipient with no password opens the
// record with. Returned once; making another replaces it. Anubis mails
// nothing — put the token in your own message, at your own record URL —
// and your page exchanges it with OpenAccessLink.
func (c *Client) CreateAccessLink(ctx context.Context, shareID string) (string, error) {
	var out struct {
		LinkToken string `json:"linkToken"`
	}
	if err := c.rpc(ctx, procCreateAccessLink, map[string]any{"share_id": shareID}, &out); err != nil {
		return "", err
	}
	if out.LinkToken == "" {
		return "", errors.New("anubis: no link token returned")
	}
	return out.LinkToken, nil
}

// OpenAccessLink exchanges a link for a token that opens THAT record in
// this application: ten minutes, no session, no refresh, amr ["link"]. Use
// it as the bearer for Authorize with the record named; Anubis refuses it
// for anything else, and the gate refuses it outright. Call it with the
// tenant key — the holder of a link has no credential of their own.
func (c *Client) OpenAccessLink(ctx context.Context, linkToken string) (*Tokens, error) {
	if linkToken == "" {
		return nil, errors.New("anubis: open needs a link token")
	}
	var out struct {
		Tokens *Tokens `json:"tokens"`
	}
	req := map[string]any{"tenant": c.opts.tenant, "client_id": c.opts.clientID, "link_token": linkToken}
	if err := c.rpcNoAuth(ctx, procOpenAccessLink, req, &out); err != nil {
		return nil, err
	}
	if out.Tokens == nil {
		return nil, errors.New("anubis: open returned no token")
	}
	c.stamp(out.Tokens)
	return out.Tokens, nil
}

// UnmarshalJSON reads the share as protojson sends it, where the two int64
// times arrive as quoted strings; a bare number is accepted too.
func (s *RecordShare) UnmarshalJSON(b []byte) error {
	type plain RecordShare
	var wire struct {
		plain
		CreatedAtUnix  pbInt64 `json:"createdAt"`
		ValidUntilUnix pbInt64 `json:"validUntil"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	*s = RecordShare(wire.plain)
	s.CreatedAtUnix, s.ValidUntilUnix = int64(wire.CreatedAtUnix), int64(wire.ValidUntilUnix)
	return nil
}
