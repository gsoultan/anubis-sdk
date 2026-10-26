package anubis

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// GrantedNodes is the answer to "where, on this axis, may this subject do
// this?" — asked ONCE per screen so an application can filter its own query,
// instead of asking Authorize once per row.
//
// Three shapes, because the three mean different things to a filter:
//
//   - Everywhere: some qualifying grant puts no limit on the axis. There is
//     no list; apply no filter.
//   - Nodes: the places qualifying grants name, each with its reach and its
//     exceptions. Turn these into the predicate your data model needs.
//   - OwnRecords: a self-scoped grant qualifies. Rows the subject owns pass
//     regardless of place.
//
// Nowhere reports that none of the three is set: show the empty state, not
// every row.
//
// It is read from the gate's snapshot, so a grant made a moment ago may be
// a few seconds away; AsOf says how fresh. Anubis refuses — an APIError
// with code "snapshot_unavailable" — rather than answering from a stale one.
type GrantedNodes struct {
	Everywhere bool          `json:"everywhere"`
	OwnRecords bool          `json:"ownRecords"`
	Nodes      []GrantedNode `json:"nodes"`
	AsOfUnix   int64         `json:"asOf"`
}

// GrantedNode is one place a grant reaches. Inherit says whether everything
// inside it is reached too; Except lists what the SAME grant carves out — it
// narrows this node only, not a node another grant reaches independently.
type GrantedNode struct {
	NodeID  string        `json:"nodeId"`
	Inherit bool          `json:"inherit"`
	Except  []GrantedNode `json:"except,omitempty"`
}

// Nowhere reports that the subject may do this at no place on the axis.
func (g GrantedNodes) Nowhere() bool {
	return !g.Everywhere && !g.OwnRecords && len(g.Nodes) == 0
}

// AsOf is when the snapshot the answer came from was current.
func (g GrantedNodes) AsOf() time.Time { return time.Unix(g.AsOfUnix, 0) }

// GrantedNodes asks where the verified caller may exercise permission along
// axis. fixed pins the OTHER axes — usually the session's active scope —
// because a grant limited on two axes reaches a place on one only where the
// other is satisfied too. A grant limited on an axis that is neither axis nor
// fixed is dropped, the same fail-closed rule Authorize applies, so the list
// can never name a place Authorize would deny.
func (c *Client) GrantedNodes(ctx context.Context, permission Permission, axis Axis, fixed Scopes) (*GrantedNodes, error) {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return nil, ErrNoPrincipal
	}
	return c.grantedNodes(ctx, id.Subject, permission, axis, fixed)
}

// GrantedNodesOf asks about a named subject rather than the verified caller,
// for back ends that hold a tenant API key and ask about their users.
func (c *Client) GrantedNodesOf(ctx context.Context, subject SubjectID, permission Permission, axis Axis, fixed Scopes) (*GrantedNodes, error) {
	return c.grantedNodes(ctx, subject, permission, axis, fixed)
}

func (c *Client) grantedNodes(ctx context.Context, subject SubjectID, permission Permission, axis Axis, fixed Scopes) (*GrantedNodes, error) {
	if subject == "" {
		return nil, errors.New("anubis: granted nodes needs a subject")
	}
	if !permission.IsValid() {
		return nil, fmt.Errorf("anubis: %q is not a permission key — expected app:resource:action", permission)
	}
	if axis == "" || axis == AxisOwner {
		return nil, errors.New("anubis: granted nodes needs a structure axis to leave open")
	}
	req := map[string]any{
		"subject":    string(subject),
		"permission": string(permission),
		"axis":       string(axis),
		"scopes":     fixed.wire(),
	}
	var out GrantedNodes
	if err := c.rpc(ctx, procListGrantedNodes, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
