package anubis

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// RevocationKind is what stopped being valid.
type RevocationKind string

const (
	// RevocationUnspecified is an event this SDK does not have a name for,
	// which on a newer server means a kind added after this build. Something
	// changed; treat it as a reason to re-check, not as noise to drop.
	RevocationUnspecified RevocationKind = "KIND_UNSPECIFIED"
	// RevocationSession ends one session — logout, an administrator revoking
	// it, or refresh-token theft detection. Session is set.
	RevocationSession RevocationKind = "KIND_SESSION_REVOKED"
	// RevocationEpoch invalidates every token issued to an identity before
	// Epoch, which is how a password change or a disable invalidates in bulk.
	// Subject and Epoch are set.
	RevocationEpoch RevocationKind = "KIND_EPOCH_BUMPED"
	// RevocationSynced is sent once, before any change event, and says the
	// consumer has seen the current state. It is the only thing that
	// distinguishes "nothing has happened yet" from "not connected yet".
	RevocationSynced RevocationKind = "KIND_SYNCED"
)

// revocationKinds is the enum in field-number order, for a server that sends
// numbers rather than names.
var revocationKinds = [...]RevocationKind{
	RevocationUnspecified, RevocationSession, RevocationEpoch, RevocationSynced,
}

// UnmarshalJSON accepts both spellings protojson can produce. A default
// encoder writes the name; one built with UseEnumNumbers writes the number.
// Which one arrives is a server-side encoder setting that has nothing to do
// with this client, so understanding only one of them would be a break
// waiting on somebody else's configuration change.
//
// A name this build has never heard of is kept verbatim rather than flattened
// to unspecified: a caller that logs the kind can then say what it saw.
func (k *RevocationKind) UnmarshalJSON(b []byte) error {
	s := string(bytes.Trim(bytes.TrimSpace(b), `"`))
	if s == "" || s == "null" {
		*k = RevocationUnspecified
		return nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n >= len(revocationKinds) {
			*k = RevocationUnspecified
			return nil
		}
		*k = revocationKinds[n]
		return nil
	}
	*k = RevocationKind(s)
	return nil
}

// Revocation names something that stopped being valid.
type Revocation struct {
	Kind    RevocationKind `json:"kind"`
	Tenant  string         `json:"tenant"`
	Session SessionID      `json:"sid"`
	Subject SubjectID      `json:"sub"`
	Epoch   int            `json:"epoch"`
	// Observed is when Anubis saw it, not when this process received it. The
	// gap between the two is exactly the window the stream exists to shorten,
	// so measuring it needs both.
	Observed pbInt64 `json:"observedAt"`
}

// ObservedAt is when Anubis observed the revocation.
func (r Revocation) ObservedAt() time.Time { return unix(int64(r.Observed)) }

// StreamRevocations watches one tenant's revocations, calling fn for each
// event until ctx is cancelled, fn returns an error, or the stream ends.
//
// This is a CACHE INVALIDATION and not an authorization decision, which is the
// whole contract. Anubis drops events for a consumer that is not connected
// rather than queueing them — a slow reader must never hold up the gate — so a
// consumer that was away missed whatever happened while it was away. That is
// survivable only because correctness comes from short token lifetimes and
// from re-checking. Treat a gap as "check again", never as "allow", and never
// let a delivered event be the only thing standing between a revoked session
// and a served request.
//
// The first event is RevocationSynced. Events before it are not possible, so a
// consumer can treat its arrival as the point where its cache is current.
//
// Service authentication only: this is session state for a whole tenant, and
// an end user's own token does not entitle them to watch everybody else's
// sessions end. Configure WithAPIKey. A tenant-scoped credential watches its
// own tenant whatever it passes here.
//
// The call blocks. Cancelling ctx is how it is stopped, and returns ctx.Err().
//
// An [UnavailableError] is the one to reconnect on: a dropped connection, and
// also an instance that is not watching snapshots and so has nothing to
// stream, which refuses with the code stream_unavailable — another instance
// may serve the reconnect.
func (c *Client) StreamRevocations(ctx context.Context, tenant string, fn func(Revocation) error) error {
	body, err := json.Marshal(map[string]any{"tenant": tenant})
	if err != nil {
		return fmt.Errorf("anubis: encoding %s request: %w", procStreamRevocations, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+procStreamRevocations, bytes.NewReader(connectEnvelope(body)))
	if err != nil {
		return err
	}
	// Streaming Connect is a different content type from the unary JSON the
	// rest of this client speaks, and the messages are length-prefixed rather
	// than a single document.
	req.Header.Set("Content-Type", "application/connect+json")
	req.Header.Set("Connect-Protocol-Version", "1")
	// Nothing here inflates a frame, so say so rather than meet one.
	req.Header.Set("Connect-Accept-Encoding", "identity")
	if err := c.attachCredential(ctx, req); err != nil {
		return err
	}
	for name, value := range c.opts.headers {
		req.Header.Set(name, value)
	}
	if c.opts.tenant != "" {
		req.Header.Set("X-Anubis-Tenant", c.opts.tenant)
	}

	resp, err := c.streamClient().Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return &UnavailableError{err: err}
	}
	defer resp.Body.Close()

	// A Connect stream reports its own failures in the end-of-stream frame
	// with a 200, so a non-200 here is the request never having become a
	// stream at all: no credential, no such route, a proxy in the way.
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return classify(parseWireError(raw, resp.StatusCode), resp.Header)
	}
	return readRevocations(ctx, resp, fn)
}

// readRevocations drains the enveloped stream.
func readRevocations(ctx context.Context, resp *http.Response, fn func(Revocation) error) error {
	for {
		flags, payload, err := readEnvelope(resp.Body)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err == io.EOF {
				// The connection went away without an end-of-stream frame.
				// That is a disconnection, not an orderly finish, and the
				// caller's next move is the same as for any other gap:
				// reconnect and re-check. Typing it as unavailable is what
				// says so.
				return &UnavailableError{err: fmt.Errorf("anubis: revocation stream ended without a trailer")}
			}
			return &UnavailableError{err: err}
		}
		switch {
		case flags&connectFlagCompressed != 0:
			// We asked for identity encoding. A compressed frame anyway is a
			// frame we would silently mis-decode, so refuse it instead.
			return &UnavailableError{err: fmt.Errorf("anubis: revocation stream sent a compressed frame")}
		case flags&connectFlagEndStream != 0:
			return endOfStream(payload, resp.Header)
		}
		var rev Revocation
		if err := json.Unmarshal(payload, &rev); err != nil {
			return fmt.Errorf("anubis: decoding revocation: %w", err)
		}
		if err := fn(rev); err != nil {
			return err
		}
	}
}

// Connect envelope flags. The prefix is one flag byte and a four-byte
// big-endian length, ahead of every message in both directions.
const (
	connectFlagCompressed = 0x01
	connectFlagEndStream  = 0x02
)

// connectEnvelope wraps one request message.
func connectEnvelope(payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}

// readEnvelope reads one framed message.
//
// The length is attacker-reachable in the sense that matters here — it is a
// number from the far end, and this side allocates on it — so it is bounded by
// the same limit a unary response gets. Without that, one bad four-byte prefix
// is a four-gigabyte allocation.
func readEnvelope(r io.Reader) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, nil, io.EOF
		}
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(head[1:5])
	if size > maxResponseBytes {
		return 0, nil, fmt.Errorf("anubis: revocation frame of %d bytes exceeds the %d-byte limit", size, maxResponseBytes)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, nil, io.EOF
		}
		return 0, nil, err
	}
	return head[0], payload, nil
}

// endOfStream turns the closing frame into the caller's error, or nil.
//
// A stream that ends cleanly carries no error and is not a failure: the
// subscription is simply over, and a caller that wants to keep watching
// reconnects.
func endOfStream(payload []byte, header http.Header) error {
	var end struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(payload, &end); err != nil {
		return fmt.Errorf("anubis: decoding end of revocation stream: %w", err)
	}
	if len(end.Error) == 0 || string(end.Error) == "null" {
		return nil
	}
	// Status 0 rather than 200: this refusal never had an HTTP status of its
	// own, and claiming the 200 the stream opened with would be a lie about
	// where the code came from. classify reads the code, which Connect always
	// sets on an error.
	return classify(parseWireError(end.Error, 0), header)
}

// streamClient is the HTTP client without the per-call timeout.
//
// DefaultTimeout bounds a unary call, and should: every other call in this
// client is a question with an answer. A subscription has no answer, and a
// Timeout that applied to it would tear the stream down on a schedule —
// ten seconds in, by default — and hand back something indistinguishable from
// a network failure. Cancelling ctx is how a stream is stopped.
//
// The clone shares the Transport, so connections still pool.
func (c *Client) streamClient() *http.Client {
	if c.opts.httpClient.Timeout == 0 {
		return c.opts.httpClient
	}
	unbounded := *c.opts.httpClient
	unbounded.Timeout = 0
	return &unbounded
}
