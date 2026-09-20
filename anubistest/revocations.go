package anubistest

// The revocation stream, as a fake.
//
// It speaks the Connect streaming framing rather than the unary JSON the rest
// of this server answers with, because that framing is the part of the client
// with nowhere else to be exercised: a length prefix read wrongly is a
// consumer that silently stops seeing revocations.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
)

// RevocationRow is an event to push with PushRevocation.
//
// Tenant and ObservedAt are filled in when left empty — the stream's tenant
// and now — so a test naming only what it is asserting on says only that.
type RevocationRow struct {
	Kind       anubis.RevocationKind
	Tenant     string
	Session    anubis.SessionID
	Subject    anubis.SubjectID
	Epoch      int
	ObservedAt time.Time
}

// revSubBuffer is how many events a subscriber may fall behind by. The real
// broker drops rather than queueing — a slow reader must never hold up the
// gate — and a fake that queued without bound would let a test pass on a
// delivery the installation would not have made.
const revSubBuffer = 16

// PushRevocation delivers an event to every open StreamRevocations
// subscriber, dropping it for any that is already this far behind.
//
// Push only after the consumer has seen anubis.RevocationSynced. Before that
// the subscription does not exist yet, exactly as against a real server, and
// the event goes nowhere.
func (s *Server) PushRevocation(r RevocationRow) {
	s.mu.Lock()
	subs := make([]chan RevocationRow, 0, len(s.revSubs))
	for _, ch := range s.revSubs {
		subs = append(subs, ch)
	}
	s.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- r:
		default:
		}
	}
}

// subscribeRevocations registers a subscriber and returns it with its removal.
func (s *Server) subscribeRevocations() (<-chan RevocationRow, func()) {
	ch := make(chan RevocationRow, revSubBuffer)
	s.mu.Lock()
	if s.revSubs == nil {
		s.revSubs = map[int64]chan RevocationRow{}
	}
	s.revSeq++
	id := s.revSeq
	s.revSubs[id] = ch
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.revSubs, id)
		s.mu.Unlock()
	}
}

func (s *Server) streamRevocations(w http.ResponseWriter, r *http.Request) {
	s.count("StreamRevocations")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.t.Fatalf("anubistest: the test server cannot stream")
		return
	}

	var req struct {
		Tenant string `json:"tenant"`
	}
	if payload, _, err := readEnvelope(r.Body); err == nil {
		_ = json.Unmarshal(payload, &req)
	}

	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)

	// A stream reports its own refusals in the closing frame under a status
	// that already said 200, which is the part of Connect a client written
	// against the unary shape gets wrong. Both refusals the real handler can
	// raise before the first message come out that way here.
	if r.Header.Get("Authorization") == "" {
		writeEndStream(w, flusher, "unauthenticated", "no credential")
		return
	}
	if req.Tenant == "" {
		writeEndStream(w, flusher, "invalid_argument", "tenant: required")
		return
	}

	events, unsubscribe := s.subscribeRevocations()
	defer unsubscribe()

	// Synced goes out after the subscription exists, never before: the other
	// order leaves a window where a revocation happens, the consumer is told
	// it is current, and the event was never delivered.
	if !writeRevocation(w, flusher, req.Tenant, RevocationRow{Kind: anubis.RevocationSynced}) {
		return
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// A client that cancelled is gone; there is nobody left to read a
			// closing frame.
			return
		case ev := <-events:
			if !writeRevocation(w, flusher, req.Tenant, ev) {
				return
			}
		}
	}
}

// writeRevocation frames one message. It reports whether the write landed; a
// failed one means the consumer went away mid-stream.
func writeRevocation(w http.ResponseWriter, flusher http.Flusher, tenant string, r RevocationRow) bool {
	if r.Tenant != "" {
		tenant = r.Tenant
	}
	observed := r.ObservedAt
	if observed.IsZero() {
		observed = time.Now()
	}
	// protojson spelling, as everywhere else here: camelCase on the wire, and
	// int64 rendered as a string.
	body, err := json.Marshal(map[string]any{
		"kind": string(r.Kind), "tenant": tenant,
		"sid": string(r.Session), "sub": string(r.Subject),
		"epoch": r.Epoch, "observedAt": itoa64(observed.Unix()),
	})
	if err != nil {
		return false
	}
	if _, err := w.Write(envelope(0, body)); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// writeEndStream closes the stream with an error.
func writeEndStream(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"code": code, "message": message},
	})
	_, _ = w.Write(envelope(endStreamFlag, body))
	flusher.Flush()
}

// endStreamFlag marks the closing frame of a Connect stream.
const endStreamFlag = 0x02

// envelope frames one message: a flag byte, a four-byte big-endian length,
// then the payload.
func envelope(flags byte, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = flags
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}

// readEnvelope reads one framed message, bounded so that a bad length prefix
// cannot turn into an allocation.
func readEnvelope(r io.Reader) ([]byte, byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, 0, err
	}
	size := binary.BigEndian.Uint32(head[1:5])
	if size > 1<<20 {
		return nil, 0, fmt.Errorf("anubistest: envelope of %d bytes is too large", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}
	return payload, head[0], nil
}
