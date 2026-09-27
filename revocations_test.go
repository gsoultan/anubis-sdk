package anubis_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

// watch runs a subscription in the background and returns the events it saw
// and the error it finished with.
func watch(t *testing.T, ctx context.Context, c *anubis.Client, tenant string) (<-chan anubis.Revocation, <-chan error) {
	t.Helper()
	events := make(chan anubis.Revocation, 8)
	errc := make(chan error, 1)
	go func() {
		errc <- c.StreamRevocations(ctx, tenant, func(r anubis.Revocation) error {
			select {
			case events <- r:
			case <-ctx.Done():
			}
			return nil
		})
	}()
	return events, errc
}

func nextRevocation(t *testing.T, events <-chan anubis.Revocation) anubis.Revocation {
	t.Helper()
	select {
	case r := <-events:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a revocation")
		return anubis.Revocation{}
	}
}

// TestStreamRevocationsSyncsThenDelivers covers the contract a consumer builds
// on: the first message says "you are current", and every event after it is
// something that stopped being valid.
func TestStreamRevocationsSyncsThenDelivers(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, _ := watch(t, ctx, c, "impack")

	if synced := nextRevocation(t, events); synced.Kind != anubis.RevocationSynced {
		t.Fatalf("first message = %q, want %q", synced.Kind, anubis.RevocationSynced)
	}

	observed := time.Now().Add(-2 * time.Second).Truncate(time.Second)
	s.PushRevocation(anubistest.RevocationRow{
		Kind:       anubis.RevocationSession,
		Session:    "ses_9",
		Subject:    "usr_1",
		ObservedAt: observed,
	})

	got := nextRevocation(t, events)
	if got.Kind != anubis.RevocationSession {
		t.Errorf("kind = %q, want %q", got.Kind, anubis.RevocationSession)
	}
	if got.Session != "ses_9" || got.Subject != "usr_1" {
		t.Errorf("sid/sub = %q/%q, want ses_9/usr_1", got.Session, got.Subject)
	}
	if got.Tenant != "impack" {
		t.Errorf("tenant = %q, want impack", got.Tenant)
	}
	// protojson renders int64 as a string; a client that decoded it as a
	// number would have failed the whole message, not just this field.
	if !got.ObservedAt().Equal(observed) {
		t.Errorf("observedAt = %s, want %s", got.ObservedAt(), observed)
	}
}

// TestStreamRevocationsCarriesTheEpochBump proves the bulk form survives the
// wire. An epoch bump names no session: it invalidates everything issued to an
// identity before it, and a consumer that only handled sessions would keep
// serving a password that has just been changed.
func TestStreamRevocationsCarriesTheEpochBump(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, _ := watch(t, ctx, c, "impack")
	nextRevocation(t, events) // synced

	s.PushRevocation(anubistest.RevocationRow{
		Kind: anubis.RevocationEpoch, Subject: "usr_7", Epoch: 4,
	})

	got := nextRevocation(t, events)
	if got.Kind != anubis.RevocationEpoch || got.Subject != "usr_7" || got.Epoch != 4 {
		t.Fatalf("got %+v, want an epoch bump to 4 for usr_7", got)
	}
	if got.Session != "" {
		t.Errorf("sid = %q, want empty on an epoch bump", got.Session)
	}
}

// TestStreamRevocationsOutlivesTheCallTimeout is the regression test for a
// subscription that dies on a schedule.
//
// The root cause it guards: every other call here is a question with an
// answer, so the shared http.Client carries a Timeout — and a stream sharing
// that client is torn down mid-flight when it fires, arriving as something
// indistinguishable from a network fault.
func TestStreamRevocationsOutlivesTheCallTimeout(t *testing.T) {
	s := newTestServer(t)
	const timeout = 150 * time.Millisecond
	c := newClient(t, s, anubis.WithTimeout(timeout))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := time.Now()
	events, errc := watch(t, ctx, c, "impack")
	nextRevocation(t, events) // synced

	// Push only once the unary deadline is comfortably behind us.
	time.Sleep(time.Until(started.Add(3 * timeout)))
	select {
	case err := <-errc:
		t.Fatalf("stream ended after %s with %v; the call timeout should not reach it", time.Since(started), err)
	default:
	}

	s.PushRevocation(anubistest.RevocationRow{Kind: anubis.RevocationSession, Session: "ses_late"})
	if got := nextRevocation(t, events); got.Session != "ses_late" {
		t.Fatalf("sid = %q, want ses_late", got.Session)
	}
}

// TestStreamRevocationsReportsAnEndOfStreamError is the regression test for a
// refusal read as a clean finish.
//
// The root cause it guards: a Connect stream answers 200 and puts its refusal
// in the closing frame, so a client that judges by HTTP status alone reports
// success and a consumer sits there believing it is subscribed.
func TestStreamRevocationsReportsAnEndOfStreamError(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)

	// The fake refuses an empty tenant, as the real handler does.
	err := c.StreamRevocations(context.Background(), "", func(anubis.Revocation) error {
		t.Error("no event should arrive on a refused stream")
		return nil
	})
	if err == nil {
		t.Fatal("StreamRevocations succeeded on a refused subscription")
	}
	var apiErr *anubis.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want an *anubis.APIError", err, err)
	}
	if apiErr.Code != "invalid_argument" {
		t.Errorf("code = %q, want invalid_argument", apiErr.Code)
	}
}

// TestStreamRevocationsFromAnInstanceThatDoesNotStream: root cause — the
// domain code in ErrorInfo replaced Connect's transport class, and classify did
// not know "stream_unavailable", so an instance saying "not me, another can
// serve this" came back as a bare APIError. A consumer that reconnects on
// UnavailableError — the SDK's own advice for a gap — gave up instead of
// landing on an instance that streams.
//
// The frame is the real server's: Connect's class, and the domain code in an
// ErrorInfo detail beside it.
func TestStreamRevocationsFromAnInstanceThatDoesNotStream(t *testing.T) {
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		w.Write(connectFrame(0x02, `{"error":{"code":"unavailable",`+
			`"message":"stream_unavailable: Revocation streaming is not enabled on this instance",`+
			`"details":[{"type":"anubis.v1.ErrorInfo","value":"`+
			errorInfoWire("stream_unavailable", "req_stream", nil)+`"}]}}`))
	}))
	defer raw.Close()

	c, err := anubis.New(raw.URL, anubis.WithApplication(app, ""), anubis.WithAPIKey("anb_live_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.StreamRevocations(context.Background(), "impack", func(anubis.Revocation) error { return nil })
	var unavailable *anubis.UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v (%T), want an *anubis.UnavailableError: reconnecting may reach an instance that streams", err, err)
	}
	var apiErr *anubis.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "stream_unavailable" {
		t.Errorf("the server's own code is lost: %v", err)
	}
}

// TestAReconnectLandsOnAnInstanceThatStreams is the same refusal through the
// fake, the way a consumer meets it behind a load balancer: refused as
// unavailable by an instance not watching snapshots, reconnect, served.
func TestAReconnectLandsOnAnInstanceThatStreams(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.RefuseStreams(true)
	err := c.StreamRevocations(ctx, "impack", func(anubis.Revocation) error { return nil })
	var unavailable *anubis.UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v (%T), want an *anubis.UnavailableError", err, err)
	}

	s.RefuseStreams(false)
	events, _ := watch(t, ctx, c, "impack")
	if synced := nextRevocation(t, events); synced.Kind != anubis.RevocationSynced {
		t.Fatalf("first message after reconnecting = %q, want %q", synced.Kind, anubis.RevocationSynced)
	}
}

// TestStreamRevocationsRefusalIsTyped proves the closing frame still reaches
// classify: an unauthenticated stream has to arrive as an AuthError, like
// every other unauthenticated call, and not as an opaque transport failure.
func TestStreamRevocationsRefusalIsTyped(t *testing.T) {
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		w.Write(connectFrame(0x02, `{"error":{"code":"unauthenticated","message":"no credential"}}`))
	}))
	defer raw.Close()

	c, err := anubis.New(raw.URL, anubis.WithApplication(app, ""), anubis.WithAPIKey("anb_live_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.StreamRevocations(context.Background(), "impack", func(anubis.Revocation) error { return nil })
	var authErr *anubis.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error = %v (%T), want an *anubis.AuthError", err, err)
	}
}

// TestStreamRevocationsStopsOnCancel proves cancelling is how a consumer lets
// go, and that it says so rather than reporting a fault.
func TestStreamRevocationsStopsOnCancel(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)
	ctx, cancel := context.WithCancel(context.Background())

	events, errc := watch(t, ctx, c, "impack")
	nextRevocation(t, events) // synced
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling did not end the stream")
	}
}

// TestStreamRevocationsStopsWhenTheCallbackFails proves a consumer can give
// up from inside the loop, and gets its own error back rather than a wrapped
// one it has to unpick.
func TestStreamRevocationsStopsWhenTheCallbackFails(t *testing.T) {
	s := newTestServer(t)
	c := newClient(t, s)
	sentinel := errors.New("enough")

	err := c.StreamRevocations(context.Background(), "impack", func(anubis.Revocation) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the callback's own error", err)
	}
}

// TestRevocationKindAcceptsEnumNumbers covers the other spelling protojson can
// produce. Which one arrives is a server-side encoder setting; a client that
// understood only names would decode an event as unspecified and drop it.
func TestRevocationKindAcceptsEnumNumbers(t *testing.T) {
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		w.Write(connectFrame(0, `{"kind":1,"sid":"ses_3","observedAt":"1700000000"}`))
		w.(http.Flusher).Flush()
		w.Write(connectFrame(0x02, `{}`))
	}))
	defer raw.Close()

	c, err := anubis.New(raw.URL, anubis.WithApplication(app, ""), anubis.WithAPIKey("anb_live_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got []anubis.Revocation
	if err := c.StreamRevocations(context.Background(), "impack", func(r anubis.Revocation) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamRevocations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Kind != anubis.RevocationSession {
		t.Errorf("kind = %q, want %q", got[0].Kind, anubis.RevocationSession)
	}
}

// TestStreamRevocationsRejectsAnOversizedFrame proves the length prefix is
// bounded. It is a number from the far end that this side allocates on, so an
// unbounded one turns a single bad frame into a four-gigabyte allocation.
func TestStreamRevocationsRejectsAnOversizedFrame(t *testing.T) {
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		var head [5]byte
		binary.BigEndian.PutUint32(head[1:5], 1<<30)
		w.Write(head[:])
		w.(http.Flusher).Flush()
	}))
	defer raw.Close()

	c, err := anubis.New(raw.URL, anubis.WithApplication(app, ""), anubis.WithAPIKey("anb_live_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.StreamRevocations(context.Background(), "impack", func(anubis.Revocation) error { return nil })
	if err == nil {
		t.Fatal("a 1 GiB frame was accepted")
	}
}

// connectFrame builds one enveloped message, by hand, so these tests do not
// depend on the framing they exist to check.
func connectFrame(flags byte, payload string) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = flags
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}
