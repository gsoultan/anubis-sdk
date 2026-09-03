package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

const slug = "billing-worker"

// No broker. go-kit's Subscriber exposes ServeDelivery(Channel), which takes
// the two interfaces a broker would have supplied — so the whole worker runs
// in-process against a synthesized delivery. What a broker would add is
// network, and the network is not what goes wrong here.

type fakeChannel struct {
	published []amqp.Publishing
}

func (c *fakeChannel) Publish(_, _ string, _, _ bool, msg amqp.Publishing) error {
	c.published = append(c.published, msg)
	return nil
}

func (c *fakeChannel) Consume(_, _ string, _, _, _, _ bool, _ amqp.Table) (<-chan amqp.Delivery, error) {
	return nil, nil
}

// acknowledger records the fate of the message, which is the only thing a
// worker really decides.
type acknowledger struct {
	acked   bool
	nacked  bool
	requeue bool
}

func (a *acknowledger) Ack(uint64, bool) error {
	a.acked = true
	return nil
}

func (a *acknowledger) Nack(_ uint64, _, requeue bool) error {
	a.nacked, a.requeue = true, requeue
	return nil
}

func (a *acknowledger) Reject(uint64, bool) error { return nil }

func start(t *testing.T) (*anubistest.Server, func(*amqp.Delivery), *fakeChannel) {
	t.Helper()
	an := anubistest.NewServer(t)
	endpoints, err := build(an.URL, slug, "anb_live_ab12cd34_s3cr3t", "impack")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ch := &fakeChannel{}
	return an, NewSubscriber(endpoints).ServeDelivery(ch), ch
}

func delivery(token, invoiceID string) (*amqp.Delivery, *acknowledger) {
	ack := &acknowledger{}
	body, _ := json.Marshal(billing.ApproveRequest{InvoiceID: invoiceID})
	deliv := &amqp.Delivery{
		Acknowledger: ack,
		Body:         body,
		ReplyTo:      "reply.q",
		DeliveryTag:  1,
	}
	if token != "" {
		deliv.Headers = amqp.Table{anubiskit.AuthorizationHeader: "Bearer " + token}
	}
	return deliv, ack
}

func token(an *anubistest.Server, subject anubis.SubjectID, amr ...anubis.AuthMethod) string {
	return an.MintToken(anubis.Claims{
		Subject: subject, Audience: []string{slug}, Session: "ses_1", AMR: amr,
	})
}

func TestAuthorisedMessageIsProcessedRepliedAndAcked(t *testing.T) {
	an, serve, ch := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	deliv, ack := delivery(token(an, "usr_1", "pwd", "otp"), "inv-1")
	serve(deliv)

	if !ack.acked || ack.nacked {
		t.Fatalf("acked=%v nacked=%v, want acked", ack.acked, ack.nacked)
	}
	if len(ch.published) != 1 {
		t.Fatalf("published %d replies, want 1", len(ch.published))
	}
	var reply billing.ApproveResponse
	if err := json.Unmarshal(ch.published[0].Body, &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.Invoice.Approved || reply.Invoice.ApprovedBy != "usr_1" {
		t.Fatalf("reply = %+v", reply.Invoice)
	}

	// The same assertion the HTTP and gRPC examples make, over a third
	// transport and the same endpoint code.
	ask := an.LastAsk()
	if ask.Scopes["org"] != "org-north" || ask.Scopes["customer"] != "cust-acme" {
		t.Fatalf("scopes = %v, want both axes from the loaded invoice", ask.Scopes)
	}
	if len(ask.AMR) != 2 || ask.AuthTime == 0 {
		t.Fatalf("amr = %v, auth_time = %d", ask.AMR, ask.AuthTime)
	}
}

// TestPermanentRefusalsAreNotRequeued is the test this transport exists for.
// None of these becomes true on a second delivery, so requeuing any of them
// spins the queue forever on a message that can never succeed.
func TestPermanentRefusalsAreNotRequeued(t *testing.T) {
	cases := []struct {
		name  string
		setUp func(an *anubistest.Server) string
	}{
		{"no credential at all", func(*anubistest.Server) string { return "" }},
		{"denied", func(an *anubistest.Server) string {
			an.Deny("usr_1", "billing:invoice:approve", "scope_mismatch", "customer")
			return token(an, "usr_1", "pwd")
		}},
		{"step-up required", func(an *anubistest.Server) string {
			an.RequireStepUp("usr_1", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")
			return token(an, "usr_1", "pwd")
		}},
		{"token minted for another service", func(an *anubistest.Server) string {
			return an.MintToken(anubis.Claims{Subject: "usr_1", Audience: []string{"hr-api"}})
		}},
		{
			// The hazard peculiar to queues: a message can be consumed long
			// after it was published. Requeuing an expired credential is an
			// infinite loop, because time only makes it worse.
			"token expired while it sat on the queue",
			func(an *anubistest.Server) string {
				return an.MintToken(anubis.Claims{
					Subject: "usr_1", Audience: []string{slug},
					Expires: time.Now().Add(-time.Hour).Unix(),
				})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			an, serve, ch := start(t)
			deliv, ack := delivery(tc.setUp(an), "inv-1")

			serve(deliv)

			if !ack.nacked {
				t.Fatal("the message was not nacked")
			}
			if ack.requeue {
				t.Fatal("requeued a message that can never succeed")
			}
			if ack.acked {
				t.Fatal("a refused message was acknowledged as done")
			}
			if len(ch.published) != 0 {
				t.Fatal("replied to a message it refused to process")
			}
		})
	}
}

// TestTransientFailureIsRequeued is the other half. Anubis being unreachable
// says nothing about the message; dead-lettering it here would throw away work
// because a dependency blinked.
func TestTransientFailureIsRequeued(t *testing.T) {
	an, serve, _ := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	// Warm the key cache first, so what fails afterwards is the decision call
	// and not offline verification — which is the point: verification survives
	// Anubis going away, and asking does not.
	first, firstAck := delivery(token(an, "usr_1", "pwd"), "inv-1")
	serve(first)
	if !firstAck.acked {
		t.Fatal("setup delivery did not succeed")
	}

	an.Close()

	second, ack := delivery(token(an, "usr_1", "pwd"), "inv-2")
	serve(second)

	if !ack.nacked {
		t.Fatal("the message was not nacked")
	}
	if !ack.requeue {
		t.Fatal("dead-lettered a message that would have succeeded on a retry")
	}
}

func TestMalformedBodyIsDeadLettered(t *testing.T) {
	_, serve, _ := start(t)
	ack := &acknowledger{}
	serve(&amqp.Delivery{Acknowledger: ack, Body: []byte("{not json"), DeliveryTag: 1})

	if !ack.nacked || ack.requeue {
		t.Fatalf("nacked=%v requeue=%v, want a dead-letter", ack.nacked, ack.requeue)
	}
}

// TestContextToAMQPRoundTrips checks the publishing side against the consuming
// side, which is the only way to know the two agree on a header name.
func TestContextToAMQPRoundTrips(t *testing.T) {
	an, serve, ch := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	// As a publisher would: put the credential in the context, let the
	// RequestFunc write the header.
	ctx := t.Context()
	ctx = contextWithToken(ctx, token(an, "usr_1", "pwd"))
	pub := &amqp.Publishing{}
	anubiskit.ContextToAMQP()(ctx, pub, nil)

	if pub.Headers[anubiskit.AuthorizationHeader] == nil {
		t.Fatal("the publisher wrote no credential")
	}

	body, _ := json.Marshal(billing.ApproveRequest{InvoiceID: "inv-1"})
	ack := &acknowledger{}
	serve(&amqp.Delivery{
		Acknowledger: ack, Body: body, Headers: pub.Headers, ReplyTo: "reply.q", DeliveryTag: 1,
	})

	if !ack.acked {
		t.Fatal("the consumer did not accept what the publisher wrote")
	}
	if len(ch.published) != 1 {
		t.Fatalf("published %d replies, want 1", len(ch.published))
	}
}

func contextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, anubiskit.BearerTokenContextKey, token)
}
