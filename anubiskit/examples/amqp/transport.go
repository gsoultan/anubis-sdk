// Command amqp serves the billing service as an AMQP worker.
//
// The service and the endpoints are the same ones the HTTP and gRPC examples
// serve — package billing, unchanged. A queue is just another way for a
// request to arrive, and a message that arrived is not thereby authorised:
// whatever published it had to prove something, and this worker checks that
// proof exactly as the HTTP transport checks a bearer token.
package main

import (
	"context"
	"encoding/json"

	amqptransport "github.com/go-kit/kit/transport/amqp"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/gsoultan/anubis-sdk/anubiskit"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
)

// NewSubscriber mounts the approve endpoint on a queue.
//
// Three options do the integration. SubscriberBefore lifts the credential out
// of the message headers; SubscriberErrorEncoder decides what happens to a
// message that could not be processed; the response publisher replies and
// acknowledges.
func NewSubscriber(e billing.Endpoints) *amqptransport.Subscriber {
	return amqptransport.NewSubscriber(
		e.Approve,
		decodeApproveRequest,
		encodeApproveResponse,
		amqptransport.SubscriberBefore(anubiskit.AMQPToContext()),
		amqptransport.SubscriberErrorEncoder(errorEncoder),
		amqptransport.SubscriberResponsePublisher(publishAndAck),
	)
}

func decodeApproveRequest(_ context.Context, deliv *amqp.Delivery) (any, error) {
	var req billing.ApproveRequest
	if err := json.Unmarshal(deliv.Body, &req); err != nil {
		return nil, err
	}
	return req, nil
}

func encodeApproveResponse(_ context.Context, pub *amqp.Publishing, response any) error {
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	pub.ContentType = "application/json"
	pub.Body = body
	return nil
}

// publishAndAck sends the reply, then acknowledges the delivery.
//
// The acknowledgement comes last on purpose. Acking first and then failing to
// publish loses the reply with no record that it was ever owed; this way a
// crash between the two redelivers the message, and the work is idempotent
// because approving an approved invoice approves it again.
func publishAndAck(_ context.Context, deliv *amqp.Delivery, ch amqptransport.Channel, pub *amqp.Publishing) error {
	if deliv.ReplyTo != "" {
		pub.CorrelationId = deliv.CorrelationId
		if err := ch.Publish("", deliv.ReplyTo, false, false, *pub); err != nil {
			return err
		}
	}
	return deliv.Ack(false)
}

// errorEncoder decides the fate of a message that failed.
//
// This is the only decision that really matters on a queue, and it is not the
// same question HTTP asks. HTTP answers a caller who is still waiting; AMQP
// answers nobody, and the choice is between putting the message back and
// giving up on it. Get it backwards and you either spin on a poison message
// forever or throw away work because a dependency blinked.
//
// anubiskit.Retryable draws the line: a refused credential or a denial is
// permanent — a message does not become authorised by being delivered again —
// while Anubis being unreachable is not.
func errorEncoder(ctx context.Context, err error, deliv *amqp.Delivery, ch amqptransport.Channel, pub *amqp.Publishing) {
	if deliv == nil {
		return
	}
	// A malformed body is this service's own permanent failure, and the SDK
	// has no opinion about it: dead-letter it rather than requeue.
	if _, isJSON := err.(*json.SyntaxError); isJSON {
		_ = deliv.Nack(false, false)
		return
	}
	anubiskit.NackErrorEncoder(ctx, err, deliv, ch, pub)
}
