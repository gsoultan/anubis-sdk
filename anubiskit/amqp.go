package anubiskit

import (
	"context"
	"errors"

	amqptransport "github.com/go-kit/kit/transport/amqp"
	amqp "github.com/rabbitmq/amqp091-go"

	anubis "github.com/gsoultan/anubis-sdk"
)

// AuthorizationHeader is the AMQP header the credential travels in. AMQP has
// no notion of an Authorization header, so this is a convention — but it is
// the same word, so nobody has to learn a second one.
const AuthorizationHeader = "authorization"

// AMQPToContext moves the credential from the delivery's headers into the
// context.
//
// Wire it with amqptransport.SubscriberBefore. A message is not a request from
// a browser: whatever published it authenticated once, usually with client
// credentials, and put the resulting token here. The queue is not the
// authority — a message that arrived is not thereby authorised, which is the
// whole reason this exists rather than trusting the exchange.
func AMQPToContext() amqptransport.RequestFunc {
	return func(ctx context.Context, _ *amqp.Publishing, deliv *amqp.Delivery) context.Context {
		if deliv == nil || deliv.Headers == nil {
			return ctx
		}
		raw, ok := deliv.Headers[AuthorizationHeader]
		if !ok {
			return ctx
		}
		value, ok := raw.(string)
		if !ok {
			return ctx
		}
		if token, ok := bearer(value); ok {
			return context.WithValue(ctx, BearerTokenContextKey, token)
		}
		// Tolerate a bare token: an AMQP header has no scheme convention to
		// respect, and refusing a credential over its prefix helps nobody.
		if value != "" {
			return context.WithValue(ctx, BearerTokenContextKey, value)
		}
		return ctx
	}
}

// ContextToAMQP puts the credential on an outgoing publishing.
//
// Wire it with amqptransport.PublisherBefore, or call it when publishing by
// hand. Remember that a queued message may be consumed long after it was
// published: give the token enough life to survive the queue, or publish a
// client-credentials token the consumer can verify rather than a user's, which
// is short-lived by design.
func ContextToAMQP() amqptransport.RequestFunc {
	return func(ctx context.Context, pub *amqp.Publishing, _ *amqp.Delivery) context.Context {
		token, ok := ctx.Value(BearerTokenContextKey).(string)
		if !ok || token == "" || pub == nil {
			return ctx
		}
		if pub.Headers == nil {
			pub.Headers = amqp.Table{}
		}
		pub.Headers[AuthorizationHeader] = "Bearer " + token
		return ctx
	}
}

// Retryable reports whether repeating the work could succeed.
//
// This is the only question that matters when a message fails, and getting it
// backwards is expensive in both directions: requeue a permanent failure and
// the queue spins on it forever, dead-letter a transient one and you have
// thrown away work because a dependency blinked.
//
// A refused credential and a denial are permanent — a message does not become
// authorised by being delivered again. Anubis being unreachable, or rate
// limiting the consumer, is not.
func Retryable(err error) bool {
	var limited *anubis.RateLimitedError
	var down *anubis.UnavailableError
	return errors.As(err, &limited) || errors.As(err, &down)
}

// NackErrorEncoder answers a failed delivery by requeuing it only if repeating
// it could work.
//
// Wire it with amqptransport.SubscriberErrorEncoder. Permanent refusals are
// nacked without requeue, so they land in whatever dead-letter exchange the
// queue is configured with and a human can look at them; transient ones are
// requeued.
//
// go-kit's own DefaultErrorEncoder neither replies nor acks, which leaves the
// message in flight until the channel closes. That is a reasonable default for
// a library and a poor one for an authorization failure, which will never
// resolve itself.
func NackErrorEncoder(_ context.Context, err error, deliv *amqp.Delivery, _ amqptransport.Channel, _ *amqp.Publishing) {
	if deliv == nil {
		return
	}
	_ = deliv.Nack(false, Retryable(err))
}
