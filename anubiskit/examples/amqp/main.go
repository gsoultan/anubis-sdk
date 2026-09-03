package main

import (
	"log"
	"os"

	amqp "github.com/rabbitmq/amqp091-go"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
)

// Run it against a real broker and installation:
//
//	AMQP_URL=amqp://guest:guest@localhost:5672/ \
//	ANUBIS_URL=https://anubis.internal ANUBIS_APP=billing-worker \
//	ANUBIS_API_KEY=anb_live_… go run ./anubiskit/examples/amqp
func main() {
	endpoints, err := build(
		env("ANUBIS_URL", "https://anubis.internal"),
		env("ANUBIS_APP", "billing-worker"),
		os.Getenv("ANUBIS_API_KEY"),
		env("ANUBIS_TENANT", "impack"),
	)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := amqp.Dial(env("AMQP_URL", "amqp://guest:guest@localhost:5672/"))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	channel, err := conn.Channel()
	if err != nil {
		log.Fatal(err)
	}
	defer channel.Close()

	queue, err := channel.QueueDeclare("billing.approve", true, false, false, false, nil)
	if err != nil {
		log.Fatal(err)
	}
	// autoAck is false, and must be: the whole point of the error encoder is
	// deciding whether a failed message goes back on the queue, and an
	// auto-acknowledged message is already gone by the time it fails.
	deliveries, err := channel.Consume(queue.Name, "billing-worker", false, false, false, false, nil)
	if err != nil {
		log.Fatal(err)
	}

	serve := NewSubscriber(endpoints).ServeDelivery(channel)
	log.Println("consuming", queue.Name)
	for delivery := range deliveries {
		serve(&delivery)
	}
}

func build(anubisURL, slug, apiKey, tenant string) (billing.Endpoints, error) {
	verifier, err := anubis.NewVerifier(anubis.Config{
		Issuer:   anubisURL,
		Audience: slug, // the aud the publisher's token must have been minted for
		KeysURL:  anubisURL + "/.well-known/anubis-keys.json",
	})
	if err != nil {
		return billing.Endpoints{}, err
	}
	client, err := anubis.New(anubisURL,
		anubis.WithApplication(slug, ""),
		anubis.WithAPIKey(apiKey),
		anubis.WithTenant(tenant),
	)
	if err != nil {
		return billing.Endpoints{}, err
	}
	return billing.MakeEndpoints(billing.NewService(), verifier, client), nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
