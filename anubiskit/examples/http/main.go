package main

import (
	"log"
	"net/http"
	"os"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
)

// Run it against a real installation:
//
//	ANUBIS_URL=https://anubis.internal \
//	ANUBIS_APP=billing-api \
//	ANUBIS_API_KEY=anb_live_… \
//	go run ./anubiskit/examples/http
func main() {
	handler, err := build(
		env("ANUBIS_URL", "https://anubis.internal"),
		env("ANUBIS_APP", "billing-api"),
		os.Getenv("ANUBIS_API_KEY"),
		env("ANUBIS_TENANT", "impack"),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

func build(anubisURL, slug, apiKey, tenant string) (http.Handler, error) {
	// Offline verification. Audience is this service's own slug — without it,
	// a token minted for another service is accepted here.
	verifier, err := anubis.NewVerifier(anubis.Config{
		Issuer:   anubisURL,
		Audience: slug,
		KeysURL:  anubisURL + "/.well-known/anubis-keys.json",
	})
	if err != nil {
		return nil, err
	}

	// Decisions. The tenant api key is this service's own credential for
	// asking about its users.
	client, err := anubis.New(anubisURL,
		anubis.WithApplication(slug, ""),
		anubis.WithAPIKey(apiKey),
		anubis.WithTenant(tenant),
	)
	if err != nil {
		return nil, err
	}

	return MakeHTTPHandler(billing.MakeEndpoints(billing.NewService(), verifier, client)), nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
