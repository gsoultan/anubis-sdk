package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
	pb "github.com/gsoultan/anubis-sdk/anubiskit/examples/grpc/pb"
)

// Run it against a real installation:
//
//	ANUBIS_URL=https://anubis.internal ANUBIS_APP=billing-api \
//	ANUBIS_API_KEY=anb_live_… go run ./anubiskit/examples/grpc
func main() {
	server, err := build(
		env("ANUBIS_URL", "https://anubis.internal"),
		env("ANUBIS_APP", "billing-api"),
		os.Getenv("ANUBIS_API_KEY"),
		env("ANUBIS_TENANT", "impack"),
	)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", ":8082")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterInvoicesServer(grpcServer, server)
	log.Println("listening on :8082")
	log.Fatal(grpcServer.Serve(listener))
}

func build(anubisURL, slug, apiKey, tenant string) (pb.InvoicesServer, error) {
	verifier, err := anubis.NewVerifier(anubis.Config{
		Issuer:   anubisURL,
		Audience: slug, // without it, a token minted for another service is accepted here
		KeysURL:  anubisURL + "/.well-known/anubis-keys.json",
	})
	if err != nil {
		return nil, err
	}
	client, err := anubis.New(anubisURL,
		anubis.WithApplication(slug, ""),
		anubis.WithAPIKey(apiKey),
		anubis.WithTenant(tenant),
	)
	if err != nil {
		return nil, err
	}
	return NewGRPCServer(billing.MakeEndpoints(billing.NewService(), verifier, client)), nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
