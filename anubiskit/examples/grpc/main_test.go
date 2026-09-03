package main

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit"
	pb "github.com/gsoultan/anubis-sdk/anubiskit/examples/grpc/pb"
	"github.com/gsoultan/anubis-sdk/anubistest"
)

const slug = "billing-api"

// start brings up an in-process Anubis and a real gRPC server in front of it,
// over a real socket. Calling ServeGRPC directly would exercise the middleware
// but not the metadata plumbing, and the metadata plumbing is the half of a
// gRPC integration that actually goes wrong.
func start(t *testing.T) (*anubistest.Server, pb.InvoicesClient) {
	t.Helper()
	an := anubistest.NewServer(t)

	server, err := build(an.URL, slug, "anb_live_ab12cd34_s3cr3t", "impack")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterInvoicesServer(srv, server)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///"+listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return an, pb.NewInvoicesClient(conn)
}

// authed puts the credential where gRPC carries it. In production this is
// anubiskit.ContextToGRPC on the calling side; here it is spelled out so the
// test asserts the metadata key the server actually reads.
func authed(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func token(an *anubistest.Server, subject anubis.SubjectID, amr ...anubis.AuthMethod) string {
	return an.MintToken(anubis.Claims{
		Subject: subject, Audience: []string{slug}, Session: "ses_1", AMR: amr,
	})
}

func TestNoCredentialIsUnauthenticated(t *testing.T) {
	_, client := start(t)
	var trailer metadata.MD

	_, err := client.List(context.Background(), &pb.ListRequest{}, grpc.Trailer(&trailer))

	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
	if got := trailer.Get(anubiskit.TrailerError); len(got) == 0 || got[0] != "unauthenticated" {
		t.Fatalf("trailer %s = %v", anubiskit.TrailerError, got)
	}
	// And it does not say which check failed: "expired" versus "wrong
	// audience" is a map of the verification rules for whoever is probing them.
	if msg := status.Convert(err).Message(); msg != "authentication required" {
		t.Errorf("message = %q, want it uninformative", msg)
	}
}

func TestTokenForAnotherServiceIsUnauthenticated(t *testing.T) {
	an, client := start(t)
	other := an.MintToken(anubis.Claims{Subject: "usr_1", Audience: []string{"hr-api"}})

	_, err := client.List(authed(context.Background(), other), &pb.ListRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated — the aud check stops the confused deputy", status.Code(err))
	}
}

func TestListNeedsNoDecision(t *testing.T) {
	an, client := start(t)

	res, err := client.List(authed(context.Background(), token(an, "usr_1", "pwd")),
		&pb.ListRequest{OrgId: "org-north"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.GetInvoices()) != 1 {
		t.Fatalf("got %d invoices, want 1", len(res.GetInvoices()))
	}
	if an.Calls["Authorize"] != 0 {
		t.Error("listing asked Anubis for a decision it does not need")
	}
}

func TestApproveSuppliesEveryAxisFromTheLoadedRecord(t *testing.T) {
	an, client := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	res, err := client.Approve(authed(context.Background(), token(an, "usr_1", "pwd", "otp")),
		&pb.ApproveRequest{InvoiceId: "inv-1"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !res.GetInvoice().GetApproved() || res.GetInvoice().GetApprovedBy() != "usr_1" {
		t.Fatalf("invoice = %v", res.GetInvoice())
	}

	// The same assertion the HTTP example makes, over a different transport
	// and the same endpoint code. That is the point of the layering.
	ask := an.LastAsk()
	if ask.Scopes["org"] != "org-north" || ask.Scopes["customer"] != "cust-acme" {
		t.Fatalf("scopes = %v, want both axes from the loaded invoice", ask.Scopes)
	}
	if len(ask.AMR) != 2 || ask.AuthTime == 0 {
		t.Fatalf("amr = %v, auth_time = %d — both must come off the token", ask.AMR, ask.AuthTime)
	}
}

func TestDenialIsPermissionDeniedAndNamesTheAxis(t *testing.T) {
	an, client := start(t)
	an.Deny("usr_1", "billing:invoice:approve", "scope_mismatch", "customer")
	var trailer metadata.MD

	_, err := client.Approve(authed(context.Background(), token(an, "usr_1", "pwd")),
		&pb.ApproveRequest{InvoiceId: "inv-1"}, grpc.Trailer(&trailer))

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %s, want PermissionDenied", status.Code(err))
	}
	if got := trailer.Get(anubiskit.TrailerError); len(got) == 0 || got[0] != "scope_mismatch" {
		t.Fatalf("trailer error = %v", got)
	}
	if got := trailer.Get(anubiskit.TrailerFailingAxis); len(got) == 0 || got[0] != "customer" {
		t.Fatalf("failing axis = %v — a deny that does not name the axis is a support ticket", got)
	}
}

// TestStepUpIsUnauthenticatedNotPermissionDenied pins the distinction gRPC
// makes. PermissionDenied means "we know who you are, and no"; Unauthenticated
// means the credential is not good enough — which is exactly what a step-up
// refusal says, and it is fixable.
func TestStepUpIsUnauthenticatedNotPermissionDenied(t *testing.T) {
	an, client := start(t)
	an.RequireStepUp("usr_1", "billing:invoice:approve", anubis.AuthMethods{anubis.MethodOTP}, "2m")
	var trailer metadata.MD

	_, err := client.Approve(authed(context.Background(), token(an, "usr_1", "pwd")),
		&pb.ApproveRequest{InvoiceId: "inv-1"}, grpc.Trailer(&trailer))

	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
	if got := trailer.Get(anubiskit.TrailerError); len(got) == 0 || got[0] != "step_up_required" {
		t.Fatalf("trailer error = %v", got)
	}
	if got := trailer.Get(anubiskit.TrailerRequiredAMR); len(got) == 0 || got[0] != "otp" {
		t.Fatalf("required amr = %v — the caller must not guess what 'stronger' means", got)
	}
	if got := trailer.Get(anubiskit.TrailerMaxAuthAge); len(got) == 0 || got[0] != "2m" {
		t.Fatalf("max auth age = %v", got)
	}
}

func TestUnknownInvoiceNeverReachesAnubis(t *testing.T) {
	an, client := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	_, err := client.Approve(authed(context.Background(), token(an, "usr_1", "pwd")),
		&pb.ApproveRequest{InvoiceId: "nope"})

	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %s, want NotFound", status.Code(err))
	}
	if an.Calls["Authorize"] != 0 {
		t.Error("asked Anubis about an invoice that does not exist")
	}
}

// TestContextToGRPCRoundTrips checks the forwarding side: a service calling a
// service on the caller's behalf puts the token back on the wire in the key
// the receiving server reads.
func TestContextToGRPCRoundTrips(t *testing.T) {
	an, client := start(t)
	an.Allow("usr_1", "billing:invoice:approve")

	// As if an inbound request had left the credential in the context.
	ctx := anubis.WithPrincipal(context.Background(), &anubis.Principal{})
	ctx = context.WithValue(ctx, anubiskit.BearerTokenContextKey, token(an, "usr_1", "pwd"))

	md := metadata.MD{}
	ctx = anubiskit.ContextToGRPC()(ctx, &md)
	ctx = metadata.NewOutgoingContext(ctx, md)

	if _, err := client.Approve(ctx, &pb.ApproveRequest{InvoiceId: "inv-1"}); err != nil {
		t.Fatalf("a forwarded credential was not accepted: %v", err)
	}
}
