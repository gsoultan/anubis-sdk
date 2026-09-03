package anubiskit

import (
	"context"
	"errors"
	"strings"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	anubis "github.com/gsoultan/anubis-sdk"
)

// AuthorizationMD is the metadata key gRPC carries the credential in. Lower
// case because gRPC normalises metadata keys, and a caller who sets
// "Authorization" and a server who reads "authorization" must find each other.
const AuthorizationMD = "authorization"

// Trailer keys for the machine-readable part of a refusal.
//
// gRPC's status carries a code and a message; anything structured goes in
// details, and details are proto messages. Rather than make every consumer
// generate a proto to read "which axis failed", the detail rides in trailer
// metadata — which any gRPC client can read without a schema.
const (
	TrailerError       = "anubis-error"
	TrailerFailingAxis = "anubis-failing-axis"
	TrailerRequiredAMR = "anubis-required-amr"
	TrailerMaxAuthAge  = "anubis-max-auth-age"
	TrailerRequestID   = "anubis-request-id"
)

// GRPCToContext moves the authorization metadata into the context.
//
// Wire it with grpctransport.ServerBefore. Like its HTTP sibling it verifies
// nothing: carrying the credential inward is the transport's job, and deciding
// what it means is the endpoint layer's, which is what lets one service speak
// three protocols with one authentication rule.
func GRPCToContext() grpctransport.ServerRequestFunc {
	return func(ctx context.Context, md metadata.MD) context.Context {
		for _, value := range md.Get(AuthorizationMD) {
			if token, ok := bearer(value); ok {
				return context.WithValue(ctx, BearerTokenContextKey, token)
			}
		}
		return ctx
	}
}

// ContextToGRPC puts the credential on an outgoing call, for a service calling
// another service on the caller's behalf.
//
// The forwarded token keeps its original audience, so the receiving service —
// which pins its own — refuses it unless it was minted for that service. That
// is the behaviour you want: forwarding authority should not silently widen it.
func ContextToGRPC() grpctransport.ClientRequestFunc {
	return func(ctx context.Context, md *metadata.MD) context.Context {
		if token, ok := ctx.Value(BearerTokenContextKey).(string); ok && token != "" {
			md.Set(AuthorizationMD, "Bearer "+token)
		}
		return ctx
	}
}

// GRPCCode maps an SDK error to its gRPC status code.
//
// The mapping is the one Anubis itself uses on its own Connect transport, so a
// service behind Anubis refuses in the same vocabulary Anubis does.
//
// Note that gRPC has no equivalent of the 401/403 split: Unauthenticated means
// "we do not know who you are or your credential is not good enough" and
// PermissionDenied means "we know, and no". A step-up refusal is therefore
// Unauthenticated — the caller can still fix it — and a denial is
// PermissionDenied.
func GRPCCode(err error) codes.Code {
	var stepUp *anubis.StepUpRequiredError
	var denied *anubis.DeniedError
	var auth *anubis.AuthError
	var limited *anubis.RateLimitedError
	var down *anubis.UnavailableError

	switch {
	case errors.As(err, &stepUp):
		return codes.Unauthenticated
	case errors.As(err, &denied):
		return codes.PermissionDenied
	case errors.As(err, &auth):
		return codes.Unauthenticated
	case errors.As(err, &limited):
		return codes.ResourceExhausted
	case errors.As(err, &down):
		return codes.Unavailable
	case errors.Is(err, ErrTokenContextMissing),
		errors.Is(err, anubis.ErrExpired),
		errors.Is(err, anubis.ErrAudience),
		errors.Is(err, anubis.ErrIssuer),
		errors.Is(err, anubis.ErrNotYetValid),
		errors.Is(err, anubis.ErrUnknownKid):
		return codes.Unauthenticated
	default:
		return codes.Internal
	}
}

// GRPCError converts a refusal into a gRPC status error, attaching the
// machine-readable detail as trailer metadata.
//
// Call it where the generated handler returns:
//
//	func (s *grpcServer) Approve(ctx context.Context, r *pb.ApproveRequest) (*pb.ApproveResponse, error) {
//	    _, resp, err := s.approve.ServeGRPC(ctx, r)
//	    if err != nil {
//	        return nil, anubiskit.GRPCError(ctx, err)
//	    }
//	    return resp.(*pb.ApproveResponse), nil
//	}
//
// The message stays deliberately vague on an authentication failure. "Expired"
// versus "wrong audience" versus "unknown key" is a map of the verification
// rules, drawn for whoever is probing them; the trailer says which class of
// refusal it was, which is all a legitimate caller needs.
func GRPCError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	code := GRPCCode(err)
	md := metadata.MD{}
	message := "authentication required"

	var stepUp *anubis.StepUpRequiredError
	var denied *anubis.DeniedError
	var limited *anubis.RateLimitedError
	var api *anubis.APIError

	switch {
	case errors.As(err, &stepUp):
		message = "stronger authentication is required for this action"
		md.Set(TrailerError, "step_up_required")
		if len(stepUp.RequiredAMR) > 0 {
			md.Set(TrailerRequiredAMR, strings.Join(stepUp.RequiredAMR.Strings(), " "))
		}
		if stepUp.MaxAuthAge != "" {
			md.Set(TrailerMaxAuthAge, stepUp.MaxAuthAge)
		}
	case errors.As(err, &denied):
		message = denied.Message
		if message == "" {
			message = "not permitted"
		}
		md.Set(TrailerError, denied.Reason)
		if denied.FailingAxis != "" {
			md.Set(TrailerFailingAxis, string(denied.FailingAxis))
		}
	case errors.As(err, &limited):
		message = "slow down"
		md.Set(TrailerError, "rate_limited")
	case code == codes.Unavailable:
		message = "authorization is unavailable"
		md.Set(TrailerError, "unavailable")
	case code == codes.Unauthenticated:
		md.Set(TrailerError, "unauthenticated")
	default:
		message = "internal error"
		md.Set(TrailerError, "internal")
	}

	if errors.As(err, &api) && api.RequestID != "" {
		md.Set(TrailerRequestID, api.RequestID)
	}
	// Best effort: outside a unary handler there is no stream to attach to,
	// and a missing trailer must not turn a clean refusal into an error about
	// reporting the refusal.
	_ = grpc.SetTrailer(ctx, md)

	return status.Error(code, message)
}
