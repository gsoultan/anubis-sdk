package billing

import (
	"context"

	"github.com/go-kit/kit/endpoint"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/anubiskit"
)

// Endpoints is the wired endpoint set.
type Endpoints struct {
	List    endpoint.Endpoint
	Approve endpoint.Endpoint
}

// MakeEndpoints attaches authentication and authorization where they belong:
// once, at the endpoint layer, in front of every transport the service speaks.
//
// Read the Approve chain outside in. Authenticate establishes who is calling.
// loadInvoice resolves the record, because the axes a decision needs live on
// it. Authorize then asks. Only if all three pass does the service run.
func MakeEndpoints(svc Service, v *anubis.Verifier, c *anubis.Client) Endpoints {
	authenticate := anubiskit.Authenticate(v)

	return Endpoints{
		// Listing needs a caller, not a decision: the service filters to what
		// the request asked for and the rows themselves are not privileged.
		List: authenticate(makeListEndpoint(svc)),

		Approve: authenticate(
			loadInvoice(svc)(
				anubiskit.Authorize(c, "billing:invoice:approve", ScopesOfInvoice)(
					makeApproveEndpoint(svc)))),
	}
}

type invoiceKey struct{}

// loadInvoice resolves the record the request names and puts it in the context.
//
// This middleware exists because of an ordering problem every real
// authorization has: you cannot ask "may they approve this invoice" until you
// know which organisation and customer the invoice belongs to, and that is a
// lookup. Doing it in the transport decoder would put a database call in a
// function whose job is to parse bytes; doing it inside the service would put
// the decision after the work had started.
func loadInvoice(svc Service) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request any) (any, error) {
			req, ok := request.(ApproveRequest)
			if !ok {
				return next(ctx, request)
			}
			inv, err := svc.Load(ctx, req.InvoiceID)
			if err != nil {
				return nil, err
			}
			return next(context.WithValue(ctx, invoiceKey{}, inv), request)
		}
	}
}

// ScopesOfInvoice supplies every axis the action touches.
//
// Both of them, always. On a strict axis an omitted axis is DENIED, not
// ignored — so a forgotten axis here surfaces as a permissions bug that is
// really a bug in this function.
func ScopesOfInvoice(ctx context.Context, _ any) anubis.Scopes {
	inv, ok := ctx.Value(invoiceKey{}).(Invoice)
	if !ok {
		// Returning nothing is the safe failure: with no axes supplied a
		// strict grant refuses, which is the answer we want when we could not
		// work out what was being asked about.
		return nil
	}
	return anubis.Scopes{"org": inv.OrgID, "customer": inv.CustomerID}
}

func makeListEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		return svc.List(ctx, request.(ListRequest))
	}
}

func makeApproveEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		return svc.Approve(ctx, request.(ApproveRequest))
	}
}
