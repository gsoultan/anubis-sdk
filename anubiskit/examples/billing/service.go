// Package billing is a go-kit service integrated with Anubis.
//
// It is deliberately transport-free. The same Service and the same Endpoints
// are served over HTTP, gRPC and AMQP by the three sibling packages, and none
// of the authentication or authorization is written three times — that is what
// it means for the endpoint layer to be where cross-cutting concerns live.
//
// Nothing in this file mentions HTTP, tokens or permissions. An integration
// that forces business code to unpack an Authorization header has broken the
// layering it was supposed to respect.
package billing

import (
	"context"
	"errors"
	"sync"

	anubis "github.com/gsoultan/anubis-sdk"
)

// Invoice is scoped on two axes. Which axes exist is a property of the domain,
// which is why the scope set for a decision is derived from the loaded record
// rather than from the URL it arrived on.
type Invoice struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	CustomerID string `json:"customer_id"`
	Amount     int64  `json:"amount"`
	Approved   bool   `json:"approved"`
	ApprovedBy string `json:"approved_by,omitempty"`
}

var ErrNotFound = errors.New("invoice not found")

type ListRequest struct {
	OrgID string
}

type ListResponse struct {
	Invoices []Invoice `json:"invoices"`
}

type ApproveRequest struct {
	InvoiceID string
}

type ApproveResponse struct {
	Invoice Invoice `json:"invoice"`
}

type Service interface {
	List(ctx context.Context, req ListRequest) (ListResponse, error)
	Approve(ctx context.Context, req ApproveRequest) (ApproveResponse, error)
	// Load resolves an invoice. The endpoint layer calls it before asking
	// Anubis, because the axes a decision needs live on the record.
	Load(ctx context.Context, id string) (Invoice, error)
}

type service struct {
	mu       sync.RWMutex
	invoices map[string]Invoice
}

func NewService() Service {
	return &service{invoices: map[string]Invoice{
		"inv-1": {ID: "inv-1", OrgID: "org-north", CustomerID: "cust-acme", Amount: 50_000},
		"inv-2": {ID: "inv-2", OrgID: "org-south", CustomerID: "cust-globex", Amount: 12_500},
	}}
}

func (s *service) Load(_ context.Context, id string) (Invoice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.invoices[id]
	if !ok {
		return Invoice{}, ErrNotFound
	}
	return inv, nil
}

func (s *service) List(_ context.Context, req ListRequest) (ListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ListResponse{Invoices: []Invoice{}}
	for _, inv := range s.invoices {
		if req.OrgID == "" || inv.OrgID == req.OrgID {
			out.Invoices = append(out.Invoices, inv)
		}
	}
	return out, nil
}

// Approve runs only if the endpoint layer already established that it may.
//
// It still reads the principal — not to decide anything, but to record who
// approved. That is what the context carries a principal for: identity is
// useful to business code, authorization is not its job.
func (s *service) Approve(ctx context.Context, req ApproveRequest) (ApproveResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invoices[req.InvoiceID]
	if !ok {
		return ApproveResponse{}, ErrNotFound
	}
	inv.Approved = true
	// The identity, not the claim set: who approved is a domain fact, and the
	// SDK already turned the token into something that says so.
	if id, ok := anubis.IdentityFromContext(ctx); ok {
		inv.ApprovedBy = id.Subject.String()
	}
	s.invoices[req.InvoiceID] = inv
	return ApproveResponse{Invoice: inv}, nil
}
