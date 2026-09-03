// Command grpc serves the billing service over gRPC.
//
// The service and the endpoints are the same ones the HTTP and AMQP examples
// serve — package billing, unchanged. Only this file differs, which is the
// claim go-kit makes and the reason authentication and authorization are
// attached at the endpoint layer rather than in a transport interceptor.
package main

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/anubis-sdk/anubiskit"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
	pb "github.com/gsoultan/anubis-sdk/anubiskit/examples/grpc/pb"
)

type grpcServer struct {
	pb.UnimplementedInvoicesServer
	list    grpctransport.Handler
	approve grpctransport.Handler
}

// NewGRPCServer mounts the endpoint set.
//
// One option does the integration: ServerBefore lifts the credential out of
// the request metadata into the context. gRPC has no ServerErrorEncoder — the
// generated method returns the error itself — so the conversion happens in the
// two wrappers below.
func NewGRPCServer(e billing.Endpoints) pb.InvoicesServer {
	opts := []grpctransport.ServerOption{
		grpctransport.ServerBefore(anubiskit.GRPCToContext()),
	}
	return &grpcServer{
		list:    grpctransport.NewServer(e.List, decodeListRequest, encodeListResponse, opts...),
		approve: grpctransport.NewServer(e.Approve, decodeApproveRequest, encodeApproveResponse, opts...),
	}
}

func (s *grpcServer) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	_, resp, err := s.list.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(ctx, err)
	}
	return resp.(*pb.ListResponse), nil
}

func (s *grpcServer) Approve(ctx context.Context, req *pb.ApproveRequest) (*pb.ApproveResponse, error) {
	_, resp, err := s.approve.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(ctx, err)
	}
	return resp.(*pb.ApproveResponse), nil
}

// encodeError handles this service's own errors and defers everything else to
// the SDK's, which knows a step-up refusal from a denial and attaches the
// machine-readable detail as trailer metadata.
func encodeError(ctx context.Context, err error) error {
	if errors.Is(err, billing.ErrNotFound) {
		return status.Error(codes.NotFound, "invoice not found")
	}
	return anubiskit.GRPCError(ctx, err)
}

// ---- codecs ---------------------------------------------------------------
//
// Nothing below knows about tokens. Decoding is a translation between the wire
// type and the domain type, and an integration that made it also unpack a
// credential would have put transport concerns back into the service.

func decodeListRequest(_ context.Context, request any) (any, error) {
	r := request.(*pb.ListRequest)
	return billing.ListRequest{OrgID: r.GetOrgId()}, nil
}

func encodeListResponse(_ context.Context, response any) (any, error) {
	r := response.(billing.ListResponse)
	out := &pb.ListResponse{Invoices: make([]*pb.Invoice, 0, len(r.Invoices))}
	for _, inv := range r.Invoices {
		out.Invoices = append(out.Invoices, toProto(inv))
	}
	return out, nil
}

func decodeApproveRequest(_ context.Context, request any) (any, error) {
	r := request.(*pb.ApproveRequest)
	return billing.ApproveRequest{InvoiceID: r.GetInvoiceId()}, nil
}

func encodeApproveResponse(_ context.Context, response any) (any, error) {
	r := response.(billing.ApproveResponse)
	return &pb.ApproveResponse{Invoice: toProto(r.Invoice)}, nil
}

func toProto(inv billing.Invoice) *pb.Invoice {
	return &pb.Invoice{
		Id:         inv.ID,
		OrgId:      inv.OrgID,
		CustomerId: inv.CustomerID,
		Amount:     inv.Amount,
		Approved:   inv.Approved,
		ApprovedBy: inv.ApprovedBy,
	}
}
