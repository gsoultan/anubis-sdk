package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"

	"github.com/gsoultan/anubis-sdk/anubiskit"
	"github.com/gsoultan/anubis-sdk/anubiskit/examples/billing"
)

// MakeHTTPHandler mounts the endpoint set.
//
// Two options do the whole integration. ServerBefore lifts the credential off
// the wire into the context; ServerErrorEncoder turns the refusals that come
// back out into statuses and bodies. Between them the endpoint layer never sees
// an *http.Request and this file never sees a token.
func MakeHTTPHandler(e billing.Endpoints) http.Handler {
	opts := []httptransport.ServerOption{
		httptransport.ServerBefore(anubiskit.HTTPToContext()),
		httptransport.ServerErrorEncoder(errorEncoder),
	}

	mux := http.NewServeMux()
	mux.Handle("GET /invoices", httptransport.NewServer(
		e.List, decodeListRequest, encodeResponse, opts...))
	mux.Handle("POST /invoices/{id}/approve", httptransport.NewServer(
		e.Approve, decodeApproveRequest, encodeResponse, opts...))
	return mux
}

func decodeListRequest(_ context.Context, r *http.Request) (any, error) {
	return billing.ListRequest{OrgID: r.URL.Query().Get("org")}, nil
}

func decodeApproveRequest(_ context.Context, r *http.Request) (any, error) {
	return billing.ApproveRequest{InvoiceID: r.PathValue("id")}, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

// errorEncoder handles this service's own errors and defers everything else to
// the SDK's, which knows how a step-up refusal differs from a denial.
func errorEncoder(ctx context.Context, err error, w http.ResponseWriter) {
	if errors.Is(err, billing.ErrNotFound) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "not_found", "message": "invoice not found",
		})
		return
	}
	anubiskit.ErrorEncoder(ctx, err, w)
}
