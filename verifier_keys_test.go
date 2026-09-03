package anubis

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/anubis-sdk/keys"
)

func TestKeysURLMustBeIntegrityProtected(t *testing.T) {
	for _, tc := range []struct {
		name, url string
		wantErr   bool
	}{
		{name: "https", url: "https://anubis.internal/.well-known/anubis-keys.json"},
		{name: "loopback v4", url: "http://127.0.0.1:8080/.well-known/anubis-keys.json"},
		{name: "loopback v6", url: "http://[::1]:8080/.well-known/anubis-keys.json"},
		{name: "localhost", url: "http://localhost:8080/.well-known/anubis-keys.json"},
		{name: "plaintext over the network", url: "http://anubis.internal/keys.json", wantErr: true},
		{name: "private range is still plaintext", url: "http://10.0.0.7/keys.json", wantErr: true},
		{name: "not a fetchable scheme", url: "file:///etc/anubis/keys.json", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(Config{
				Issuer: "https://anubis.test", Audience: "billing-api", KeysURL: tc.url,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewVerifier(%q) err = %v, wantErr %v", tc.url, err, tc.wantErr)
			}
		})
	}
}

// A key past its published not_after must stop verifying tokens, even ones
// minted while it was still current. That is what makes the window a
// revocation mechanism rather than documentation.
func TestVerifierRejectsKeyOutsideItsWindow(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	entry := keys.Entry{
		Kid: "k1", Alg: "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(pk),
		NotAfter:  now.Add(-time.Minute).Unix(),
	}
	raw, _ := json.Marshal(keys.Document{Keys: []keys.Entry{entry}})
	ks, err := keys.ParseDocument(raw, "")
	if err != nil {
		t.Fatal(err)
	}

	v := newTestVerifier(t, ks, "billing-api", now)
	// The token itself is entirely valid; only the key has been retired.
	if _, err := v.Verify(context.Background(), mint(t, sk, baseClaims(now))); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("retired key still verifies: err = %v, want ErrUnknownKid", err)
	}
}

// roundTripper lets the test stand in for a private CA without one.
type roundTripper struct {
	body  []byte
	calls int
}

func (rt *roundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	rt.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(rt.body))),
		Header:     make(http.Header),
	}, nil
}

// An .internal deployment's chain is not in the system pool, so the verifier
// has to accept a client the caller configured.
func TestVerifierFetchesKeysWithInjectedClient(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(keys.Document{
		Issuer: "https://anubis.test",
		Keys: []keys.Entry{{
			Kid: "k1", Alg: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(pk),
		}},
	})
	rt := &roundTripper{body: raw}

	now := time.Now()
	v, err := NewVerifier(Config{
		Issuer:     "https://anubis.test",
		Audience:   "billing-api",
		KeysURL:    "https://anubis.internal/.well-known/anubis-keys.json",
		HTTPClient: &http.Client{Transport: rt},
		now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), mint(t, sk, baseClaims(now))); err != nil {
		t.Fatalf("verify through the injected client: %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("injected client saw %d requests, want 1", rt.calls)
	}
}

// The verifier's own issuer is what binds the fetched document to a
// deployment; pointing it at another one must fail loudly.
func TestVerifierRejectsKeysFromAnotherIssuer(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(keys.Document{
		Issuer: "https://staging.anubis.test",
		Keys: []keys.Entry{{
			Kid: "k1", Alg: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(pk),
		}},
	})

	now := time.Now()
	v, err := NewVerifier(Config{
		Issuer:     "https://anubis.test",
		Audience:   "billing-api",
		KeysURL:    "https://anubis.internal/.well-known/anubis-keys.json",
		HTTPClient: &http.Client{Transport: &roundTripper{body: raw}},
		now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), mint(t, sk, baseClaims(now)))
	if err == nil {
		t.Fatal("accepted a keys document from another deployment")
	}
	if !strings.Contains(err.Error(), "issued by") {
		t.Fatalf("err = %v, want the issuer mismatch", err)
	}
}
