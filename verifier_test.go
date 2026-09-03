package anubis

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/gsoultan/anubis-sdk/keys"
	"github.com/gsoultan/anubis-sdk/paseto"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *keys.Set) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(keys.Document{Keys: []keys.Entry{{
		Kid: "k1", Alg: "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(pk),
	}}})
	ks, err := keys.ParseDocument(doc, "")
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk, ks
}

func mint(t *testing.T, sk ed25519.PrivateKey, c Claims) string {
	t.Helper()
	body, _ := json.Marshal(c)
	tok, err := paseto.Sign(sk, body, []byte(`{"kid":"k1"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func baseClaims(now time.Time) Claims {
	return Claims{
		Issuer: "https://anubis.test", Subject: "usr_1", Audience: []string{"billing-api"},
		Expires: now.Add(10 * time.Minute).Unix(), IssuedAt: now.Unix(),
		NotBefore: now.Unix(), Tenant: "tnt_1", Session: "ses_1", Version: 1,
	}
}

func newTestVerifier(t *testing.T, ks *keys.Set, aud string, now time.Time) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{
		Issuer: "https://anubis.test", Audience: aud, StaticKeys: ks,
		now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyHappyPath(t *testing.T) {
	_, sk, ks := testKeys(t)
	now := time.Now()
	v := newTestVerifier(t, ks, "billing-api", now)

	claims, err := v.Verify(context.Background(), mint(t, sk, baseClaims(now)))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "usr_1" || claims.Tenant != "tnt_1" {
		t.Errorf("claims: %+v", claims)
	}
}

func TestAudienceIsMandatory(t *testing.T) {
	_, _, ks := testKeys(t)
	if _, err := NewVerifier(Config{Issuer: "x", StaticKeys: ks}); err != ErrNoAudience {
		t.Fatalf("verifier without audience must refuse to construct, got %v", err)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	// The confused-deputy case: a token minted for billing-api presented to
	// payments-api must be rejected even though the signature is valid.
	_, sk, ks := testKeys(t)
	now := time.Now()
	v := newTestVerifier(t, ks, "payments-api", now)
	if _, err := v.Verify(context.Background(), mint(t, sk, baseClaims(now))); err != ErrAudience {
		t.Fatalf("want ErrAudience, got %v", err)
	}
}

func TestExpiryAndNbf(t *testing.T) {
	_, sk, ks := testKeys(t)
	now := time.Now()
	v := newTestVerifier(t, ks, "billing-api", now)

	expired := baseClaims(now)
	expired.Expires = now.Add(-5 * time.Minute).Unix()
	if _, err := v.Verify(context.Background(), mint(t, sk, expired)); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}

	future := baseClaims(now)
	future.NotBefore = now.Add(5 * time.Minute).Unix()
	if _, err := v.Verify(context.Background(), mint(t, sk, future)); err != ErrNotYetValid {
		t.Fatalf("want ErrNotYetValid, got %v", err)
	}

	// within leeway: 30s early is tolerated (clock skew)
	slightly := baseClaims(now)
	slightly.NotBefore = now.Add(30 * time.Second).Unix()
	if _, err := v.Verify(context.Background(), mint(t, sk, slightly)); err != nil {
		t.Fatalf("30s skew should be inside the 60s leeway: %v", err)
	}
}

func TestUnknownKidRejectedWithZeroIO(t *testing.T) {
	_, sk, ks := testKeys(t)
	now := time.Now()
	v := newTestVerifier(t, ks, "billing-api", now)

	body, _ := json.Marshal(baseClaims(now))
	tok, _ := paseto.Sign(sk, body, []byte(`{"kid":"nope"}`), nil)
	if _, err := v.Verify(context.Background(), tok); err != ErrUnknownKid {
		t.Fatalf("want ErrUnknownKid, got %v", err)
	}
}
