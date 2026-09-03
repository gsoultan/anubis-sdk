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

// BUDGET: ~50 µs and NO I/O (docs/architecture.md). Every consuming service
// runs this on every request, so a regression here is a regression
// everywhere at once — which is exactly why the SDK is zero-dependency and
// verification never touches the network.
func BenchmarkVerify(b *testing.B) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	doc, _ := json.Marshal(keys.Document{Keys: []keys.Entry{{
		Kid: "k1", Alg: "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(pk),
	}}})
	set, err := keys.ParseDocument(doc, "")
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	v, err := NewVerifier(Config{
		Issuer: "https://anubis.test", Audience: "billing-api", StaticKeys: set,
		now: func() time.Time { return now },
	})
	if err != nil {
		b.Fatal(err)
	}
	body, _ := json.Marshal(Claims{
		Issuer: "https://anubis.test", Subject: "usr_1", Audience: []string{"billing-api"},
		Expires: now.Add(10 * time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Unix(),
		Tenant: "tnt", Session: "ses", Roles: Roles{"finance.approver"},
		Scopes: Scopes{"org": "01a0", "product": "01a1"}, Version: 1,
	})
	token, _ := paseto.Sign(sk, body, []byte(`{"kid":"k1"}`), nil)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

// Signing is Anubis-side only, but it sits on the login and refresh paths.
func BenchmarkSign(b *testing.B) {
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"iss":"https://anubis.test","sub":"usr_1","exp":1735689600}`)
	footer := []byte(`{"kid":"k1"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := paseto.Sign(sk, body, footer, nil); err != nil {
			b.Fatal(err)
		}
	}
}
