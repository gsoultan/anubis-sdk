package paseto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// Official v4 test vectors from github.com/paseto-standard/test-vectors
// (v4.json). The PAE golden vectors pin the signed byte layout; these pin the
// whole token, so a token minted here verifies in every other PASETO library
// and the other way round.
const (
	specPublicKey = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	specSecretKey = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774" + specPublicKey
	specPayload   = `{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`
	specFooter    = `{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`
)

var specSign = []struct {
	name, token, footer, implicit string
}{
	{
		name:  "4-S-1",
		token: "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
	},
	{
		name:   "4-S-2",
		token:  "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
		footer: specFooter,
	},
	{
		name:     "4-S-3",
		token:    "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
		footer:   specFooter,
		implicit: `{"test-vector":"4-S-3"}`,
	},
}

func specKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pk, err := hex.DecodeString(specPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := hex.DecodeString(specSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk
}

// Ed25519 is deterministic, so signing the vector's inputs must reproduce the
// vector's token byte for byte, and the vector's token must verify.
func TestSpecVectorsSign(t *testing.T) {
	pk, sk := specKeys(t)
	for _, v := range specSign {
		t.Run(v.name, func(t *testing.T) {
			got, err := Sign(sk, []byte(specPayload), []byte(v.footer), []byte(v.implicit))
			if err != nil {
				t.Fatal(err)
			}
			if got != v.token {
				t.Fatalf("sign mismatch\n got  %s\n want %s", got, v.token)
			}
			m, f, err := Verify(pk, v.token, []byte(v.implicit))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if string(m) != specPayload || string(f) != v.footer {
				t.Fatalf("decoded (%q, %q)", m, f)
			}
		})
	}
}

// The expect-fail vectors that reach a v4.public verifier: a v4.local token,
// a v3 token, and a v4.public token signed with the wrong key.
func TestSpecVectorsFail(t *testing.T) {
	pk, _ := specKeys(t)
	fails := []struct{ name, token, implicit string }{
		{"4-F-1", "v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlNdGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24", `{"test-vector":"4-F-1"}`},
		{"4-F-2", "v4.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn22Sp4gjCaUw0c7EH84ZSm_jN_Qr41MrgLNu5LIBCzUr1pn3Z-Wukg9h3ceplWigpoHaTLcwxj0NsI1vjTh67YB.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", `{"test-vector":"4-F-2"}`},
		{"4-F-3", "v3.local.23e_2PiqpQBPvRFKzB0zHhjmxK3sKo2grFZRRLM-U7L0a8uHxuF9RlVz3Ic6WmdUUWTxCaYycwWV1yM8gKbZB2JhygDMKvHQ7eBf8GtF0r3K0Q_gF1PXOxcOgztak1eD1dPe9rLVMSgR0nHJXeIGYVuVrVoLWQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24", `{"test-vector":"4-F-3"}`},
	}
	for _, v := range fails {
		t.Run(v.name, func(t *testing.T) {
			if _, _, err := Verify(pk, v.token, []byte(v.implicit)); err == nil {
				t.Fatal("expect-fail vector verified")
			}
		})
	}
}
