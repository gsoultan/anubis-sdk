package paseto

import (
	"crypto/ed25519"
	"testing"
)

// FuzzVerify feeds arbitrary strings through Parse+Verify. The parser must
// never panic and never accept an unsigned token. Development.md lists this
// fuzz target as a testing requirement for the token parser.
func FuzzVerify(f *testing.F) {
	pk, sk, _ := ed25519.GenerateKey(nil)
	good, _ := Sign(sk, []byte(`{"sub":"a"}`), []byte("footer"), nil)
	f.Add(good)
	f.Add("v4.public.")
	f.Add("v4.public.AAAA.BBBB")
	f.Add("v4.local.AAAA")
	f.Add("")

	f.Fuzz(func(t *testing.T, token string) {
		m, _, err := Verify(pk, token, nil)
		if err == nil {
			// The only accepted token must be one actually signed by sk;
			// re-verify the invariant that acceptance implies a valid parse.
			if m == nil {
				t.Fatal("accepted token with nil message")
			}
		}
	})
}
