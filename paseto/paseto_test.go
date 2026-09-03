package paseto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// PAE golden vectors from the PASETO specification (§2.2 Authentication
// Padding). These are computable by hand and pin the exact byte layout the
// signature covers — any drift here is a cross-implementation token break.
func TestPAEGolden(t *testing.T) {
	cases := []struct {
		name   string
		pieces [][]byte
		hex    string
	}{
		{"empty list", nil, "0000000000000000"},
		{"one empty string", [][]byte{{}}, "01000000000000000000000000000000"},
		{"test", [][]byte{[]byte("test")}, "0100000000000000040000000000000074657374"},
		{"two pieces", [][]byte{[]byte("test"), {}},
			"02000000000000000400000000000000746573740000000000000000"},
	}
	for _, c := range cases {
		got := pae(c.pieces...)
		want, _ := hex.DecodeString(c.hex)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: PAE = %x, want %x", c.name, got, want)
		}
	}
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk
}

func TestRoundTrip(t *testing.T) {
	pk, sk := keys(t)
	msg := []byte(`{"sub":"usr_1","exp":1735689600}`)

	for _, footer := range [][]byte{nil, []byte(`{"kid":"k1"}`)} {
		tok, err := Sign(sk, msg, footer, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, "v4.public.") {
			t.Fatalf("bad header: %s", tok)
		}
		m, f, err := Verify(pk, tok, nil)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !bytes.Equal(m, msg) {
			t.Errorf("message mismatch: %s", m)
		}
		if len(footer) > 0 && !bytes.Equal(f, footer) {
			t.Errorf("footer mismatch: %s", f)
		}
	}
}

func TestImplicitAssertionIsAuthenticated(t *testing.T) {
	pk, sk := keys(t)
	tok, _ := Sign(sk, []byte("m"), nil, []byte("tenant-a"))
	if _, _, err := Verify(pk, tok, []byte("tenant-a")); err != nil {
		t.Fatalf("matching implicit should verify: %v", err)
	}
	if _, _, err := Verify(pk, tok, []byte("tenant-b")); err != ErrBadSig {
		t.Fatalf("mismatched implicit must fail with ErrBadSig, got %v", err)
	}
}

func TestTamper(t *testing.T) {
	pk, sk := keys(t)
	tok, _ := Sign(sk, []byte(`{"sub":"alice"}`), []byte("f"), nil)

	// flip one character in the body
	raw := []rune(tok)
	i := len("v4.public.") + 3
	if raw[i] == 'A' {
		raw[i] = 'B'
	} else {
		raw[i] = 'A'
	}
	if _, _, err := Verify(pk, string(raw), nil); err == nil {
		t.Fatal("tampered body verified")
	}

	// swap the footer: the signature covers it via PAE
	m, sig, _, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	forged := "v4.public." + b64.EncodeToString(append(append([]byte{}, m...), sig...)) +
		"." + b64.EncodeToString([]byte("forged"))
	if _, _, err := Verify(pk, forged, nil); err != ErrBadSig {
		t.Fatalf("forged footer must fail signature, got %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	_, sk := keys(t)
	otherPk, _ := keys(t)
	tok, _ := Sign(sk, []byte("m"), nil, nil)
	if _, _, err := Verify(otherPk, tok, nil); err != ErrBadSig {
		t.Fatalf("want ErrBadSig, got %v", err)
	}
}

func TestMalformed(t *testing.T) {
	pk, _ := keys(t)
	for _, tok := range []string{
		"", "v4.public", "v4.local.abc", "v2.public.abc",
		"v4.public.", "v4.public.!!!!",
		"v4.public.AAAA",          // shorter than a signature
		"v4.public.AAAA.",         // empty footer part
		"v4.public.AAAA.BBBB.CCC", // two dots after body
	} {
		if _, _, err := Verify(pk, tok, nil); err == nil {
			t.Errorf("malformed token %q verified", tok)
		}
	}
}
