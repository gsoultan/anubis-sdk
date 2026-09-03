// Package paseto implements PASETO v4.public — Ed25519-signed public tokens —
// over the standard library only (ADR-0002: format layers are hand-written,
// primitives never are).
//
// v4.public token layout:
//
//	v4.public.<b64url(message || signature)>[.<b64url(footer)>]
//
// where signature = Ed25519-Sign(sk, PAE([h, m, f, i])), h the header
// including trailing dot, m the message, f the footer ("" when absent) and i
// the implicit assertion. PAE is the spec's Pre-Authentication Encoding; it
// makes the signed byte string injective over its pieces, which is what stops
// a footer byte from being reinterpreted as a message byte.
package paseto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const headerV4Public = "v4.public."

var (
	ErrMalformed   = errors.New("paseto: malformed token")
	ErrWrongHeader = errors.New("paseto: not a v4.public token")
	ErrBadSig      = errors.New("paseto: signature verification failed")
	ErrKeySize     = errors.New("paseto: wrong key size")
)

var b64 = base64.RawURLEncoding.Strict()

// pae implements Pre-Authentication Encoding from the PASETO spec:
// LE64(count) || for each piece: LE64(len(piece)) || piece.
// LE64 encodes a uint64 little-endian with the most significant bit cleared.
func pae(pieces ...[]byte) []byte {
	size := 8
	for _, p := range pieces {
		size += 8 + len(p)
	}
	out := make([]byte, 0, size)
	out = le64(out, uint64(len(pieces)))
	for _, p := range pieces {
		out = le64(out, uint64(len(p)))
		out = append(out, p...)
	}
	return out
}

func le64(dst []byte, n uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n&0x7FFFFFFFFFFFFFFF)
	return append(dst, b[:]...)
}

// Sign produces a v4.public token over message with an optional footer and
// implicit assertion. The implicit assertion is authenticated but NOT carried
// in the token; both sides must agree on it out of band.
func Sign(sk ed25519.PrivateKey, message, footer, implicit []byte) (string, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return "", ErrKeySize
	}
	m2 := pae([]byte(headerV4Public), message, footer, implicit)
	sig := ed25519.Sign(sk, m2)

	var b strings.Builder
	b.WriteString(headerV4Public)
	b.WriteString(b64.EncodeToString(append(append([]byte{}, message...), sig...)))
	if len(footer) > 0 {
		b.WriteByte('.')
		b.WriteString(b64.EncodeToString(footer))
	}
	return b.String(), nil
}

// Parse splits a token without verifying it. Callers must treat the result as
// untrusted until Verify succeeds; it exists so the kid can be read from a
// footer to select a verification key.
func Parse(token string) (message, signature, footer []byte, err error) {
	if !strings.HasPrefix(token, headerV4Public) {
		return nil, nil, nil, ErrWrongHeader
	}
	rest := token[len(headerV4Public):]
	var bodyPart, footPart string
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		bodyPart, footPart = rest[:i], rest[i+1:]
		if footPart == "" || strings.IndexByte(footPart, '.') >= 0 {
			return nil, nil, nil, ErrMalformed
		}
	} else {
		bodyPart = rest
	}
	body, err := b64.DecodeString(bodyPart)
	if err != nil || len(body) < ed25519.SignatureSize {
		return nil, nil, nil, ErrMalformed
	}
	if footPart != "" {
		footer, err = b64.DecodeString(footPart)
		if err != nil {
			return nil, nil, nil, ErrMalformed
		}
	}
	n := len(body) - ed25519.SignatureSize
	return body[:n], body[n:], footer, nil
}

// Verify checks the token against pk and returns the message on success.
func Verify(pk ed25519.PublicKey, token string, implicit []byte) (message, footer []byte, err error) {
	if len(pk) != ed25519.PublicKeySize {
		return nil, nil, ErrKeySize
	}
	m, sig, f, err := Parse(token)
	if err != nil {
		return nil, nil, err
	}
	m2 := pae([]byte(headerV4Public), m, f, implicit)
	if !ed25519.Verify(pk, m2, sig) {
		return nil, nil, ErrBadSig
	}
	return m, f, nil
}
