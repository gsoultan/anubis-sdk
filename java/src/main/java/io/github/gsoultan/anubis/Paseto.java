package io.github.gsoultan.anubis;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * PASETO v4.public — Ed25519-signed tokens — over the JDK alone.
 *
 * <p>Token layout:
 *
 * <pre>v4.public.&lt;b64url(message || signature)&gt;[.&lt;b64url(footer)&gt;]</pre>
 *
 * <p>where signature = Ed25519-Sign(sk, PAE([h, m, f, i])). PAE is the spec's
 * Pre-Authentication Encoding; it makes the signed byte string injective over
 * its pieces, which is what stops a footer byte being reinterpreted as a
 * message byte.
 *
 * <p>The primitive is never hand-rolled — {@code Signature.getInstance("Ed25519")}
 * does the curve work. Only the format layer is written here.
 */
public final class Paseto {
    public static final String HEADER = "v4.public.";
    private static final int SIGNATURE_BYTES = 64;
    public static final int PUBLIC_KEY_BYTES = 32;

    /**
     * The fixed SubjectPublicKeyInfo prefix for an Ed25519 key.
     *
     * <p>The key document publishes 32 raw bytes, and X509EncodedKeySpec wants
     * SPKI. Prepending this constant header is exact rather than approximate:
     * the DER is fully determined for a key of this algorithm and length.
     */
    private static final byte[] SPKI_PREFIX = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    private Paseto() {}

    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    public static byte[] b64urlDecode(String s) {
        try {
            return URL_DECODER.decode(s);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("anubis: malformed token");
        }
    }

    public static String b64urlEncode(byte[] raw) {
        return URL_ENCODER.encodeToString(raw);
    }

    /** LE64 with the most significant bit cleared, per the specification. */
    private static byte[] le64(long n) {
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(n & 0x7FFFFFFFFFFFFFFFL).array();
    }

    public static byte[] pae(byte[]... pieces) {
        int size = 8;
        for (byte[] p : pieces) {
            size += 8 + p.length;
        }
        ByteBuffer out = ByteBuffer.allocate(size);
        out.put(le64(pieces.length));
        for (byte[] p : pieces) {
            out.put(le64(p.length));
            out.put(p);
        }
        return out.array();
    }

    /** A token split into its parts, before or after verification. */
    public record Parsed(byte[] message, byte[] signature, byte[] footer) {
        public String messageString() {
            return new String(message, StandardCharsets.UTF_8);
        }

        public String footerString() {
            return new String(footer, StandardCharsets.UTF_8);
        }
    }

    /**
     * Split a token WITHOUT verifying it.
     *
     * <p>The result is untrusted until {@link #verify} succeeds. It exists so
     * the kid can be read from the footer to select a key — a read that may
     * only ever index a bounded, already-loaded map.
     */
    public static Parsed parse(String token) {
        if (token == null || !token.startsWith(HEADER)) {
            throw new VerificationException("anubis: not a v4.public token");
        }
        String rest = token.substring(HEADER.length());
        String bodyPart = rest;
        String footerPart = "";
        int dot = rest.indexOf('.');
        if (dot >= 0) {
            bodyPart = rest.substring(0, dot);
            footerPart = rest.substring(dot + 1);
            if (footerPart.isEmpty() || footerPart.indexOf('.') >= 0) {
                throw new VerificationException("anubis: malformed token");
            }
        }
        byte[] body = b64urlDecode(bodyPart);
        if (body.length < SIGNATURE_BYTES) {
            throw new VerificationException("anubis: malformed token");
        }
        byte[] footer = footerPart.isEmpty() ? new byte[0] : b64urlDecode(footerPart);
        int cut = body.length - SIGNATURE_BYTES;
        byte[] message = new byte[cut];
        byte[] signature = new byte[SIGNATURE_BYTES];
        System.arraycopy(body, 0, message, 0, cut);
        System.arraycopy(body, cut, signature, 0, SIGNATURE_BYTES);
        return new Parsed(message, signature, footer);
    }

    /** Build a PublicKey from the 32 raw bytes the key document carries. */
    public static PublicKey publicKeyFromRaw(byte[] raw) {
        if (raw.length != PUBLIC_KEY_BYTES) {
            throw new VerificationException("anubis: wrong key size");
        }
        byte[] spki = new byte[SPKI_PREFIX.length + raw.length];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, SPKI_PREFIX.length, raw.length);
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        } catch (Exception e) {
            throw new VerificationException("anubis: cannot read public key: " + e.getMessage());
        }
    }

    /** Verify a token and return its parts. */
    public static Parsed verify(PublicKey key, String token, byte[] implicit) {
        Parsed parsed = parse(token);
        byte[] m2 = pae(
            HEADER.getBytes(StandardCharsets.UTF_8),
            parsed.message(),
            parsed.footer(),
            implicit == null ? new byte[0] : implicit);
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(m2);
            if (!verifier.verify(parsed.signature())) {
                throw new VerificationException("anubis: signature verification failed");
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("anubis: signature verification failed: " + e.getMessage());
        }
        return parsed;
    }
}
