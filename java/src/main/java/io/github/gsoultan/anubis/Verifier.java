package io.github.gsoultan.anubis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Locale;

/**
 * Verifies v4.public access tokens offline.
 *
 * <p>Zero I/O on the verify path, except a bounded, rate-limited key refetch
 * when a token names a kid this process has not seen.
 *
 * <pre>{@code
 * var verifier = Verifier.builder()
 *     .issuer("https://anubis.internal")
 *     .audience("billing-api")
 *     .keysUrl("https://anubis.internal/.well-known/anubis-keys.json")
 *     .build();
 * }</pre>
 */
public final class Verifier {
    private final String issuer;
    private final String audience;
    private final Duration leeway;
    private final Keys keys;
    private final ObjectMapper json;
    private final java.time.Clock clock;

    private Verifier(Builder b) {
        if (b.audience == null || b.audience.isEmpty()) {
            // A verifier without an audience accepts tokens minted for other
            // services — the classic confused deputy. There is no flag to skip
            // this, on purpose.
            throw new VerificationException(
                "anubis: a verifier requires an audience — refusing to skip the aud check");
        }
        if (b.keysUrl == null && b.staticKeys == null) {
            throw new VerificationException("anubis: either keysUrl or staticKeys is required");
        }
        this.issuer = b.issuer == null ? "" : b.issuer;
        this.audience = b.audience;
        this.leeway = b.leeway;
        this.json = b.json == null ? new ObjectMapper() : b.json;
        this.clock = b.clock == null ? java.time.Clock.systemUTC() : b.clock;
        HttpClient http = b.http == null
            ? HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
            : b.http;
        if (b.keysUrl != null) {
            assertFetchableKeysUrl(b.keysUrl);
        }
        this.keys = new Keys(b.keysUrl == null ? "" : b.keysUrl, http, this.json, this.issuer);
        if (b.staticKeys != null) {
            this.keys.pin(Keys.parseDocument(b.staticKeys));
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Checks signature, expiry, nbf, issuer and audience.
     *
     * <p>It does NOT check epoch or session revocation — those need state only
     * Anubis holds. Use introspection where instant revocation matters.
     */
    public Claims verify(String token) {
        // The kid rides in the footer, which the signature covers — but it has
        // to be read BEFORE verification to select the key. That
        // pre-verification read may only index the bounded key map.
        Paseto.Parsed unverified = Paseto.parse(token);
        String kid = "";
        if (unverified.footer().length > 0) {
            try {
                kid = json.readTree(unverified.footerString()).path("kid").asText("");
            } catch (Exception e) {
                throw new VerificationException("anubis: token footer is not JSON");
            }
        }
        // One instant for the whole verification: a key inside its window and a
        // token inside its lifetime must be judged against the same reading.
        long now = clock.instant().getEpochSecond();

        PublicKey key = keys.get(kid, now);
        Paseto.Parsed verified = Paseto.verify(key, token, null);

        Claims claims;
        try {
            claims = json.readValue(verified.message(), Claims.class);
        } catch (Exception e) {
            throw new VerificationException("anubis: claims decode: " + e.getMessage());
        }
        if (claims.version() != 0 && claims.version() != 1) {
            throw new VerificationException("anubis: unsupported token version");
        }
        validate(claims, now);
        return claims;
    }

    private void validate(Claims c, long now) {
        long l = leeway.toSeconds();
        if (c.expires() != 0 && now > c.expires() + l) {
            throw new VerificationException("anubis: token expired");
        }
        if (c.notBefore() != 0 && now < c.notBefore() - l) {
            throw new VerificationException("anubis: token not yet valid (check NTP)");
        }
        if (!issuer.isEmpty() && !issuer.equals(c.issuer())) {
            throw new VerificationException("anubis: issuer mismatch");
        }
        if (!c.audience().contains(audience)) {
            throw new VerificationException("anubis: audience mismatch");
        }
    }

    /** Extracts the Authorization bearer credential. */
    public static String bearer(String authorization) {
        if (authorization == null) {
            return null;
        }
        String trimmed = authorization.trim();
        if (trimmed.length() <= 7 || !trimmed.substring(0, 7).toLowerCase(Locale.ROOT).equals("bearer ")) {
            return null;
        }
        return trimmed.substring(7).trim();
    }

    /** Verifies a request and returns the principal, or throws. */
    public Principal principal(String authorizationHeader) {
        String token = bearer(authorizationHeader);
        if (token == null) {
            throw new VerificationException("anubis: missing bearer token");
        }
        return new Principal(verify(token), token);
    }

    public static final class Builder {
        private String issuer;
        private String audience;
        private String keysUrl;
        private JsonNode staticKeys;
        private Duration leeway = Duration.ofSeconds(60);
        private HttpClient http;
        private ObjectMapper json;
        private java.time.Clock clock;

        public Builder issuer(String v) {
            this.issuer = v;
            return this;
        }

        /** Mandatory. This service's identifier — the aud its tokens carry. */
        public Builder audience(String v) {
            this.audience = v;
            return this;
        }

        /**
         * The discovery endpoint. Must be https unless it points at loopback:
         * whoever answers this URL decides which keys this verifier trusts.
         */
        public Builder keysUrl(String v) {
            this.keysUrl = v;
            return this;
        }

        /** Pin keys directly, for air-gapped consumers and tests. */
        public Builder staticKeys(JsonNode v) {
            this.staticKeys = v;
            return this;
        }

        /** Absorbs clock skew between services. Enforce NTP anyway. */
        public Builder leeway(Duration v) {
            this.leeway = v;
            return this;
        }

        public Builder httpClient(HttpClient v) {
            this.http = v;
            return this;
        }

        public Builder objectMapper(ObjectMapper v) {
            this.json = v;
            return this;
        }

        public Builder clock(java.time.Clock v) {
            this.clock = v;
            return this;
        }

        public Verifier build() {
            return new Verifier(this);
        }
    }

    /** Convenience for pinning an already-parsed key set. */
    void pinKeys(Keys.KeySet pinned) {
        keys.pin(pinned);
    }

    /**
     * Refuses a keys endpoint that is not integrity-protected. Whoever answers
     * this URL decides which public keys the verifier trusts, and therefore who
     * can mint tokens it accepts — over plaintext that is anyone on the path.
     * Loopback is exempt: it never leaves the host, and test servers live there.
     */
    static void assertFetchableKeysUrl(String raw) {
        URI u;
        try {
            u = URI.create(raw);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("anubis: keysUrl \"" + raw + "\" is not a URL");
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        if (scheme.equals("https")) {
            return;
        }
        if (!scheme.equals("http")) {
            throw new VerificationException("anubis: keysUrl \"" + raw + "\": scheme must be https");
        }
        if (isLoopback(u.getHost())) {
            return;
        }
        throw new VerificationException("anubis: keysUrl \"" + raw
            + "\" is plaintext http — whoever answers it decides which keys "
            + "this verifier trusts; use https");
    }

    private static boolean isLoopback(String host) {
        if (host == null) {
            return false;
        }
        String h = host.startsWith("[") && host.endsWith("]")
            ? host.substring(1, host.length() - 1)
            : host;
        return h.equals("localhost") || h.equals("::1") || h.startsWith("127.");
    }
}
