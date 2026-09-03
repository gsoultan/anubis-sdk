package io.github.gsoultan.anubis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * Fetches and caches the published key document.
 *
 * <p>Two clocks govern refetching. The TTL bounds how stale the document may
 * get, so a key withdrawn upstream stops verifying. The min-refetch interval
 * bounds what an unknown kid can provoke inside that window — kid arrives
 * inside attacker-supplied tokens, so a stream of garbage kids must not become
 * a stream of outbound requests.
 *
 * <p>Fetches are single-flight and run with no lock held: a slow keys endpoint
 * must not stall every concurrent verification behind it.
 */
final class Keys {
    /**
     * kid is attacker-controlled input: it arrives inside tokens. It may only
     * ever index a bounded, pre-loaded, in-memory map — never a database query,
     * a filesystem path, or a per-token network fetch.
     */
    private static final int MAX_KEYS = 64;

    /** A keys document past this size is refused rather than buffered. */
    private static final int MAX_DOCUMENT_BYTES = 1 << 20;

    static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    static final Duration DEFAULT_MIN_REFETCH = Duration.ofSeconds(30);
    static final Duration DEFAULT_MIN_RETRY = Duration.ofSeconds(1);

    private final String url;
    private final String issuer;
    private final HttpClient http;
    private final ObjectMapper json;
    private final long ttlMs;
    private final long minRefetchMs;
    private final long minRetryMs;

    private final Object lock = new Object();
    private KeySet pinned;
    private KeySet keys;
    private long lastFetch;
    private long nextFetch;
    private String lastError;
    private CountDownLatch inflight;

    Keys(String url, HttpClient http, ObjectMapper json, String issuer) {
        this(url, http, json, issuer, DEFAULT_TTL, DEFAULT_MIN_REFETCH, DEFAULT_MIN_RETRY);
    }

    Keys(String url, HttpClient http, ObjectMapper json, String issuer,
         Duration ttl, Duration minRefetch, Duration minRetry) {
        this.url = url;
        this.issuer = issuer == null ? "" : issuer;
        this.http = http;
        this.json = json;
        this.ttlMs = ttl.toMillis();
        this.minRefetchMs = minRefetch.toMillis();
        this.minRetryMs = minRetry.toMillis();
    }

    /** A key together with the window it may be trusted in. */
    private record Held(PublicKey key, long notBefore, long notAfter) {}

    /** An immutable kid -&gt; public key map that knows each key's window. */
    static final class KeySet {
        private final Map<String, Held> keys;

        private KeySet(Map<String, Held> keys) {
            this.keys = keys;
        }

        /**
         * Returns the key for kid if this set holds it and nowSec falls inside
         * its published window, else null. Either bound at zero is unbounded.
         *
         * <p>not_after is when a verifier stops <em>trusting</em> the key, not
         * when the issuer stops signing with it: a token minted a second before
         * the deadline is rejected the moment it passes. Publish not_after at
         * least one maximum token lifetime after the key's last signing time,
         * or a rotation rejects tokens that are still live.
         */
        PublicKey get(String kid, long nowSec) {
            Held held = keys.get(kid);
            if (held == null) {
                return null;
            }
            if (held.notBefore() != 0 && nowSec < held.notBefore()) {
                return null;
            }
            if (held.notAfter() != 0 && nowSec >= held.notAfter()) {
                return null;
            }
            return held.key();
        }
    }

    static KeySet parseDocument(JsonNode document) {
        return parseDocument(document, "");
    }

    /**
     * Parses a published keys document.
     *
     * <p>issuer, when non-empty, must match the document's own issuer. A
     * verifier that loads whatever keys its URL happens to serve cannot notice
     * it was pointed at the wrong deployment. A document that omits the field
     * is accepted: the binding is only ever as good as what the issuer
     * publishes.
     */
    static KeySet parseDocument(JsonNode document, String issuer) {
        JsonNode entries = document.path("keys");
        if (!entries.isArray()) {
            throw new VerificationException("anubis: keys document has no keys");
        }
        String published = document.path("issuer").asText("");
        if (issuer != null && !issuer.isEmpty() && !published.isEmpty() && !published.equals(issuer)) {
            throw new VerificationException(
                "anubis: keys document is issued by \"" + published + "\", expected \"" + issuer + "\"");
        }
        if (entries.size() > MAX_KEYS) {
            throw new VerificationException(
                "anubis: keys document has " + entries.size() + " keys, max " + MAX_KEYS);
        }
        Map<String, Held> out = new HashMap<>();
        for (JsonNode entry : entries) {
            if (!"Ed25519".equals(entry.path("alg").asText())) {
                continue; // pinned algorithm; nothing negotiable
            }
            byte[] raw = Paseto.b64urlDecode(entry.path("public_key").asText());
            out.put(entry.path("kid").asText(), new Held(
                Paseto.publicKeyFromRaw(raw),
                entry.path("not_before").asLong(0),
                entry.path("not_after").asLong(0)));
        }
        return new KeySet(Map.copyOf(out));
    }

    void pin(KeySet keySet) {
        synchronized (lock) {
            this.pinned = keySet;
        }
    }

    PublicKey get(String kid, long nowSec) {
        long nowMs = nowSec * 1000L;
        KeySet pin;
        KeySet snapshot;
        long fetched;
        synchronized (lock) {
            pin = pinned;
            snapshot = keys;
            fetched = lastFetch;
        }

        // Pinned keys are held separately from the fetched document: a refetch
        // replaces what the URL serves, and must not silently drop what the
        // caller handed over.
        if (pin != null) {
            PublicKey hit = pin.get(kid, nowSec);
            if (hit != null) {
                return hit;
            }
            if (url.isEmpty()) {
                throw new VerificationException("anubis: unknown kid \"" + kid + "\"");
            }
        }

        // The hot path: a current document holding the kid answers with no I/O.
        if (snapshot != null && nowMs - fetched < ttlMs) {
            PublicKey hit = snapshot.get(kid, nowSec);
            if (hit != null) {
                return hit;
            }
        }

        // Missing, stale, or an unknown kid worth spending a fetch on.
        if (!url.isEmpty()) {
            try {
                refetch(nowMs);
            } catch (RuntimeException e) {
                // Stale keys beat no keys; the unknown-kid rejection stands.
                if (snapshot == null) {
                    throw e;
                }
            }
        }

        synchronized (lock) {
            snapshot = keys;
        }
        if (snapshot != null) {
            PublicKey hit = snapshot.get(kid, nowSec);
            if (hit != null) {
                return hit;
            }
        }
        throw new VerificationException("anubis: unknown kid \"" + kid + "\"");
    }

    /**
     * Runs at most one fetch at a time. A caller arriving while one is in
     * flight waits for that result rather than starting its own — otherwise a
     * burst of unknown kids becomes a burst of outbound requests, which is
     * exactly what the kid budget exists to prevent.
     */
    private void refetch(long nowMs) {
        CountDownLatch waitFor = null;
        CountDownLatch mine = null;
        synchronized (lock) {
            if (inflight != null) {
                waitFor = inflight;
            } else if (nowMs < nextFetch) {
                if (lastError != null) {
                    throw new VerificationException(lastError);
                }
                return;
            } else {
                mine = new CountDownLatch(1);
                inflight = mine;
            }
        }

        if (waitFor != null) {
            try {
                waitFor.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new VerificationException("anubis: keys fetch interrupted");
            }
            synchronized (lock) {
                if (lastError != null) {
                    throw new VerificationException(lastError);
                }
            }
            return;
        }

        try {
            KeySet parsed = fetch();
            synchronized (lock) {
                keys = parsed;
                lastFetch = nowMs;
                nextFetch = nowMs + minRefetchMs;
                lastError = null;
            }
        } catch (RuntimeException e) {
            synchronized (lock) {
                nextFetch = nowMs + minRetryMs;
                lastError = e.getMessage() == null ? "anubis: keys fetch failed" : e.getMessage();
            }
            throw e;
        } finally {
            // Released however we leave. A wedged in-flight slot would park
            // every later caller on a latch nothing counts down, which is a
            // worse outage than the failed fetch that caused it.
            synchronized (lock) {
                inflight = null;
            }
            mine.countDown();
        }
    }

    private KeySet fetch() {
        try {
            HttpResponse<InputStream> res = http.send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofInputStream());
            byte[] raw;
            try (InputStream in = res.body()) {
                if (res.statusCode() != 200) {
                    throw new VerificationException("anubis: keys fetch: status " + res.statusCode());
                }
                raw = in.readNBytes(MAX_DOCUMENT_BYTES + 1);
            }
            if (raw.length > MAX_DOCUMENT_BYTES) {
                throw new VerificationException(
                    "anubis: keys document exceeds " + MAX_DOCUMENT_BYTES + " bytes");
            }
            return parseDocument(json.readTree(raw), issuer);
        } catch (VerificationException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VerificationException("anubis: keys fetch interrupted");
        } catch (Exception e) {
            throw new VerificationException("anubis: keys fetch: " + e.getMessage());
        }
    }
}
