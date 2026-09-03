package io.github.gsoultan.anubis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Fetches and caches the published key document.
 *
 * <p>On an unknown kid it refetches at most once per {@code minRefetch} — a
 * stream of garbage kids must not translate into a stream of outbound requests.
 */
final class Keys {
    /**
     * kid is attacker-controlled input: it arrives inside tokens. It may only
     * ever index a bounded, pre-loaded, in-memory map — never a database query,
     * a filesystem path, or a per-token network fetch.
     */
    private static final int MAX_KEYS = 64;

    private final String url;
    private final Duration minRefetch;
    private final HttpClient http;
    private final ObjectMapper json;

    private volatile Map<String, PublicKey> keys;
    private volatile long lastFetch;

    Keys(String url, HttpClient http, ObjectMapper json, Duration minRefetch) {
        this.url = url;
        this.http = http;
        this.json = json;
        this.minRefetch = minRefetch;
    }

    static Map<String, PublicKey> parseDocument(JsonNode document) {
        JsonNode entries = document.path("keys");
        if (!entries.isArray()) {
            throw new VerificationException("anubis: keys document has no keys");
        }
        if (entries.size() > MAX_KEYS) {
            throw new VerificationException(
                "anubis: keys document has " + entries.size() + " keys, max " + MAX_KEYS);
        }
        Map<String, PublicKey> out = new HashMap<>();
        for (JsonNode entry : entries) {
            if (!"Ed25519".equals(entry.path("alg").asText())) {
                continue; // pinned algorithm; nothing negotiable
            }
            byte[] raw = Paseto.b64urlDecode(entry.path("public_key").asText());
            out.put(entry.path("kid").asText(), Paseto.publicKeyFromRaw(raw));
        }
        return Map.copyOf(out);
    }

    void pin(Map<String, PublicKey> pinned) {
        this.keys = pinned;
    }

    PublicKey get(String kid) {
        Map<String, PublicKey> current = keys;
        if (current != null && current.containsKey(kid)) {
            return current.get(kid);
        }
        if (current == null || System.nanoTime() - lastFetch >= minRefetch.toNanos()) {
            try {
                refresh();
            } catch (RuntimeException e) {
                // Stale keys beat no keys; the unknown-kid rejection still stands.
                if (keys == null) {
                    throw e;
                }
            }
            current = keys;
            if (current != null && current.containsKey(kid)) {
                return current.get(kid);
            }
        }
        throw new VerificationException("anubis: unknown kid \"" + kid + "\"");
    }

    private synchronized void refresh() {
        lastFetch = System.nanoTime();
        try {
            HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) {
                throw new VerificationException("anubis: keys fetch: status " + res.statusCode());
            }
            keys = parseDocument(json.readTree(res.body()));
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
