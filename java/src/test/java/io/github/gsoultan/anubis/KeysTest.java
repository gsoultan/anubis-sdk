package io.github.gsoultan.anubis;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class KeysTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long NOW = 1_700_000_000L;

    private static ObjectNode key(String kid) {
        try {
            byte[] spki = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
            ObjectNode k = JSON.createObjectNode();
            k.put("kid", kid);
            k.put("alg", "Ed25519");
            k.put("public_key", Paseto.b64urlEncode(Arrays.copyOfRange(spki, spki.length - 32, spki.length)));
            return k;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static ObjectNode doc(String issuer, ObjectNode... keys) {
        ObjectNode d = JSON.createObjectNode();
        if (!issuer.isEmpty()) {
            d.put("issuer", issuer);
        }
        d.set("keys", JSON.valueToTree(List.of(keys)));
        return d;
    }

    /** A keys endpoint the test can swap, count and stall. */
    private static final class KeysServer implements AutoCloseable {
        private final HttpServer server;
        final AtomicInteger hits = new AtomicInteger();
        final String url;
        volatile byte[] body;
        volatile int status = 200;
        volatile CountDownLatch gate;

        KeysServer(String initial) {
            try {
                this.body = initial.getBytes(StandardCharsets.UTF_8);
                this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                server.createContext("/keys", exchange -> {
                    hits.incrementAndGet();
                    CountDownLatch g = gate;
                    if (g != null) {
                        try {
                            g.await(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    byte[] out = this.body;
                    exchange.sendResponseHeaders(status, out.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(out);
                    }
                });
                server.setExecutor(Executors.newFixedThreadPool(8));
                server.start();
                this.url = "http://127.0.0.1:" + server.getAddress().getPort() + "/keys";
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }

        void serve(String newBody, int newStatus) {
            this.body = newBody.getBytes(StandardCharsets.UTF_8);
            this.status = newStatus;
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static Keys cache(String url, String issuer) {
        return new Keys(url, HttpClient.newHttpClient(), JSON, issuer,
            Duration.ofMinutes(5), Duration.ofSeconds(30), Duration.ofSeconds(1));
    }

    // ---- parseDocument ---------------------------------------------------

    @Test
    void bindsTheDocumentToAnIssuer() {
        ObjectNode k = key("k1");
        assertDoesNotThrow(() -> Keys.parseDocument(doc("https://a.test", k), "https://a.test"));
        assertDoesNotThrow(() -> Keys.parseDocument(doc("", k), "https://a.test"));
        assertDoesNotThrow(() -> Keys.parseDocument(doc("https://evil.test", k), ""));
        VerificationException e = assertThrows(VerificationException.class,
            () -> Keys.parseDocument(doc("https://evil.test", k), "https://a.test"));
        assertTrue(e.getMessage().contains("issued by"), e.getMessage());
    }

    @Test
    void boundsTheKeyCount() {
        ObjectNode[] keys = new ObjectNode[65];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = key("k" + i);
        }
        assertThrows(VerificationException.class, () -> Keys.parseDocument(doc("", keys), ""));
    }

    @Test
    void pinsTheAlgorithm() {
        ObjectNode bad = key("k2");
        bad.put("alg", "RS256");
        Keys.KeySet set = Keys.parseDocument(doc("", key("k1"), bad));
        assertNotNull(set.get("k1", NOW));
        assertNull(set.get("k2", NOW));
    }

    @Test
    void enforcesEachKeysValidityWindow() {
        ObjectNode future = key("future");
        future.put("not_before", NOW + 60);
        ObjectNode past = key("past");
        past.put("not_after", NOW);

        Keys.KeySet set = Keys.parseDocument(doc("", future, past, key("unbounded")));
        assertNull(set.get("future", NOW));
        assertNotNull(set.get("future", NOW + 120));
        assertNotNull(set.get("past", NOW - 1));
        assertNull(set.get("past", NOW), "not_after is exclusive: trust stops at the bound");
        assertNotNull(set.get("unbounded", NOW + 10_000_000));
    }

    // ---- cache -----------------------------------------------------------

    // The gap this closes: a cache that refetches only on an unknown kid never
    // notices a key being withdrawn, so a compromised key keeps verifying
    // tokens for the lifetime of the process.
    @Test
    void propagatesRevocationOnceTheDocumentGoesStale() {
        try (KeysServer srv = new KeysServer(doc("", key("k1"), key("k2")).toString())) {
            Keys keys = cache(srv.url, "");
            assertNotNull(keys.get("k2", NOW));

            srv.serve(doc("", key("k1")).toString(), 200); // k2 withdrawn

            assertNotNull(keys.get("k2", NOW + 60), "inside the TTL the cached document still answers");
            assertThrows(VerificationException.class, () -> keys.get("k2", NOW + 360),
                "past the TTL a withdrawn key must stop verifying");
        }
    }

    @Test
    void rateLimitsWhatAnUnknownKidCanProvoke() {
        try (KeysServer srv = new KeysServer(doc("", key("k1")).toString())) {
            Keys keys = cache(srv.url, "");
            for (int i = 0; i < 50; i++) {
                assertThrows(VerificationException.class, () -> keys.get("garbage", NOW));
            }
            assertEquals(1, srv.hits.get(), "50 garbage kids must not become 50 requests");

            assertThrows(VerificationException.class, () -> keys.get("garbage", NOW + 31));
            assertEquals(2, srv.hits.get());
        }
    }

    // The regression: get() read lastFetch outside the synchronized refresh,
    // so a burst of unknown kids produced one serial fetch each.
    @Test
    void aColdStartIsSingleFlight() throws Exception {
        try (KeysServer srv = new KeysServer(doc("", key("k1")).toString())) {
            CountDownLatch release = new CountDownLatch(1);
            srv.gate = release;
            Keys keys = cache(srv.url, "");

            final int callers = 16;
            CountDownLatch ready = new CountDownLatch(callers);
            ExecutorService pool = Executors.newFixedThreadPool(callers);
            List<Future<PublicKey>> futures = new ArrayList<>();
            for (int i = 0; i < callers; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    return keys.get("k1", NOW);
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            release.countDown();

            for (Future<PublicKey> f : futures) {
                assertNotNull(f.get(10, TimeUnit.SECONDS));
            }
            pool.shutdown();
            assertEquals(1, srv.hits.get(), callers + " concurrent cold-start callers must cause one fetch");
        }
    }

    @Test
    void staleKeysBeatNoKeys() {
        try (KeysServer srv = new KeysServer(doc("", key("k1")).toString())) {
            Keys keys = cache(srv.url, "");
            assertNotNull(keys.get("k1", NOW));

            srv.serve("", 500);
            assertNotNull(keys.get("k1", NOW + 360), "endpoint down and document stale: stale keys beat no keys");
        }
    }

    // Until the first fetch lands nothing verifies, but a down endpoint must
    // still not take one outbound request per inbound request.
    @Test
    void rateLimitsAFailingBootstrap() {
        try (KeysServer srv = new KeysServer("")) {
            srv.serve("", 500);
            Keys keys = cache(srv.url, "");

            for (int i = 0; i < 20; i++) {
                assertThrows(VerificationException.class, () -> keys.get("k1", NOW));
            }
            assertEquals(1, srv.hits.get(), "20 requests against a down endpoint must cause one fetch");

            assertThrows(VerificationException.class, () -> keys.get("k1", NOW + 2));
            assertEquals(2, srv.hits.get());
        }
    }

    @Test
    void refusesADocumentFromAnotherDeployment() {
        try (KeysServer srv = new KeysServer(doc("https://staging.test", key("k1")).toString())) {
            Keys keys = cache(srv.url, "https://prod.test");
            VerificationException e = assertThrows(VerificationException.class, () -> keys.get("k1", NOW));
            assertTrue(e.getMessage().contains("issued by"), e.getMessage());
        }
    }

    @Test
    void refusesADocumentThatOutgrowsTheBound() {
        try (KeysServer srv = new KeysServer("")) {
            srv.serve("{\"keys\":[],\"pad\":\"" + "x".repeat(1 << 20) + "\"}", 200);
            Keys keys = cache(srv.url, "");
            VerificationException e = assertThrows(VerificationException.class, () -> keys.get("k1", NOW));
            assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
        }
    }

    @Test
    void pinnedKeysSurviveARefetch() {
        try (KeysServer srv = new KeysServer(doc("", key("fetched")).toString())) {
            Keys keys = cache(srv.url, "");
            keys.pin(Keys.parseDocument(doc("", key("pinned"))));

            assertNotNull(keys.get("pinned", NOW));
            assertNotNull(keys.get("fetched", NOW), "an unknown kid provokes the fetch");
            assertNotNull(keys.get("pinned", NOW), "a refetch must not drop the caller's pinned keys");
        }
    }

    // ---- keysUrl ---------------------------------------------------------

    @Test
    void keysUrlMustBeIntegrityProtected() {
        for (String ok : List.of(
            "https://anubis.internal/.well-known/anubis-keys.json",
            "http://127.0.0.1:8080/keys.json",
            "http://[::1]:8080/keys.json",
            "http://localhost:8080/keys.json")) {
            assertDoesNotThrow(() -> Verifier.assertFetchableKeysUrl(ok), ok);
        }
        for (String bad : List.of(
            "http://anubis.internal/keys.json",
            "http://10.0.0.7/keys.json",
            "file:///etc/anubis/keys.json")) {
            assertThrows(VerificationException.class, () -> Verifier.assertFetchableKeysUrl(bad), bad);
        }
    }

    @Test
    void theVerifierRefusesToBeBuiltOnPlaintext() {
        VerificationException e = assertThrows(VerificationException.class,
            () -> Verifier.builder()
                .issuer("https://a.test")
                .audience("billing-api")
                .keysUrl("http://a.test/keys.json")
                .build());
        assertTrue(e.getMessage().contains("plaintext http"), e.getMessage());
    }
}
