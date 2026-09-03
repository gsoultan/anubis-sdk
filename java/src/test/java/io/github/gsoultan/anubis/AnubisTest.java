package io.github.gsoultan.anubis;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AnubisTest {
    private static final String ISSUER = "http://127.0.0.1";
    private static final String APP = "billing-api";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static final KeyPair KEYS = generateKeys();

    private static KeyPair generateKeys() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    /** The key document publishes 32 raw bytes; the JDK exports SPKI. */
    private static String rawPublicKey() {
        byte[] spki = KEYS.getPublic().getEncoded();
        return Paseto.b64urlEncode(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
    }

    private static String mint(String body) {
        try {
            byte[] message = body.getBytes(StandardCharsets.UTF_8);
            byte[] footer = "{\"kid\":\"k1\"}".getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(KEYS.getPrivate());
            signer.update(Paseto.pae("v4.public.".getBytes(StandardCharsets.UTF_8), message, footer, new byte[0]));
            byte[] sig = signer.sign();
            byte[] joined = new byte[message.length + sig.length];
            System.arraycopy(message, 0, joined, 0, message.length);
            System.arraycopy(sig, 0, joined, message.length, sig.length);
            return "v4.public." + Paseto.b64urlEncode(joined) + "." + Paseto.b64urlEncode(footer);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static String token(Map<String, Object> extra) {
        ObjectNode c = JSON.createObjectNode();
        c.put("iss", ISSUER);
        c.put("sub", "usr_1");
        c.set("aud", JSON.valueToTree(List.of(APP)));
        c.put("exp", Instant.now().plusSeconds(600).getEpochSecond());
        c.put("iat", Instant.now().getEpochSecond());
        extra.forEach((k, v) -> c.set(k, JSON.valueToTree(v)));
        return mint(c.toString());
    }

    private static Verifier verifier() {
        ObjectNode doc = JSON.createObjectNode();
        ObjectNode key = JSON.createObjectNode();
        key.put("kid", "k1");
        key.put("alg", "Ed25519");
        key.put("public_key", rawPublicKey());
        doc.set("keys", JSON.valueToTree(List.of(key)));
        return Verifier.builder().issuer(ISSUER).audience(APP).staticKeys(doc).build();
    }

    // ---- PASETO -----------------------------------------------------------

    /**
     * Golden vectors from the PASETO specification. The same table the Go, PHP
     * and TypeScript implementations assert — drift here is a
     * cross-implementation token break.
     */
    @Test
    void paeMatchesTheSpecificationVectors() {
        assertEquals("0000000000000000", hex(Paseto.pae()));
        assertEquals("01000000000000000000000000000000", hex(Paseto.pae(new byte[0])));
        assertEquals("0100000000000000040000000000000074657374", hex(Paseto.pae(bytes("test"))));
        assertEquals(
            "02000000000000000400000000000000746573740000000000000000",
            hex(Paseto.pae(bytes("test"), new byte[0])));
    }

    // ---- verification -----------------------------------------------------

    @Test
    void verifiesAWellFormedToken() {
        Claims c = verifier().verify(token(Map.of("roles", List.of("billing.clerk"))));
        assertEquals("usr_1", c.subject());
        assertTrue(c.hasRole("billing.clerk"));
    }

    @Test
    void refusesToBeBuiltWithoutAnAudience() {
        assertThrows(
            VerificationException.class,
            () -> Verifier.builder().issuer(ISSUER).keysUrl("http://x/keys").build());
    }

    @Test
    void rejectsATokenMintedForAnotherApplication() {
        String other = token(Map.of("aud", List.of("hr-api")));
        assertThrows(VerificationException.class, () -> verifier().verify(other));
    }

    @Test
    void rejectsExpiredAndNotYetValidTokens() {
        String expired = token(Map.of("exp", Instant.now().minusSeconds(3600).getEpochSecond()));
        assertThrows(VerificationException.class, () -> verifier().verify(expired));
        String early = token(Map.of("nbf", Instant.now().plusSeconds(3600).getEpochSecond()));
        assertThrows(VerificationException.class, () -> verifier().verify(early));
    }

    @Test
    void rejectsMalformedTokens() {
        Verifier v = verifier();
        for (String bad : List.of("", "v4.public", "v2.public.abc", "v4.public.", "v4.public.AAAA")) {
            assertThrows(AnubisException.class, () -> v.verify(bad));
        }
    }

    @Test
    void rejectsAnUnknownKidWithoutIO() {
        // The kid rides in the footer and must only ever index the bounded map.
        byte[] message = "{\"iss\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        byte[] footer = "{\"kid\":\"nope\"}".getBytes(StandardCharsets.UTF_8);
        String forged =
            "v4.public." + Paseto.b64urlEncode(new byte[message.length + 64]) + "." + Paseto.b64urlEncode(footer);
        assertThrows(VerificationException.class, () -> verifier().verify(forged));
    }

    // ---- the vocabulary ---------------------------------------------------

    @Test
    void permissionKnowsItsPartsAndBothSpellings() {
        Permission p = Permission.of("billing:invoice:approve");
        assertEquals("billing", p.app());
        assertEquals("invoice", p.resource());
        assertEquals("approve", p.action());
        // A manifest declares permissions WITHOUT the application prefix.
        assertEquals("invoice:approve", p.manifest());
        assertEquals(p, Permission.from("billing", "invoice", "approve"));
    }

    @Test
    void aMalformedPermissionReportsNothingRatherThanAPlausiblePart() {
        for (String bad : List.of("", "approve", "invoice:approve", "a:b:c:d", "a::c")) {
            Permission p = Permission.of(bad);
            assertFalse(p.isValid(), bad + " was accepted");
            assertEquals("", p.app(), bad + " returned an app");
        }
    }

    @Test
    void roleSeparatesThePrefixFromTheManifestName() {
        Role r = Role.of("billing.clerk");
        assertEquals("billing", r.app());
        assertEquals("clerk", r.name());
        assertEquals(r, Role.from("billing", "clerk"));
        // An unprefixed role reports no application rather than pretending.
        assertEquals("", Role.of("clerk").app());
    }

    @Test
    void rolesComparesTheFullPrefixedName() {
        Roles rs = Roles.of(List.of("billing.clerk", "billing.approver", "hr.viewer"));
        assertTrue(rs.has("billing.clerk"));
        assertFalse(rs.has("clerk"));
        assertTrue(rs.hasAny("nope.none", "hr.viewer"));
        assertEquals(2, rs.ofApp("billing").size());
    }

    @Test
    void scopesAreImmutableAndSorted() {
        Scopes base = Scopes.of("org", "o1");
        Scopes with = base.with("customer", "c1");
        assertEquals(1, base.size(), "with() mutated the receiver");
        assertEquals("c1", with.node("customer"));
        // One printable form, which is what keeps a cache from keying the same
        // question many ways.
        assertEquals("customer=c1 org=o1", with.toString());
        Scopes merged = with.merge(Scopes.of("org", "o2", "product", "p1"));
        assertEquals("o2", merged.node("org"));
        assertEquals("c1", merged.node("customer"));
        assertTrue(Scopes.empty().isEmpty());
    }

    @Test
    void ownerNamesTheReservedAxis() {
        assertEquals("usr_applicant", Scopes.owner("usr_applicant").node(Scopes.OWNER_AXIS));
        assertEquals("_owner", Scopes.OWNER_AXIS);
    }

    @Test
    void hasAllRequiresEveryMethodNotAny() {
        AuthMethods m = AuthMethods.of(AuthMethods.PASSWORD, AuthMethods.OTP);
        assertTrue(m.has(AuthMethods.OTP));
        assertTrue(m.hasAll(AuthMethods.PASSWORD, AuthMethods.OTP));
        assertFalse(m.hasAll(AuthMethods.PASSWORD, AuthMethods.DEVICE_KEY));
    }

    @Test
    void durationsParseOrReportThemselvesUnreadable() {
        assertEquals(Duration.ofMinutes(2), Durations.parse("2m"));
        assertEquals(Duration.ofSeconds(30), Durations.parse("30s"));
        // null rather than zero: zero would read as "no maximum age", which is
        // the opposite of what an unreadable value means.
        assertNull(Durations.parse("nonsense"));
        assertNull(Durations.parse(""));
    }

    // ---- identity ---------------------------------------------------------

    @Test
    void aPrincipalAnswersWhoAndWhatWithoutClaimSetSpelunking() {
        long authTime = Instant.now().minusSeconds(2400).getEpochSecond();
        String t = token(Map.of(
            "sid", "ses_9",
            "tid", "tnt_impack",
            "realm", "internal",
            "roles", List.of("billing.clerk"),
            "scopes", Map.of("org", "o1", "customer", "c1"),
            "amr", List.of("pwd"),
            "ial", 2,
            "auth_time", authTime));
        Principal p = new Principal(verifier().verify(t), t);

        assertEquals("usr_1", p.subject());
        assertEquals("ses_9", p.session());
        assertTrue(p.hasRole("billing.clerk"));
        assertEquals("c1", p.scopes().node("customer"));

        Identity id = p.identity();
        assertEquals("o1", id.activeScope("org"));
        // Authentication time is not issue time: a refresh mints a token with
        // no fresh proof, which is why step-up is decided against this.
        assertTrue(id.authAge().toMinutes() >= 39);
        assertFalse(id.isApplication());
        assertEquals("usr_1 [customer=c1 org=o1]", id.toString());
    }

    @Test
    void aClientCredentialsSubjectIsRecognisable() {
        String t = token(Map.of("sub", "app_batch"));
        assertTrue(new Principal(verifier().verify(t), t).identity().isApplication());
    }

    @Test
    void tokensExposeLifetimeAndWhetherTheyCanRotate() {
        Instant issued = Instant.now();
        Tokens t = new Tokens("a", "r", "Bearer", 600, "ses_1", issued);
        assertEquals(Duration.ofMinutes(10), t.lifetime());
        assertEquals(issued.plusSeconds(600), t.expiry());
        assertTrue(t.hasRefresh());
        // A client-credentials pair has no refresh token; it is re-minted.
        assertFalse(new Tokens("a", "", "Bearer", 300, "", issued).hasRefresh());
    }

    // ---- the client, against a real socket ---------------------------------

    @Test
    void authorizeSendsEveryAxisAndSurfacesTypedRefusals() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        StringBuilder lastBody = new StringBuilder();
        String[] answer = {"{\"allow\":true}"};

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/anubis.v1.AuthzService/Authorize", exchange -> {
            calls.incrementAndGet();
            lastBody.setLength(0);
            lastBody.append(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] out = answer[0].getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("content-type", "application/json");
            exchange.sendResponseHeaders(200, out.length);
            try (OutputStream body = exchange.getResponseBody()) {
                body.write(out);
            }
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            Client client = Client.builder(base).application(APP, null).apiKey("anb_live_ab12cd34_s3cr3t").build();
            String t = token(Map.of("amr", List.of("pwd", "otp"), "auth_time", Instant.now().getEpochSecond()));
            Principal p = new Principal(verifier().verify(t), t);

            client.require(p, "billing:invoice:approve", Scopes.of("org", "o1", "customer", "c1"));
            assertEquals(1, calls.get());
            // Both axes, and the amr and auth_time that make step-up decidable.
            assertTrue(lastBody.toString().contains("\"org\":\"o1\""), lastBody.toString());
            assertTrue(lastBody.toString().contains("\"customer\":\"c1\""), lastBody.toString());
            assertTrue(lastBody.toString().contains("\"otp\""), lastBody.toString());

            answer[0] = "{\"allow\":false,\"reason\":\"scope_mismatch\",\"failingAxis\":\"customer\","
                + "\"message\":\"no grant\"}";
            DeniedException denied = assertThrows(
                DeniedException.class,
                () -> client.require(p, "billing:invoice:approve", Scopes.empty()));
            assertEquals("customer", denied.failingAxis());

            answer[0] = "{\"allow\":false,\"reason\":\"step_up_required\",\"requiredAmr\":[\"otp\"],"
                + "\"maxAuthAge\":\"2m\"}";
            StepUpRequiredException stepUp = assertThrows(
                StepUpRequiredException.class,
                () -> client.require(p, "billing:invoice:approve", Scopes.empty()));
            assertTrue(stepUp.requiredAmr().has(AuthMethods.OTP));
            assertEquals(Duration.ofMinutes(2), stepUp.maxAuthAgeDuration());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void authorizeRefusesAMalformedPermissionBeforeSpendingADecision() {
        Client client = Client.builder("https://anubis.test").apiKey("anb_live_ab12cd34_s3cr3t").build();
        String t = token(Map.of());
        Principal p = new Principal(verifier().verify(t), t);
        // No server is running: reaching the network would fail differently.
        assertThrows(
            IllegalArgumentException.class,
            () -> client.authorize(p, "invoice:approve", Scopes.empty()));
    }

    @Test
    void constructionRefusesBadConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> Client.builder("http://anubis.test").build());
        assertThrows(
            IllegalArgumentException.class,
            () -> Client.builder("https://a.test").apiKey("nope").build());
        assertThrows(
            IllegalArgumentException.class,
            () -> Client.builder("https://a.test").apiKey("anb_live_ab12cd34_s3cr3t").application("app", "secret").build());
    }

    // ---- helpers ----------------------------------------------------------

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(byte[] b) {
        StringBuilder out = new StringBuilder();
        for (byte x : b) {
            out.append(String.format("%02x", x));
        }
        return out.toString();
    }
}
