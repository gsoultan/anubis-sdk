package io.github.gsoultan.anubis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Talks to an Anubis installation: sign-in, refresh, decisions, introspection.
 *
 * <p>This is the cold half of the SDK. Verifying a token on the request path
 * needs a {@link Verifier} instead, and needs no Client at all.
 */
public final class Client {
    private static final String PROC_LOGIN = "/anubis.v1.AuthService/Login";
    private static final String PROC_VERIFY_MFA = "/anubis.v1.AuthService/VerifyMfa";
    private static final String PROC_REFRESH = "/anubis.v1.AuthService/Refresh";
    private static final String PROC_LOGOUT_ALL = "/anubis.v1.AuthService/LogoutAll";
    private static final String PROC_CLIENT_CREDENTIALS = "/anubis.v1.AuthService/ClientCredentials";
    private static final String PROC_AUTHORIZE = "/anubis.v1.AuthzService/Authorize";
    private static final String PROC_EXPLAIN = "/anubis.v1.AuthzService/Explain";
    private static final String PROC_INTROSPECT = "/anubis.v1.TokenService/Introspect";

    private static final String PATH_AUTHORIZE = "/v1/authorize";
    private static final String PATH_TOKEN = "/v1/token";
    private static final String PATH_LOGOUT = "/v1/logout";

    public static final String LOGIN_COOKIE = "anubis_login";
    private static final Duration LOGIN_TTL = Duration.ofMinutes(10);

    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final String apiKey;
    private final String tenant;
    private final Duration timeout;
    private final Map<String, String> headers;
    private final HttpClient http;
    private final ObjectMapper json;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    private Client(Builder b) {
        URI uri = URI.create(b.baseUrl);
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException(
                "anubis: base url \"" + b.baseUrl + "\" must be an absolute origin like https://anubis.internal");
        }
        boolean local = "localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost());
        if (!"https".equals(uri.getScheme()) && !local) {
            throw new IllegalArgumentException(
                "anubis: base url \"" + b.baseUrl
                    + "\" must be https — browser sign-in needs it, and so does a credential");
        }
        if (b.apiKey != null && !b.apiKey.startsWith("anb_live_")) {
            throw new IllegalArgumentException("anubis: an api key looks like \"anb_live_<prefix>_<secret>\"");
        }
        if (b.apiKey != null && b.clientSecret != null) {
            // Two credentials means two identities: the tenant's system, and
            // the application acting as itself. A client holding both picks one
            // by accident, and the audit trail names the wrong caller.
            throw new IllegalArgumentException(
                "anubis: an api key and a client secret are different callers — use one client for each");
        }
        this.baseUrl = b.baseUrl.replaceAll("/+$", "");
        this.clientId = b.clientId == null ? "" : b.clientId;
        this.clientSecret = b.clientSecret == null ? "" : b.clientSecret;
        this.apiKey = b.apiKey == null ? "" : b.apiKey;
        this.tenant = b.tenant == null ? "" : b.tenant;
        this.timeout = b.timeout;
        this.headers = Map.copyOf(b.headers);
        this.json = b.json == null ? new ObjectMapper() : b.json;
        this.clock = b.clock == null ? Clock.systemUTC() : b.clock;
        this.http = b.http == null
            // A Connect procedure has no reason to redirect, and following one
            // would carry the credential to whatever host the Location names.
            ? HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
            : b.http;
    }

    public static Builder builder(String baseUrl) {
        return new Builder(baseUrl);
    }

    // ---- sign-in ----------------------------------------------------------

    /** An in-flight sign-in: where to send the browser, and what it must carry. */
    public record Redirect(String url, String state, String cookie) {}

    /** Parameters for a browser sign-in. */
    public static final class LoginParams {
        public String redirectUri;
        public List<String> scope = List.of("openid");
        public String realm = "";
        public String page = "";
        public String tenant = "";
        public String nonce = "";
        public String prompt = "";
        public List<String> acrValues = List.of();
        public int maxAge;

        public LoginParams(String redirectUri) {
            this.redirectUri = redirectUri;
        }
    }

    /**
     * Start an authorization-code sign-in with PKCE.
     *
     * <p>The verifier and state are generated here and stored in the returned
     * cookie, so the callback can check them. Neither is the caller's to manage.
     */
    public Redirect beginLogin(LoginParams p) {
        if (clientId.isEmpty()) {
            throw new IllegalArgumentException("anubis: beginLogin needs a client id (the application slug)");
        }
        if (p.redirectUri == null || p.redirectUri.isEmpty()) {
            throw new IllegalArgumentException(
                "anubis: beginLogin needs a redirectUri, and it must be one registered on the application");
        }
        String state = randomToken();
        String verifier = randomToken();
        String challenge = s256(verifier);

        Map<String, String> query = new LinkedHashMap<>();
        query.put("response_type", "code");
        query.put("client_id", clientId);
        query.put("redirect_uri", p.redirectUri);
        query.put("state", state);
        query.put("code_challenge", challenge);
        query.put("code_challenge_method", "S256");
        query.put("scope", String.join(" ", p.scope));
        putIf(query, "tenant", p.tenant.isEmpty() ? tenant : p.tenant);
        putIf(query, "realm", p.realm);
        putIf(query, "page", p.page);
        putIf(query, "nonce", p.nonce);
        putIf(query, "prompt", p.prompt);
        putIf(query, "acr_values", String.join(" ", p.acrValues));
        if (p.maxAge > 0) {
            query.put("max_age", String.valueOf(p.maxAge));
        }

        ObjectNode pending = json.createObjectNode();
        pending.put("s", state);
        pending.put("v", verifier);
        pending.put("r", p.redirectUri);
        pending.put("c", clock.instant().getEpochSecond());
        String cookieValue = Paseto.b64urlEncode(pending.toString().getBytes(StandardCharsets.UTF_8));

        return new Redirect(
            baseUrl + PATH_AUTHORIZE + "?" + encodeQuery(query),
            state,
            // Lax rather than Strict: the browser returns from Anubis's origin
            // by top-level navigation, and Strict would withhold the cookie on
            // exactly the request that needs it.
            LOGIN_COOKIE + "=" + cookieValue + "; Path=/; Max-Age=" + LOGIN_TTL.toSeconds()
                + "; HttpOnly; Secure; SameSite=Lax");
    }

    /**
     * Handle the callback: check the state, exchange the code, return tokens.
     *
     * <p>The state comparison happens before anything is exchanged, and there
     * is no option that turns it off. A caller cannot forget a check that was
     * never theirs to make.
     *
     * @param query   the callback's query parameters
     * @param cookies the request's cookies
     */
    public Tokens completeLogin(Map<String, String> query, Map<String, String> cookies) {
        String error = query.get("error");
        if (error != null && !error.isEmpty()) {
            throw new ApiException(error, query.getOrDefault("error_description", ""), "", 400, Map.of());
        }
        String raw = cookies.get(LOGIN_COOKIE);
        if (raw == null || raw.isEmpty()) {
            throw new StateMismatchException("no login in progress for this browser");
        }
        JsonNode pending;
        try {
            pending = json.readTree(new String(Paseto.b64urlDecode(raw), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new StateMismatchException("login cookie is unreadable");
        }
        if (clock.instant().getEpochSecond() - pending.path("c").asLong() > LOGIN_TTL.toSeconds()) {
            throw new StateMismatchException("the sign-in took longer than " + LOGIN_TTL);
        }
        // Constant time: the comparison is against an attacker-supplied value,
        // and a state that leaks byte by byte is a state that can be guessed.
        if (!MessageDigest.isEqual(
            pending.path("s").asText("").getBytes(StandardCharsets.UTF_8),
            query.getOrDefault("state", "").getBytes(StandardCharsets.UTF_8))) {
            throw new StateMismatchException("callback state is not the one this browser was sent with");
        }
        String code = query.getOrDefault("code", "");
        if (code.isEmpty()) {
            throw new StateMismatchException("callback carried no code");
        }

        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("code_verifier", pending.path("v").asText());
        form.put("redirect_uri", pending.path("r").asText());
        form.put("client_id", clientId);
        // Sent because the discovery document advertises client_secret_post.
        // The token endpoint does not currently verify it — PKCE is what binds
        // the exchange — so this is forward compatibility, not the proof.
        putIf(form, "client_secret", clientSecret);

        JsonNode body = send(PATH_TOKEN, "application/x-www-form-urlencoded", encodeQuery(form), null);
        // The browser endpoint answers snake_case, unlike every Connect
        // procedure. That asymmetry is the server's, and a client carries it.
        return new Tokens(
            body.path("access_token").asText(""),
            body.path("refresh_token").asText(""),
            body.path("token_type").asText("Bearer"),
            body.path("expires_in").asInt(0),
            body.path("session_id").asText(""),
            clock.instant());
    }

    /** The Set-Cookie value that clears the login cookie after a callback. */
    public String clearLoginCookie() {
        return LOGIN_COOKIE + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax";
    }

    // ---- decisions --------------------------------------------------------

    /**
     * Ask whether the verified caller may do something; throw if not.
     *
     * <p>The subject, amr and auth_time are read from the principal the
     * verifier produced. A caller assembling this by hand leaves amr and
     * auth_time out, and that turns every step-up rule into a silent permanent
     * denial that looks like a permissions bug.
     */
    public void require(Principal principal, Permission permission, Scopes scopes) {
        authorize(principal, permission, scopes).orThrow();
    }

    /** Convenience for a permission written inline. */
    public void require(Principal principal, String permission, Scopes scopes) {
        require(principal, Permission.of(permission), scopes);
    }

    /** The same question, answered as data. */
    public Decision authorize(Principal principal, Permission permission, Scopes scopes) {
        if (permission == null || !permission.isValid()) {
            // Caught here rather than answered with a denial, because a denial
            // for a permission that cannot exist is indistinguishable from one
            // for a permission the caller does not hold.
            throw new IllegalArgumentException(
                "anubis: \"" + permission + "\" is not a permission key — expected app:resource:action");
        }
        Identity identity = principal.identity();
        ObjectNode req = json.createObjectNode();
        req.put("subject", identity.subject());
        req.put("permission", permission.key());
        req.set("scopes", json.valueToTree(scopes == null ? Map.of() : scopes.toWire()));
        req.set("amr", json.valueToTree(identity.methods().toStrings()));
        req.put("auth_time", principal.claims().authTime());

        JsonNode out = rpc(PROC_AUTHORIZE, req, principal.token());
        return new Decision(
            out.path("allow").asBoolean(false),
            out.path("reason").asText(""),
            out.path("failingAxis").asText(""),
            out.path("message").asText(""),
            AuthMethods.of(strings(out.path("requiredAmr"))),
            out.path("maxAuthAge").asText(""),
            AuthMethods.of(strings(out.path("currentAmr"))),
            out.path("authAge").asText(""),
            permission);
    }

    /** Convenience for a permission written inline. */
    public Decision authorize(Principal principal, String permission, Scopes scopes) {
        return authorize(principal, Permission.of(permission), scopes);
    }

    /**
     * The full evaluation tree. Reach for it the moment a denial is not
     * obvious: past two axes, "why" stops being answerable by reading grants.
     */
    public JsonNode explain(Principal principal, Permission permission, Scopes scopes) {
        ObjectNode req = json.createObjectNode();
        req.put("subject", principal.subject());
        req.put("permission", permission.key());
        req.set("scopes", json.valueToTree(scopes == null ? Map.of() : scopes.toWire()));
        return rpc(PROC_EXPLAIN, req, principal.token());
    }

    /**
     * Turn a step-up refusal into the sign-in redirect that satisfies it. It is
     * a fresh authorization request, because that is what re-authentication is.
     */
    public Redirect beginStepUp(StepUpRequiredException e, LoginParams p) {
        p.prompt = "login";
        if (p.acrValues.isEmpty()) {
            p.acrValues = e.requiredAmr().toStrings();
        }
        if (p.maxAge == 0) {
            java.time.Duration max = e.maxAuthAgeDuration();
            if (max != null) {
                p.maxAge = (int) max.toSeconds();
            }
        }
        return beginLogin(p);
    }

    // ---- sessions ---------------------------------------------------------

    /**
     * Rotate a pair once.
     *
     * <p>Prefer {@link #tokenSource}, which serialises this. Calling refresh
     * directly from concurrent request handlers is how a client reports itself
     * for theft.
     */
    public Tokens refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("anubis: refresh needs a refresh token");
        }
        ObjectNode req = json.createObjectNode();
        req.put("refresh_token", refreshToken);
        JsonNode out = rpc(PROC_REFRESH, req, null);
        return tokensFromConnect(out.path("tokens"));
    }

    /** Wrap a pair so it stays fresh, with single-flight rotation. */
    public TokenSource tokenSource(Tokens initial) {
        return new TokenSource(current -> refresh(current.refreshToken()), initial, clock, true);
    }

    /**
     * Mint a token for the application acting as itself.
     *
     * <p>Returns a TokenSource rather than a token because these are
     * short-lived and have no refresh token: the only correct handling is to
     * re-mint on expiry, and that should not be every caller's job to remember.
     */
    public TokenSource clientCredentials(String audience) {
        if (clientId.isEmpty() || clientSecret.isEmpty()) {
            throw new IllegalArgumentException("anubis: client credentials need a client id and secret");
        }
        java.util.function.Function<Tokens, Tokens> mint = ignored -> {
            ObjectNode req = json.createObjectNode();
            req.put("tenant", tenant);
            req.put("client_id", clientId);
            req.put("client_secret", clientSecret);
            req.put("audience", audience == null ? "" : audience);
            JsonNode out = rpc(PROC_CLIENT_CREDENTIALS, req, null);
            return new Tokens(
                out.path("accessToken").asText(""),
                "",
                out.path("tokenType").asText("Bearer"),
                out.path("expiresIn").asInt(0),
                "",
                clock.instant());
        };
        TokenSource ts = new TokenSource(mint, null, clock, false);
        ts.token();
        return ts;
    }

    public Tokens verifyMfa(String mfaToken, String code) {
        ObjectNode req = json.createObjectNode();
        req.put("mfa_token", mfaToken);
        req.put("code", code);
        return tokensFromConnect(rpc(PROC_VERIFY_MFA, req, null).path("tokens"));
    }

    /**
     * Live token state, including revocation.
     *
     * <p>Offline verification cannot see a session that died before the token
     * expired. This closes that window, at the price of a network hop on the
     * path — so it stays an explicit call, never something a filter does.
     */
    public JsonNode introspect(String token, Principal principal) {
        ObjectNode req = json.createObjectNode();
        req.put("token", token);
        return rpc(PROC_INTROSPECT, req, principal == null ? null : principal.token());
    }

    public void logoutAll(Principal principal) {
        rpc(PROC_LOGOUT_ALL, json.createObjectNode(), principal.token());
    }

    /**
     * Where to send the browser to sign out.
     *
     * <p>Anubis answers the GET by rendering its sign-out page and ASKING. That
     * confirmation is not politeness: a bare GET that ends sessions is
     * reachable from any page on the internet with an img tag.
     */
    public String logoutUrl(String postLogoutRedirectUri, String page) {
        Map<String, String> query = new LinkedHashMap<>();
        putIf(query, "tenant", tenant);
        putIf(query, "post_logout_redirect_uri", postLogoutRedirectUri);
        putIf(query, "page", page);
        return query.isEmpty() ? baseUrl + PATH_LOGOUT : baseUrl + PATH_LOGOUT + "?" + encodeQuery(query);
    }

    /** A back-channel logout notification. */
    public record LogoutEvent(String sessionId, String subject, String tenant) {}

    /**
     * Verify a back-channel logout token and return the event.
     *
     * <p>The event-claim check is what stops somebody replaying a captured
     * ACCESS token here to sign a user out at will: an access token passes
     * every other check, because the same issuer minted it for the same
     * audience.
     */
    public static LogoutEvent verifyLogoutToken(Verifier verifier, String token, ObjectMapper mapper) {
        Claims claims = verifier.verify(token);
        // Safe to read the raw message now: the signature covering it is checked.
        Paseto.Parsed parsed = Paseto.parse(token);
        JsonNode body;
        try {
            body = mapper.readTree(parsed.messageString());
        } catch (Exception e) {
            throw new AnubisException("anubis: logout token body: " + e.getMessage());
        }
        if (!body.path("events").has("http://schemas.openid.net/event/backchannel-logout")) {
            throw new AnubisException("anubis: not a back-channel logout token (no logout event claim)");
        }
        String sid = body.path("sid").asText("");
        return new LogoutEvent(sid.isEmpty() ? claims.session() : sid, claims.subject(), claims.tenant());
    }

    // ---- transport --------------------------------------------------------

    private Tokens tokensFromConnect(JsonNode t) {
        if (t == null || t.isMissingNode() || t.isNull()) {
            throw new AnubisException("anubis: the call returned no tokens");
        }
        return new Tokens(
            t.path("accessToken").asText(""),
            t.path("refreshToken").asText(""),
            t.path("tokenType").asText("Bearer"),
            t.path("expiresIn").asInt(0),
            t.path("sessionId").asText(""),
            clock.instant());
    }

    /**
     * Request fields go out with their proto names (snake_case). protojson
     * accepts those as well as lowerCamelCase, and they are what the API
     * documentation shows.
     */
    private JsonNode rpc(String procedure, JsonNode body, String bearer) {
        String credential = !apiKey.isEmpty() ? apiKey : bearer;
        return send(procedure, "application/json", body.toString(), credential);
    }

    private JsonNode send(String path, String contentType, String body, String credential) {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(timeout)
            .header("content-type", contentType)
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (credential != null && !credential.isEmpty()) {
            req.header("authorization", "Bearer " + credential);
        }
        if (!tenant.isEmpty()) {
            req.header("x-anubis-tenant", tenant);
        }
        headers.forEach(req::header);

        HttpResponse<String> res;
        try {
            res = http.send(req.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UnavailableException("interrupted", e);
        } catch (Exception e) {
            // A transport failure is indistinguishable from an installation
            // that is down, and both are retryable, so both get one type.
            throw new UnavailableException(e.getMessage(), e);
        }
        if (res.statusCode() != 200) {
            throw classify(parseWireError(res.body(), res.statusCode()), res);
        }
        try {
            return res.body().isBlank() ? json.createObjectNode() : json.readTree(res.body());
        } catch (Exception e) {
            throw new AnubisException("anubis: decoding response: " + e.getMessage(), e);
        }
    }

    /**
     * Turn a refusal into something a caller can act on.
     *
     * <p>Reuse detection is checked first and deliberately not folded in with
     * the other authentication failures: every other one means "try again with
     * a better credential", and this one means "stop, you have been robbed".
     */
    private static RuntimeException classify(ApiException e, HttpResponse<String> res) {
        String code = e.errorCode();
        if (code.isEmpty()) {
            code = switch (e.status()) {
                case 429 -> "rate_limited";
                case 401 -> "unauthenticated";
                case 403 -> "permission_denied";
                case 503 -> "unavailable";
                default -> "";
            };
        }
        return switch (code) {
            case "refresh_token_reuse_detected" -> new RefreshReuseException(e);
            case "rate_limited" -> new RateLimitedException(retryAfter(res), e);
            case "unavailable" -> new UnavailableException(e.getMessage(), e);
            case "unauthenticated", "invalid_token", "invalid_credentials",
                 "permission_denied", "session_revoked", "invalid_refresh_token" ->
                new AuthException(code, e.getMessage(), e.requestId(), e.status(), e.details());
            default -> e;
        };
    }

    private static Duration retryAfter(HttpResponse<String> res) {
        return res.headers().firstValue("retry-after")
            .map(v -> {
                try {
                    return Duration.ofSeconds(Long.parseLong(v.trim()));
                } catch (NumberFormatException e) {
                    // A header this client cannot read is not a reason to call
                    // the refusal something else — it is still a rate limit.
                    return Duration.ZERO;
                }
            })
            .orElse(Duration.ZERO);
    }

    /**
     * Covers both shapes Anubis answers with: the Connect error object and the
     * plain-HTTP envelope. One vocabulary, two transports — but not one field
     * name for the code.
     */
    private ApiException parseWireError(String raw, int status) {
        JsonNode w;
        try {
            w = json.readTree(raw);
        } catch (Exception e) {
            String message = raw == null ? "" : raw.strip();
            return new ApiException("", message.length() > 512 ? message.substring(0, 512) : message,
                "", status, Map.of());
        }
        String code = w.path("error").asText(w.path("code").asText(""));
        String requestId = w.path("request_id").asText("");
        Map<String, String> details = new HashMap<>();

        JsonNode d = w.path("details");
        if (d.isArray()) {
            // Connect puts the stable domain code in a base64 protobuf
            // anubis.v1.ErrorInfo, because its own `code` field carries only
            // the coarse transport class.
            for (JsonNode item : d) {
                if (!item.path("type").asText("").endsWith("ErrorInfo")) {
                    continue;
                }
                ErrorInfo info = decodeErrorInfo(item.path("value").asText(""));
                if (!info.code.isEmpty()) {
                    code = info.code;
                }
                if (!info.requestId.isEmpty()) {
                    requestId = info.requestId;
                }
                details.clear();
                details.putAll(info.details);
            }
        } else if (d.isObject()) {
            // Mutated rather than reassigned: the lambda below captures it, and
            // a captured local has to stay effectively final.
            d.fields().forEachRemaining(f -> details.put(f.getKey(), f.getValue().asText("")));
        }
        return new ApiException(code, w.path("message").asText(""), requestId, status, details);
    }

    private static final class ErrorInfo {
        String code = "";
        String requestId = "";
        Map<String, String> details = new HashMap<>();
    }

    /**
     * Read anubis.v1.ErrorInfo straight off the protobuf wire.
     *
     * <p>Depending on a protobuf runtime to read three fields would cost every
     * consumer that dependency tree, for a message that is three fields and
     * will not grow a fourth without a proto change.
     *
     * <pre>string code = 1; string request_id = 2; map&lt;string,string&gt; details = 3;</pre>
     */
    private static ErrorInfo decodeErrorInfo(String b64) {
        ErrorInfo out = new ErrorInfo();
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return out;
        }
        int i = 0;
        while (i < raw.length) {
            long[] tag = varint(raw, i);
            if (tag[1] == 0 || (tag[0] & 7) != 2) {
                return out;
            }
            i += (int) tag[1];
            long[] size = varint(raw, i);
            if (size[1] == 0) {
                return out;
            }
            i += (int) size[1];
            int len = (int) size[0];
            if (i + len > raw.length) {
                return out;
            }
            String payload = new String(raw, i, len, StandardCharsets.UTF_8);
            byte[] slice = java.util.Arrays.copyOfRange(raw, i, i + len);
            i += len;

            int field = (int) (tag[0] >> 3);
            if (field == 1) {
                out.code = payload;
            } else if (field == 2) {
                out.requestId = payload;
            } else if (field == 3) {
                // A map entry is key = field 1, value = field 2: the same shapes.
                ErrorInfo entry = decodeErrorInfo(Base64.getEncoder().encodeToString(slice));
                if (!entry.code.isEmpty()) {
                    out.details.put(entry.code, entry.requestId);
                }
            }
        }
        return out;
    }

    /** @return {value, byteCount}, or {0, 0} on truncation. */
    private static long[] varint(byte[] b, int at) {
        long value = 0;
        int shift = 0;
        for (int i = at; i < b.length && i - at < 10; i++) {
            int byteValue = b[i] & 0xFF;
            value |= (long) (byteValue & 0x7F) << shift;
            if ((byteValue & 0x80) == 0) {
                return new long[] {value, i - at + 1};
            }
            shift += 7;
        }
        return new long[] {0, 0};
    }

    // ---- small helpers ----------------------------------------------------

    private String randomToken() {
        byte[] b = new byte[32];
        random.nextBytes(b);
        return Paseto.b64urlEncode(b);
    }

    private static String s256(String verifier) {
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.UTF_8));
            return Paseto.b64urlEncode(sum);
        } catch (Exception e) {
            throw new AnubisException("anubis: SHA-256 unavailable", e);
        }
    }

    private static void putIf(Map<String, String> map, String key, String value) {
        if (value != null && !value.isEmpty()) {
            map.put(key, value);
        }
    }

    private static String encodeQuery(Map<String, String> values) {
        StringBuilder b = new StringBuilder();
        values.forEach((k, v) -> {
            if (b.length() > 0) {
                b.append('&');
            }
            b.append(URLEncoder.encode(k, StandardCharsets.UTF_8))
                .append('=')
                .append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        return b.toString();
    }

    private static List<String> strings(JsonNode node) {
        List<String> out = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(n -> out.add(n.asText("")));
        }
        return List.copyOf(out);
    }

    public static final class Builder {
        private final String baseUrl;
        private String clientId;
        private String clientSecret;
        private String apiKey;
        private String tenant;
        private Duration timeout = Duration.ofSeconds(10);
        private final Map<String, String> headers = new LinkedHashMap<>();
        private HttpClient http;
        private ObjectMapper json;
        private Clock clock;

        Builder(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        /** The registered application slug — also its client_id. */
        public Builder application(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret == null || clientSecret.isEmpty() ? null : clientSecret;
            return this;
        }

        /** anb_live_ tenant key. The tenant's credential, not a person's. */
        public Builder apiKey(String v) {
            this.apiKey = v;
            return this;
        }

        public Builder tenant(String v) {
            this.tenant = v;
            return this;
        }

        public Builder timeout(Duration v) {
            this.timeout = v;
            return this;
        }

        public Builder header(String name, String value) {
            if ("authorization".equalsIgnoreCase(name)) {
                throw new IllegalArgumentException("anubis: set the credential with apiKey, not with header");
            }
            this.headers.put(name, value);
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

        public Builder clock(Clock v) {
            this.clock = v;
            return this;
        }

        public Client build() {
            return new Client(this);
        }
    }
}
