package io.github.gsoultan.anubis;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The access-token claim set.
 *
 * <p>{@code scopes} is a map, never fixed fields: adding a scope axis must not
 * change the token format.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Claims(
    @JsonProperty("iss") String issuer,
    @JsonProperty("sub") String subject,
    @JsonProperty("aud") List<String> audience,
    @JsonProperty("exp") long expires,
    @JsonProperty("iat") long issuedAt,
    @JsonProperty("nbf") long notBefore,
    @JsonProperty("jti") String tokenId,
    @JsonProperty("sid") String session,
    @JsonProperty("tid") String tenant,
    @JsonProperty("roles") List<String> roles,
    @JsonProperty("scp") String scope,
    @JsonProperty("scopes") Map<String, String> scopes,
    @JsonProperty("realm") String realm,
    @JsonProperty("ial") int ial,
    @JsonProperty("amr") List<String> amr,
    @JsonProperty("auth_time") long authTime,
    @JsonProperty("epoch") int epoch,
    @JsonProperty("ver") int version) {

    public Claims {
        audience = audience == null ? List.of() : List.copyOf(audience);
        roles = roles == null ? List.of() : List.copyOf(roles);
        amr = amr == null ? List.of() : List.copyOf(amr);
        scopes = scopes == null ? Map.of() : Map.copyOf(scopes);
    }

    /**
     * The claim set as a caller wants to read it: who this is, what they hold,
     * and what they are scoped to right now.
     *
     * <p>The record above mirrors the wire because that is its job — the times
     * are unix seconds there because they are unix seconds in the token.
     * Everything derived from them lives here.
     */
    public Identity identity() {
        return new Identity(
            subject,
            session,
            tenant,
            realm,
            Roles.of(roles),
            Scopes.of(scopes),
            AuthMethods.of(amr),
            ial,
            instant(authTime),
            instant(expires));
    }

    /** When this token stops being accepted. */
    public Instant expiresAt() {
        return instant(expires);
    }

    /** When this token was minted. */
    public Instant issuedAtTime() {
        return instant(issuedAt);
    }

    /**
     * When the caller last proved who they were.
     *
     * <p>Not the same as {@link #issuedAtTime()}: a refresh mints a new token
     * without any fresh proof of identity, which is exactly why step-up rules
     * with a maximum age are decided against this and not against issuance.
     */
    public Instant authenticatedAt() {
        return instant(authTime);
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean hasAmr(String method) {
        return amr.contains(method);
    }

    static Instant instant(long seconds) {
        return seconds == 0 ? null : Instant.ofEpochSecond(seconds);
    }
}
