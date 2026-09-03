package io.github.gsoultan.anubis;

import java.time.Instant;

/**
 * What a verified request carries: the claim set, and the token it came from.
 *
 * <p>The accessors are the ones a handler reaches for. {@code claims} is still
 * there for anything they do not cover, but a handler reading
 * {@code claims.authTime()} and converting it by hand is doing work this type
 * already did.
 */
public record Principal(Claims claims, String token) {

    /** Who this caller is and what they hold. */
    public Identity identity() {
        return claims.identity();
    }

    public String subject() {
        return claims.subject();
    }

    /**
     * The signed-in device this token belongs to. Empty for a
     * client-credentials caller, which has no session by design.
     */
    public String session() {
        return claims.session();
    }

    public String tenant() {
        return claims.tenant();
    }

    /**
     * The roles this token was minted with, prefixed by the application that
     * defined them: {@code billing.clerk}, not {@code clerk}.
     */
    public Roles roles() {
        return Roles.of(claims.roles());
    }

    /**
     * The ACTIVE scope — one node per axis, what this session is acting as
     * right now. Not everything the person is entitled to; that lives in
     * grants, on the admin plane.
     */
    public Scopes scopes() {
        return Scopes.of(claims.scopes());
    }

    public AuthMethods methods() {
        return AuthMethods.of(claims.amr());
    }

    public Instant authenticatedAt() {
        return claims.authenticatedAt();
    }

    public Instant expiresAt() {
        return claims.expiresAt();
    }

    public boolean hasRole(String role) {
        return claims.hasRole(role);
    }
}
