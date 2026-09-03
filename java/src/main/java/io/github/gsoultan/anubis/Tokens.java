package io.github.gsoultan.anubis;

import java.time.Duration;
import java.time.Instant;

/**
 * An issued credential pair.
 *
 * <p>The refresh token is single-use: every refresh returns a rotated pair and
 * kills the one presented. Store the new pair before discarding the old — see
 * {@link TokenSource}, which does that and is the only safe way to hold these
 * in a process serving concurrent requests.
 */
public record Tokens(
    String accessToken,
    String refreshToken,
    String tokenType,
    int expiresIn,
    String sessionId,
    Instant issuedAt) {

    public Instant expiry() {
        return issuedAt == null || expiresIn == 0 ? null : issuedAt.plusSeconds(expiresIn);
    }

    /** How long the access token is good for. */
    public Duration lifetime() {
        return Duration.ofSeconds(expiresIn);
    }

    /**
     * Whether this pair can be rotated. A client-credentials token cannot: it
     * is re-minted from the application's own secret instead.
     */
    public boolean hasRefresh() {
        return refreshToken != null && !refreshToken.isEmpty();
    }
}
