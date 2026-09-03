package io.github.gsoultan.anubis;

/**
 * A consumed refresh token was presented again.
 *
 * <p>Do not retry. Two parties held this token and one of them is an attacker;
 * the family and the session are already revoked. Drop the session, send the
 * user to sign in, and alert — this is a security event, not a transient
 * failure. It is the one exception here that carries no retry advice, because
 * there is none.
 */
public final class RefreshReuseException extends AnubisException {
    private final ApiException cause;

    public RefreshReuseException(ApiException cause) {
        super("anubis: refresh token reuse detected — family and session revoked, this is theft");
        this.cause = cause;
    }

    public ApiException apiCause() {
        return cause;
    }
}
