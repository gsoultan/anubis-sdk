package io.github.gsoultan.anubis;

import java.time.Instant;

/**
 * The realm requires a factor this member has not enrolled, and the deadline
 * has passed. No session was issued — but the refusal carries the means to
 * comply, which is what makes it enrol-or-deny rather than deny.
 *
 * <p>Pass {@code grantToken} to the TOTP enrolment calls in place of a session:
 * the session is exactly what the policy is withholding.
 */
public final class EnrolmentRequiredException extends AnubisException {
    private final AuthMethods factors;
    private final Instant deadline;
    private final String grantToken;

    public EnrolmentRequiredException(AuthMethods factors, Instant deadline, String grantToken) {
        super("anubis: enrolment required for [" + factors + "] — use the grant token to enrol");
        this.factors = factors;
        this.deadline = deadline;
        this.grantToken = grantToken;
    }

    public AuthMethods factors() {
        return factors;
    }

    public Instant deadline() {
        return deadline;
    }

    public String grantToken() {
        return grantToken;
    }
}
