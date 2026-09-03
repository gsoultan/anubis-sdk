package io.github.gsoultan.anubis;

import java.time.Duration;

/**
 * The caller is asking faster than its limits allow. Nothing was done, so
 * repeating the call after {@code retryAfter} is safe.
 *
 * <p>Limits apply per IP, per account and per tenant. Seeing this on a sign-in
 * path may mean somebody is attacking that account rather than that your
 * traffic grew.
 */
public final class RateLimitedException extends AnubisException {
    private final Duration retryAfter;

    public RateLimitedException(Duration retryAfter, ApiException cause) {
        super("anubis: rate limited, retry after " + retryAfter);
        this.retryAfter = retryAfter;
        initCause(cause);
    }

    public Duration retryAfter() {
        return retryAfter;
    }
}
