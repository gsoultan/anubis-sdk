package io.github.gsoultan.anubis;

/**
 * Anubis could not be reached, or answered that it is not ready. Retry with
 * backoff.
 *
 * <p>A readiness refusal is deliberate: an instance whose snapshot has outlived
 * its maximum age fails /readyz first, so it leaves the load balancer before it
 * starts denying decisions.
 */
public final class UnavailableException extends AnubisException {
    public UnavailableException(String message, Throwable cause) {
        super("anubis: unavailable: " + message, cause);
    }
}
