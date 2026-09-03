package io.github.gsoultan.anubis;

/**
 * A token was not acceptable: bad signature, wrong audience, expired, or a kid
 * this process does not hold.
 *
 * <p>Comes off the offline path, so it carries no request id — nothing was
 * asked of Anubis.
 */
public class VerificationException extends AnubisException {
    public VerificationException(String message) {
        super(message);
    }
}
