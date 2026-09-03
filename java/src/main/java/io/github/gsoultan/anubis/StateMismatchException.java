package io.github.gsoultan.anubis;

/**
 * The callback's state did not match the one this client issued.
 *
 * <p>Treat it as an attack, not a bug: state binds the callback to the browser
 * that started the flow, and a mismatch is what CSRF against the sign-in flow
 * looks like. The code is not exchanged.
 */
public final class StateMismatchException extends AnubisException {
    public StateMismatchException(String reason) {
        super("anubis: login state did not match (" + reason + ") — refusing to exchange the code");
    }
}
