package io.github.gsoultan.anubis;

/**
 * Anubis answered, and the answer was no.
 *
 * <p>{@code failingAxis} is always named on a scope refusal: a deny nobody can
 * explain is a support ticket.
 */
public final class DeniedException extends AnubisException {
    private final String reason;
    private final String failingAxis;
    private final Permission permission;

    public DeniedException(String reason, String failingAxis, String message, Permission permission) {
        super(!message.isEmpty() ? message : reason);
        this.reason = reason;
        this.failingAxis = failingAxis;
        this.permission = permission;
    }

    public String reason() {
        return reason;
    }

    public String failingAxis() {
        return failingAxis;
    }

    public Permission permission() {
        return permission;
    }
}
