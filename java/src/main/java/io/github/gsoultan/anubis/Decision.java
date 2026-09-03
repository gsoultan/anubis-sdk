package io.github.gsoultan.anubis;

import java.time.Duration;

/**
 * Anubis's answer.
 *
 * <p>A denial is an answer, not a failure: the reason and the failing axis are
 * always populated on a refusal, because a deny nobody can explain is a support
 * ticket.
 */
public record Decision(
    boolean allow,
    String reason,
    String failingAxis,
    String message,
    AuthMethods requiredAmr,
    String maxAuthAge,
    AuthMethods currentAmr,
    String authAge,
    Permission permission) {

    public boolean needsStepUp() {
        return "step_up_required".equals(reason);
    }

    /**
     * How fresh the authentication has to be. Anubis sends it as a string; a
     * caller comparing durations should not have to parse it.
     */
    public Duration maxAuthAgeDuration() {
        return Durations.parse(maxAuthAge);
    }

    /** Throws the typed refusal, or returns cleanly when allowed. */
    public void orThrow() {
        if (allow) {
            return;
        }
        if (needsStepUp()) {
            throw new StepUpRequiredException(requiredAmr, currentAmr, maxAuthAge, authAge, permission);
        }
        throw new DeniedException(reason, failingAxis, message, permission);
    }
}
