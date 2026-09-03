package io.github.gsoultan.anubis;

import java.time.Duration;

/**
 * A denial the caller can do something about: the subject holds the permission
 * but has not authenticated strongly enough, or recently enough.
 *
 * <p>Machine-readable so the application does not guess. Feed it to
 * {@code Client.beginStepUp} and send the user back through sign-in; do not
 * invent a second factor of your own.
 */
public final class StepUpRequiredException extends AnubisException {
    private final AuthMethods requiredAmr;
    private final AuthMethods currentAmr;
    private final String maxAuthAge;
    private final String authAge;
    private final Permission permission;

    public StepUpRequiredException(
        AuthMethods requiredAmr, AuthMethods currentAmr, String maxAuthAge, String authAge, Permission permission) {
        super("anubis: step-up required for " + permission
            + ": have [" + currentAmr + "], need [" + requiredAmr + "]");
        this.requiredAmr = requiredAmr;
        this.currentAmr = currentAmr;
        this.maxAuthAge = maxAuthAge;
        this.authAge = authAge;
        this.permission = permission;
    }

    public AuthMethods requiredAmr() {
        return requiredAmr;
    }

    public AuthMethods currentAmr() {
        return currentAmr;
    }

    /**
     * How fresh the authentication has to be. Anubis sends it as a string; a
     * caller comparing durations should not have to parse it.
     */
    public Duration maxAuthAgeDuration() {
        return Durations.parse(maxAuthAge);
    }

    public String maxAuthAge() {
        return maxAuthAge;
    }

    public String authAge() {
        return authAge;
    }

    public Permission permission() {
        return permission;
    }
}
