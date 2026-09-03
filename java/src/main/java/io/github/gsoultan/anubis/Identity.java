package io.github.gsoultan.anubis;

import java.time.Duration;
import java.time.Instant;

/**
 * Who a caller is and what they hold, in one place.
 *
 * <p>It answers the question every application asks first — who is this, what
 * roles do they have, what are they scoped to right now — without reaching into
 * a claim set and remembering which fields mean what.
 *
 * <p>It is a VIEW OF A SESSION, not of a person. {@code roles} and
 * {@code scopes} are what this token was minted with: the roles held at
 * issuance, and the ONE node per axis the session is currently acting as. It is
 * not the full set of nodes the person is entitled to — that lives in grants,
 * on the admin plane.
 */
public record Identity(
    String subject,
    String session,
    String tenant,
    String realm,
    Roles roles,
    Scopes scopes,
    AuthMethods methods,
    int assurance,
    Instant authenticatedAt,
    Instant expiresAt) {

    public Identity {
        subject = subject == null ? "" : subject;
        session = session == null ? "" : session;
        tenant = tenant == null ? "" : tenant;
        realm = realm == null ? "" : realm;
        roles = roles == null ? Roles.empty() : roles;
        scopes = scopes == null ? Scopes.empty() : scopes;
        methods = methods == null ? AuthMethods.empty() : methods;
    }

    /**
     * How long ago the caller authenticated.
     *
     * <p>Measured from authentication, not issuance: a refresh mints a new
     * token with no fresh proof of identity, which is exactly why a step-up
     * rule with a maximum age is decided against this.
     */
    public Duration authAge() {
        return authenticatedAt == null ? Duration.ZERO : Duration.between(authenticatedAt, Instant.now());
    }

    /** A service acting as itself rather than a person: no session, no refresh. */
    public boolean isApplication() {
        return subject.startsWith("app_");
    }

    /**
     * The cheap local check. It answers "does this token say so", which is not
     * the same question as "may they do this" — roles are an input to a
     * decision, not the decision. Reach for {@code Client.require} when it
     * matters.
     */
    public boolean hasRole(String role) {
        return roles.has(role);
    }

    /** The node this session is acting as on one axis. */
    public String activeScope(String axis) {
        return scopes.node(axis);
    }

    @Override
    public String toString() {
        return scopes.isEmpty() ? subject : subject + " [" + scopes + "]";
    }
}
