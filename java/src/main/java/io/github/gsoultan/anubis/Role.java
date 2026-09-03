package io.github.gsoultan.anubis;

import java.util.Objects;

/**
 * A granted role, which Anubis returns prefixed with the application that
 * defined it: a manifest declaring {@code clerk} for {@code billing} yields
 * {@code billing.clerk}.
 *
 * <p>Comparing a returned role against the unprefixed manifest name is the
 * mistake this type exists to make visible.
 */
public final class Role {
    private final String value;

    private Role(String value) {
        this.value = value == null ? "" : value;
    }

    public static Role of(String role) {
        return new Role(role);
    }

    public static Role from(String app, String name) {
        return new Role(app + "." + name);
    }

    public String value() {
        return value;
    }

    /** The application that defined the role, or "" for an unprefixed one. */
    public String app() {
        int dot = value.indexOf('.');
        return dot < 0 ? "" : value.substring(0, dot);
    }

    /** The role as the manifest declared it, without the prefix. */
    public String name() {
        int dot = value.indexOf('.');
        return dot < 0 ? value : value.substring(dot + 1);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Role other && value.equals(other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
