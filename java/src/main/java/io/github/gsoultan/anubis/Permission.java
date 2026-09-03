package io.github.gsoultan.anubis;

import java.util.Objects;

/**
 * A full permission key: {@code app:resource:action}.
 *
 * <p>The full key is what tokens carry and what {@code authorize} takes. Inside
 * an application manifest the same permission is written WITHOUT the
 * application prefix — {@code invoice:approve} — and that asymmetry has cost
 * people real time. {@link #manifest()} makes the two forms convertible instead
 * of a thing to remember.
 */
public final class Permission {
    private final String key;
    private final String[] parts; // null when malformed

    private Permission(String key) {
        this.key = key == null ? "" : key;
        String[] segments = this.key.split(":", -1);
        boolean wellFormed = segments.length == 3;
        if (wellFormed) {
            for (String segment : segments) {
                if (segment.isEmpty()) {
                    wellFormed = false;
                    break;
                }
            }
        }
        this.parts = wellFormed ? segments : null;
    }

    public static Permission of(String key) {
        return new Permission(key);
    }

    public static Permission from(String app, String resource, String action) {
        return new Permission(app + ":" + resource + ":" + action);
    }

    public String key() {
        return key;
    }

    /** The application slug the permission belongs to, or "" when malformed. */
    public String app() {
        return parts == null ? "" : parts[0];
    }

    public String resource() {
        return parts == null ? "" : parts[1];
    }

    public String action() {
        return parts == null ? "" : parts[2];
    }

    /** Whether the key has the three non-empty parts Anubis requires. */
    public boolean isValid() {
        return parts != null;
    }

    /** The permission as a manifest writes it: {@code resource:action}. */
    public String manifest() {
        return parts == null ? key : parts[1] + ":" + parts[2];
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Permission other && key.equals(other.key);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(key);
    }

    @Override
    public String toString() {
        return key;
    }
}
