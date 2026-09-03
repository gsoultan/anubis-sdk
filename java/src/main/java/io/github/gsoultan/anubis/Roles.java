package io.github.gsoultan.anubis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/** The set of roles a caller holds. */
public final class Roles implements Iterable<Role> {
    private static final Roles EMPTY = new Roles(List.of());

    private final List<Role> items;

    private Roles(List<Role> items) {
        this.items = List.copyOf(items);
    }

    public static Roles empty() {
        return EMPTY;
    }

    public static Roles of(List<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return EMPTY;
        }
        List<Role> out = new ArrayList<>(roles.size());
        for (String r : roles) {
            out.add(Role.of(r));
        }
        return new Roles(out);
    }

    public boolean has(Role role) {
        return items.contains(role);
    }

    public boolean has(String role) {
        return has(Role.of(role));
    }

    public boolean hasAny(String... roles) {
        for (String r : roles) {
            if (has(r)) {
                return true;
            }
        }
        return false;
    }

    /** Narrow to the roles one application defined. */
    public Roles ofApp(String app) {
        List<Role> out = new ArrayList<>();
        for (Role r : items) {
            if (r.app().equals(app)) {
                out.add(r);
            }
        }
        return new Roles(out);
    }

    public List<String> toStrings() {
        List<String> out = new ArrayList<>(items.size());
        for (Role r : items) {
            out.add(r.value());
        }
        return Collections.unmodifiableList(out);
    }

    public int size() {
        return items.size();
    }

    public boolean isEmpty() {
        return items.isEmpty();
    }

    @Override
    public Iterator<Role> iterator() {
        return items.iterator();
    }

    @Override
    public String toString() {
        return String.join(" ", toStrings());
    }
}
