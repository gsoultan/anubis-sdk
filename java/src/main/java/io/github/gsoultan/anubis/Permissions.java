package io.github.gsoultan.anubis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * An effective permission set — what a caller may do, expanded from every role
 * they hold.
 */
public final class Permissions implements Iterable<Permission> {
    private static final Permissions EMPTY = new Permissions(List.of());

    private final List<Permission> items;

    private Permissions(List<Permission> items) {
        this.items = List.copyOf(items);
    }

    public static Permissions empty() {
        return EMPTY;
    }

    public static Permissions of(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            return EMPTY;
        }
        List<Permission> out = new ArrayList<>(permissions.size());
        for (String p : permissions) {
            out.add(Permission.of(p));
        }
        return new Permissions(out);
    }

    public boolean has(Permission permission) {
        return items.contains(permission);
    }

    public boolean has(String permission) {
        return has(Permission.of(permission));
    }

    public boolean hasAny(String... permissions) {
        for (String p : permissions) {
            if (has(p)) {
                return true;
            }
        }
        return false;
    }

    public Permissions ofApp(String app) {
        List<Permission> out = new ArrayList<>();
        for (Permission p : items) {
            if (p.app().equals(app)) {
                out.add(p);
            }
        }
        return new Permissions(out);
    }

    public List<String> toStrings() {
        List<String> out = new ArrayList<>(items.size());
        for (Permission p : items) {
            out.add(p.key());
        }
        return Collections.unmodifiableList(out);
    }

    public int size() {
        return items.size();
    }

    @Override
    public Iterator<Permission> iterator() {
        return items.iterator();
    }
}
