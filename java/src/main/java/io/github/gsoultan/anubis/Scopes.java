package io.github.gsoultan.anubis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The target node on each axis an action touches.
 *
 * <p>Supply every axis the action could be constrained on. Within an axis, any
 * granted node at or above the target satisfies it; across axes, all must hold.
 * On a strict axis an omitted axis is DENIED, not ignored — fail-closed is the
 * whole design, and "I forgot an axis" and "they may not do this" are the same
 * answer from outside.
 *
 * <p>Immutable: {@link #with} and {@link #merge} return copies, so a scope set
 * shared between handlers cannot change underneath one of them.
 */
public final class Scopes {
    /** The reserved axis for self-scoped access: the owner of the record. */
    public static final String OWNER_AXIS = "_owner";

    private static final Scopes EMPTY = new Scopes(Map.of());

    private final Map<String, String> entries;

    private Scopes(Map<String, String> entries) {
        this.entries = Map.copyOf(entries);
    }

    public static Scopes empty() {
        return EMPTY;
    }

    public static Scopes of(Map<String, String> entries) {
        return entries == null || entries.isEmpty() ? EMPTY : new Scopes(entries);
    }

    public static Scopes of(String axis, String node) {
        return new Scopes(Map.of(axis, node));
    }

    public static Scopes of(String a1, String n1, String a2, String n2) {
        return new Scopes(Map.of(a1, n1, a2, n2));
    }

    /**
     * The scope set for self-scoped access, naming the reserved axis so it
     * cannot be misspelt into a silent denial.
     */
    public static Scopes owner(String subject) {
        return new Scopes(Map.of(OWNER_AXIS, subject));
    }

    public Scopes with(String axis, String node) {
        Map<String, String> out = new LinkedHashMap<>(entries);
        out.put(axis, node);
        return new Scopes(out);
    }

    public Scopes merge(Scopes other) {
        if (other == null || other.isEmpty()) {
            return this;
        }
        Map<String, String> out = new LinkedHashMap<>(entries);
        out.putAll(other.entries);
        return new Scopes(out);
    }

    /** The node targeted on one axis, or null if the axis was not supplied. */
    public String node(String axis) {
        return entries.get(axis);
    }

    /** The axes supplied, sorted, so a scope set has one printable form. */
    public List<String> axes() {
        List<String> out = new ArrayList<>(entries.keySet());
        Collections.sort(out);
        return out;
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    public int size() {
        return entries.size();
    }

    /** The plain map the API expects. */
    public Map<String, String> toWire() {
        return entries;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Scopes other && entries.equals(other.entries);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(entries);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        for (String axis : axes()) {
            if (b.length() > 0) {
                b.append(' ');
            }
            b.append(axis).append('=').append(entries.get(axis));
        }
        return b.toString();
    }
}
