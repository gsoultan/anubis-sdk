package io.github.gsoultan.anubis;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * The methods a caller authenticated with — the {@code amr} claim.
 *
 * <p>Step-up decisions turn on it, which is why it travels on every
 * authorization request.
 */
public final class AuthMethods implements Iterable<String> {
    /**
     * The methods Anubis mints today. A realm may require others later, so the
     * type stays open — these are the ones worth having a name for.
     */
    public static final String PASSWORD = "pwd";

    public static final String OTP = "otp";
    public static final String DEVICE_KEY = "device_key";

    private static final AuthMethods EMPTY = new AuthMethods(List.of());

    private final List<String> items;

    private AuthMethods(List<String> items) {
        this.items = List.copyOf(items);
    }

    public static AuthMethods empty() {
        return EMPTY;
    }

    public static AuthMethods of(List<String> methods) {
        return methods == null || methods.isEmpty() ? EMPTY : new AuthMethods(methods);
    }

    public static AuthMethods of(String... methods) {
        return methods.length == 0 ? EMPTY : new AuthMethods(List.of(methods));
    }

    public boolean has(String method) {
        return items.contains(method);
    }

    /**
     * Every listed method was used — the local form of a step-up check,
     * answerable without asking Anubis.
     */
    public boolean hasAll(String... methods) {
        for (String m : methods) {
            if (!has(m)) {
                return false;
            }
        }
        return true;
    }

    public List<String> toStrings() {
        return Collections.unmodifiableList(items);
    }

    public int size() {
        return items.size();
    }

    public boolean isEmpty() {
        return items.isEmpty();
    }

    @Override
    public Iterator<String> iterator() {
        return items.iterator();
    }

    @Override
    public String toString() {
        return String.join(" ", items);
    }
}
