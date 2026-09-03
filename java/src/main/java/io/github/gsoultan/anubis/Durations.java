package io.github.gsoultan.anubis;

import java.time.Duration;

/**
 * Durations Anubis expresses as strings ("2m").
 *
 * <p>One parser, used by every refusal that carries one, so a caller comparing
 * durations never has to write it a second time. Returns null rather than zero
 * for an unparseable value: zero would read as "no maximum age", which is the
 * opposite of what an unreadable one means.
 */
final class Durations {
    private Durations() {}

    static Duration parse(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        char unit = trimmed.charAt(trimmed.length() - 1);
        try {
            long n = Long.parseLong(trimmed.substring(0, trimmed.length() - 1));
            return switch (unit) {
                case 's' -> Duration.ofSeconds(n);
                case 'm' -> Duration.ofMinutes(n);
                case 'h' -> Duration.ofHours(n);
                default -> null;
            };
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
