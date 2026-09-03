package io.github.gsoultan.anubis;

/** Base class, so a caller can catch everything this SDK throws. */
public class AnubisException extends RuntimeException {
    public AnubisException(String message) {
        super(message);
    }

    public AnubisException(String message, Throwable cause) {
        super(message, cause);
    }
}
