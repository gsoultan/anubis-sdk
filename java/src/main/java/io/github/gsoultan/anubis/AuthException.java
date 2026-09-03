package io.github.gsoultan.anubis;

import java.util.Map;

/** The credential was missing, rejected, or lacks the scope the call needs. */
public final class AuthException extends ApiException {
    public AuthException(String errorCode, String message, String requestId, int status, Map<String, String> details) {
        super(errorCode, message, requestId, status, details);
    }
}
