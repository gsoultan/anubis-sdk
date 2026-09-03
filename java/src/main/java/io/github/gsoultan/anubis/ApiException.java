package io.github.gsoultan.anubis;

import java.util.Map;

/**
 * A refusal with no more specific type.
 *
 * <p>{@code errorCode} is the stable machine-readable string from the error
 * envelope — the same vocabulary on both transports — and {@code requestId}
 * correlates to audit_log and traces, which is the first thing anyone asks for.
 */
public class ApiException extends AnubisException {
    private final String errorCode;
    private final String requestId;
    private final int status;
    private final Map<String, String> details;

    public ApiException(String errorCode, String message, String requestId, int status, Map<String, String> details) {
        super(!message.isEmpty() ? message : (!errorCode.isEmpty() ? errorCode : "http " + status));
        this.errorCode = errorCode;
        this.requestId = requestId;
        this.status = status;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    public String errorCode() {
        return errorCode;
    }

    public String requestId() {
        return requestId;
    }

    public int status() {
        return status;
    }

    public Map<String, String> details() {
        return details;
    }
}
