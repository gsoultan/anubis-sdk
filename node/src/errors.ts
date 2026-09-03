/**
 * One taxonomy, mapped from the stable code the server puts in the error body.
 * The body is authoritative over the HTTP status: a proxy is free to rewrite a
 * status, and some do.
 */

import { AuthMethods, Permission, parseAgeSeconds } from "./identity.js";

export class AnubisError extends Error {}

/** A refusal with no more specific type. */
export class ApiError extends AnubisError {
  constructor(
    readonly code: string,
    message: string,
    readonly requestId = "",
    readonly status = 0,
    readonly details: Record<string, string> = {},
  ) {
    super(message || code || `http ${status}`);
    this.name = "ApiError";
  }
}

/** Anubis answered, and the answer was no. */
export class DeniedError extends AnubisError {
  constructor(
    readonly reason: string,
    readonly failingAxis: string,
    message: string,
    readonly permission?: Permission,
  ) {
    super(message || reason);
    this.name = "DeniedError";
  }
}

/**
 * A denial the caller can do something about: strong enough authentication is
 * missing, or too old. Machine-readable so the application does not guess —
 * feed it to client.beginStepUp().
 */
export class StepUpRequiredError extends AnubisError {
  constructor(
    readonly requiredAmr: AuthMethods,
    readonly currentAmr: AuthMethods,
    readonly maxAuthAge: string,
    readonly authAge: string,
    readonly permission?: Permission,
  ) {
    super(`step-up required for ${permission ?? "?"}: have [${currentAmr}], need [${requiredAmr}]`);
    this.name = "StepUpRequiredError";
  }

  /** How fresh the authentication has to be, in seconds. Anubis sends it as a
   * string; a caller comparing durations should not have to parse it. */
  get maxAuthAgeSeconds(): number | undefined {
    return parseAgeSeconds(this.maxAuthAge);
  }
}

/**
 * A consumed refresh token was presented again.
 *
 * Do not retry. Two parties held this token and one is an attacker; the family
 * and session are already revoked. Drop the session and alert. This is the one
 * error here that carries no retry advice, because there is none.
 */
export class RefreshReuseError extends AnubisError {
  constructor(readonly cause: ApiError) {
    super("refresh token reuse detected — family and session revoked, this is theft");
    this.name = "RefreshReuseError";
  }
}

/** The credential was missing, rejected, or lacks the scope. */
export class AuthError extends AnubisError {
  constructor(readonly cause: ApiError) {
    super(`the credential was not accepted: ${cause.message}`);
    this.name = "AuthError";
  }
}

/** Nothing was done, so repeating after retryAfter seconds is safe. */
export class RateLimitedError extends AnubisError {
  constructor(readonly retryAfter: number, readonly cause: ApiError) {
    super(`rate limited, retry after ${retryAfter}s`);
    this.name = "RateLimitedError";
  }
}

/**
 * The callback state did not match. Treat it as an attack: state binds the
 * callback to the browser that started the flow, and a mismatch is what CSRF
 * against sign-in looks like. The code is not exchanged.
 */
export class StateMismatchError extends AnubisError {
  constructor(reason: string) {
    super(`login state did not match (${reason}) — refusing to exchange the code`);
    this.name = "StateMismatchError";
  }
}

/** The realm requires a factor this member has not enrolled, past the deadline. */
export class EnrolmentRequiredError extends AnubisError {
  constructor(
    readonly factors: AuthMethods,
    readonly deadline: Date,
    readonly grantToken: string,
  ) {
    super(`enrolment required for ${factors} — use the grant token to enrol`);
    this.name = "EnrolmentRequiredError";
  }
}

/** Anubis is unreachable or not ready. Retry with backoff. */
export class UnavailableError extends AnubisError {
  constructor(readonly cause: unknown) {
    super(`unavailable: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "UnavailableError";
  }
}

export class VerificationError extends AnubisError {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

export const isStepUpRequired = (e: unknown): e is StepUpRequiredError => e instanceof StepUpRequiredError;
export const isDenied = (e: unknown): e is DeniedError => e instanceof DeniedError;
export const isRefreshReuse = (e: unknown): e is RefreshReuseError => e instanceof RefreshReuseError;

const REFRESH_REUSE = "refresh_token_reuse_detected";
const RATE_LIMITED = "rate_limited";
const UNAVAILABLE = "unavailable";
const AUTH_CODES = new Set([
  "unauthenticated",
  "invalid_token",
  "invalid_credentials",
  "permission_denied",
  "session_revoked",
  "invalid_refresh_token",
]);

/**
 * Turn a refusal into something a caller can act on.
 *
 * Reuse detection is checked first and deliberately not folded in with the
 * other authentication failures: every other one means "try again with a
 * better credential", and this one means "stop, you have been robbed".
 */
export function classify(err: ApiError, headers: Headers): Error {
  let code = err.code;
  if (!code) {
    if (err.status === 429) code = RATE_LIMITED;
    else if (err.status === 401) code = "unauthenticated";
    else if (err.status === 403) code = "permission_denied";
    else if (err.status === 503) code = UNAVAILABLE;
  }
  if (code === REFRESH_REUSE) return new RefreshReuseError(err);
  if (code === RATE_LIMITED) return new RateLimitedError(retryAfter(headers), err);
  if (code === UNAVAILABLE) return new UnavailableError(err);
  if (AUTH_CODES.has(code)) return new AuthError(err);
  return err;
}

function retryAfter(headers: Headers): number {
  const v = headers.get("retry-after");
  if (!v) return 0;
  const secs = Number.parseInt(v, 10);
  if (Number.isFinite(secs) && secs >= 0) return secs;
  const when = Date.parse(v);
  return Number.isNaN(when) ? 0 : Math.max(0, Math.round((when - Date.now()) / 1000));
}
