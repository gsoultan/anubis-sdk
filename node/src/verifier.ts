import type { KeyObject } from "node:crypto";
import { parse, verify as pasetoVerify } from "./paseto.js";
import { KeyCache, KeySet, parseKeyDocument, type KeysDocument } from "./keys.js";
import { VerificationError } from "./errors.js";
import { AuthMethods, Identity, Roles, Scopes, toDate } from "./identity.js";

/** The access-token claim set. `scopes` is a map, never fixed fields: adding a
 * scope axis must not change the token format. */
export interface Claims {
  iss: string;
  sub: string;
  aud: string[];
  exp: number;
  iat: number;
  nbf?: number;
  jti?: string;
  sid?: string;
  tid?: string;
  roles?: string[];
  scp?: string;
  scopes?: Record<string, string>;
  realm?: string;
  ial?: number;
  amr?: string[];
  auth_time?: number;
  epoch?: number;
  ver?: number;
}

/**
 * What a verified request carries: the claim set, and the token it came from.
 *
 * The accessors are the ones a handler reaches for. `claims` is still there
 * for anything they do not cover, but a handler reading `claims.auth_time` and
 * converting it by hand is doing work this class already did.
 */
export class Principal {
  constructor(
    readonly claims: Claims,
    readonly token: string,
  ) {}

  /** Who this caller is and what they hold. */
  get identity(): Identity {
    return claimsToIdentity(this.claims);
  }

  get subject(): string {
    return this.claims.sub;
  }

  /** The signed-in device this token belongs to. Empty for a
   * client-credentials caller, which has no session by design. */
  get session(): string {
    return this.claims.sid ?? "";
  }

  get tenant(): string {
    return this.claims.tid ?? "";
  }

  /** The roles this token was minted with, prefixed by the application that
   * defined them: `billing.clerk`, not `clerk`. */
  get roles(): Roles {
    return new Roles(this.claims.roles ?? []);
  }

  /** The ACTIVE scope — one node per axis, what this session is acting as
   * right now. Not everything the person is entitled to; that lives in grants. */
  get scopes(): Scopes {
    return new Scopes(this.claims.scopes ?? {});
  }

  get methods(): AuthMethods {
    return new AuthMethods(this.claims.amr ?? []);
  }

  /** When they last proved who they were — what a step-up rule with a maximum
   * age is measured against. Not the same as issue time: a refresh mints a new
   * token with no fresh proof of identity. */
  get authenticatedAt(): Date | null {
    return toDate(this.claims.auth_time);
  }

  get expiresAt(): Date | null {
    return toDate(this.claims.exp);
  }

  hasRole(role: string): boolean {
    return this.roles.has(role);
  }
}

/** Build an Identity from a raw claim set. */
export function claimsToIdentity(c: Claims): Identity {
  return new Identity(
    c.sub,
    c.sid ?? "",
    c.tid ?? "",
    c.realm ?? "",
    new Roles(c.roles ?? []),
    new Scopes(c.scopes ?? {}),
    new AuthMethods(c.amr ?? []),
    c.ial ?? 0,
    toDate(c.auth_time),
    toDate(c.exp),
  );
}

export interface VerifierConfig {
  issuer: string;
  /**
   * This service's identifier. Mandatory: a verifier without an audience
   * accepts tokens minted for other services — the confused deputy.
   */
  audience: string;
  /**
   * The discovery endpoint. Must be https unless it points at loopback:
   * whoever answers this URL decides which keys this verifier trusts, and
   * therefore who can mint tokens it accepts.
   */
  keysUrl?: string;
  /** Pin keys directly, for air-gapped consumers and tests. */
  staticKeys?: KeysDocument;
  /** Absorbs clock skew between services. Default 60s; enforce NTP anyway. */
  leewaySeconds?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

/**
 * Verifies v4.public access tokens offline.
 *
 * Zero I/O on the verify path, except a bounded, rate-limited key refetch when
 * a token names a kid this process has not seen.
 */
export class Verifier {
  readonly #cache?: KeyCache;
  readonly #static?: KeySet;
  readonly #leeway: number;
  readonly #now: () => number;

  constructor(private readonly cfg: VerifierConfig) {
    if (!cfg.audience) {
      throw new VerificationError(
        "anubis: a verifier requires an audience — refusing to skip the aud check",
      );
    }
    if (!cfg.keysUrl && !cfg.staticKeys) {
      throw new VerificationError("anubis: either keysUrl or staticKeys is required");
    }
    if (cfg.staticKeys) this.#static = parseKeyDocument(cfg.staticKeys);
    if (cfg.keysUrl) {
      assertFetchableKeysUrl(cfg.keysUrl);
      this.#cache = new KeyCache(cfg.keysUrl, { issuer: cfg.issuer, fetchImpl: cfg.fetchImpl });
    }
    this.#leeway = cfg.leewaySeconds ?? 60;
    this.#now = cfg.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Checks signature, expiry, nbf, issuer and audience.
   *
   * It does NOT check epoch or session revocation — those need state only
   * Anubis holds. Use introspection where instant revocation matters.
   */
  async verify(token: string): Promise<Claims> {
    // The kid rides in the footer, which the signature covers — but it has to
    // be read BEFORE verification to select the key. That pre-verification
    // read may only index the bounded key map.
    const { footer } = parse(token);
    let kid = "";
    if (footer.length > 0) {
      try {
        kid = (JSON.parse(footer.toString("utf8")) as { kid?: string }).kid ?? "";
      } catch {
        throw new VerificationError("anubis: token footer is not JSON");
      }
    }
    // One instant for the whole verification: a key inside its window and a
    // token inside its lifetime must be judged against the same clock reading.
    const now = this.#now();
    const key = await this.#key(kid, now);
    const { message } = pasetoVerify(key, token);

    const claims = JSON.parse(message.toString("utf8")) as Claims;
    if (claims.ver !== undefined && claims.ver !== 0 && claims.ver !== 1) {
      throw new VerificationError("anubis: unsupported token version");
    }
    this.#validate(claims, now);
    return claims;
  }

  #validate(c: Claims, now: number): void {
    if (c.exp && now > c.exp + this.#leeway) throw new VerificationError("anubis: token expired");
    if (c.nbf && now < c.nbf - this.#leeway) {
      throw new VerificationError("anubis: token not yet valid (check NTP)");
    }
    if (this.cfg.issuer && c.iss !== this.cfg.issuer) {
      throw new VerificationError("anubis: issuer mismatch");
    }
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud].filter(Boolean);
    if (!aud.includes(this.cfg.audience)) throw new VerificationError("anubis: audience mismatch");
  }

  async #key(kid: string, now: number): Promise<KeyObject> {
    const pinned = this.#static?.get(kid, now);
    if (pinned) return pinned;
    if (!this.#cache) throw new VerificationError(`anubis: unknown kid ${JSON.stringify(kid)}`);
    return this.#cache.get(kid, now);
  }

  /** Extracts the Authorization bearer credential from a header value. */
  static bearer(authorization: string | undefined | null): string | null {
    if (!authorization) return null;
    const [scheme, ...rest] = authorization.split(" ");
    if (!scheme || scheme.toLowerCase() !== "bearer" || rest.length === 0) return null;
    return rest.join(" ");
  }
}

/**
 * Refuses a keys endpoint that is not integrity-protected. Whoever answers
 * this URL decides which public keys the verifier trusts, and therefore who
 * can mint tokens it accepts — over plaintext that is anyone on the path.
 * Loopback is exempt: it never leaves the host, and test servers live there.
 */
export function assertFetchableKeysUrl(raw: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new VerificationError(`anubis: keysUrl ${JSON.stringify(raw)} is not a URL`);
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && isLoopback(url.hostname)) return;
  if (url.protocol !== "http:") {
    throw new VerificationError(`anubis: keysUrl ${JSON.stringify(raw)}: scheme must be https`);
  }
  throw new VerificationError(
    `anubis: keysUrl ${JSON.stringify(raw)} is plaintext http — whoever answers it ` +
      "decides which keys this verifier trusts; use https",
  );
}

function isLoopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "::1" || /^127\./.test(host);
}
