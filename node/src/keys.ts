import type { KeyObject } from "node:crypto";
import { publicKeyFromRaw, b64urlDecode } from "./paseto.js";
import { VerificationError } from "./errors.js";

/**
 * kid is attacker-controlled input — it arrives inside tokens — so it may only
 * ever index a bounded, pre-loaded, in-memory map. Never a database query, a
 * filesystem path, or a per-token network fetch.
 */
const MAX_KEYS = 64;

/** A keys document past this size is refused rather than buffered. */
const MAX_DOCUMENT_BYTES = 1 << 20;

/**
 * How long a fetched document is treated as current, and so the upper bound on
 * how long a withdrawn key keeps verifying tokens. A cache that refetches only
 * on an unknown kid never notices a removal: rotation works, revocation
 * silently does not.
 */
export const DEFAULT_TTL_MS = 300_000;
/** Floor between the fetches an unknown kid may provoke while still current. */
export const DEFAULT_MIN_REFETCH_MS = 30_000;
/** Floor between attempts after a failed fetch. Short: nothing verifies yet. */
export const DEFAULT_MIN_RETRY_MS = 1_000;

export interface KeyEntry {
  kid: string;
  alg: string;
  public_key: string;
  not_before?: number;
  not_after?: number;
}

export interface KeysDocument {
  issuer?: string;
  keys: KeyEntry[];
}

interface Held {
  key: KeyObject;
  notBefore: number;
  notAfter: number;
}

/** An immutable kid -> public key map that knows each key's validity window. */
export class KeySet {
  readonly #keys: Map<string, Held>;

  constructor(keys: Map<string, Held>) {
    this.#keys = keys;
  }

  /**
   * Returns the key for kid if this set holds it and nowSec falls inside its
   * published window. Either bound at zero is unbounded.
   *
   * not_after is when a verifier stops *trusting* the key, not when the issuer
   * stops signing with it: a token minted a second before the deadline is
   * rejected the moment it passes. Publish not_after at least one maximum
   * token lifetime after the key's last signing time, or a rotation rejects
   * tokens that are still live.
   */
  get(kid: string, nowSec: number): KeyObject | undefined {
    const held = this.#keys.get(kid);
    if (!held) return undefined;
    if (held.notBefore && nowSec < held.notBefore) return undefined;
    if (held.notAfter && nowSec >= held.notAfter) return undefined;
    return held.key;
  }
}

/**
 * Parses a published keys document.
 *
 * issuer, when given, must match the document's own issuer. A verifier that
 * loads whatever keys its URL happens to serve cannot notice it was pointed at
 * the wrong deployment. A document that omits the field is accepted: the
 * binding is only ever as good as what the issuer publishes.
 */
export function parseKeyDocument(doc: KeysDocument, issuer = ""): KeySet {
  if (!doc || !Array.isArray(doc.keys)) throw new VerificationError("anubis: keys document has no keys");
  if (issuer && doc.issuer && doc.issuer !== issuer) {
    throw new VerificationError(
      `anubis: keys document is issued by ${JSON.stringify(doc.issuer)}, expected ${JSON.stringify(issuer)}`,
    );
  }
  if (doc.keys.length > MAX_KEYS) {
    throw new VerificationError(`anubis: keys document has ${doc.keys.length} keys, max ${MAX_KEYS}`);
  }
  const out = new Map<string, Held>();
  for (const k of doc.keys) {
    if (k.alg !== "Ed25519") continue; // pinned algorithm; nothing negotiable
    out.set(k.kid, {
      key: publicKeyFromRaw(b64urlDecode(k.public_key)),
      notBefore: k.not_before ?? 0,
      notAfter: k.not_after ?? 0,
    });
  }
  return new KeySet(out);
}

export interface KeyCacheOptions {
  /** Binds the fetched document to a deployment; see parseKeyDocument. */
  issuer?: string;
  ttlMs?: number;
  minRefetchMs?: number;
  minRetryMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * Fetches and caches the key document.
 *
 * Two clocks govern refetching. ttlMs bounds how stale the document may get,
 * so a key withdrawn upstream stops verifying. minRefetchMs bounds what an
 * unknown kid can provoke inside that window — kid arrives inside
 * attacker-supplied tokens, so a stream of garbage kids must not become a
 * stream of outbound requests.
 */
export class KeyCache {
  #keys: KeySet | null = null;
  #lastFetch = 0;
  #nextFetch = 0;
  #lastError: unknown = null;
  #inflight: Promise<void> | null = null;

  readonly #issuer: string;
  readonly #ttl: number;
  readonly #minRefetch: number;
  readonly #minRetry: number;
  readonly #fetch: typeof fetch;

  constructor(
    private readonly url: string,
    opts: KeyCacheOptions = {},
  ) {
    this.#issuer = opts.issuer ?? "";
    // A zero interval would mean "always stale, never throttled", which is the
    // failure this cache exists to avoid.
    this.#ttl = opts.ttlMs && opts.ttlMs > 0 ? opts.ttlMs : DEFAULT_TTL_MS;
    this.#minRefetch = opts.minRefetchMs && opts.minRefetchMs > 0 ? opts.minRefetchMs : DEFAULT_MIN_REFETCH_MS;
    this.#minRetry = opts.minRetryMs && opts.minRetryMs > 0 ? opts.minRetryMs : DEFAULT_MIN_RETRY_MS;
    this.#fetch = opts.fetchImpl ?? fetch;
  }

  async get(kid: string, nowSec: number): Promise<KeyObject> {
    const nowMs = nowSec * 1000;

    // The hot path: a current document holding the kid answers with zero I/O.
    if (this.#keys && nowMs - this.#lastFetch < this.#ttl) {
      const hit = this.#keys.get(kid, nowSec);
      if (hit) return hit;
    }

    // Missing, stale, or an unknown kid worth spending a fetch on.
    const had = this.#keys;
    try {
      await this.#refresh(nowMs);
    } catch (e) {
      // Stale keys beat no keys; the unknown-kid rejection below still stands.
      if (!had) throw e;
    }

    const found = this.#keys?.get(kid, nowSec);
    if (found) return found;
    throw new VerificationError(`anubis: unknown kid ${JSON.stringify(kid)}`);
  }

  /** Single-flight: a burst of unknown kids must produce one fetch, not a burst. */
  #refresh(nowMs: number): Promise<void> {
    if (this.#inflight) return this.#inflight;
    if (nowMs < this.#nextFetch) {
      // Surface why the last attempt failed rather than a bare "throttled".
      return this.#lastError ? Promise.reject(this.#lastError) : Promise.resolve();
    }
    this.#inflight = (async () => {
      try {
        this.#keys = parseKeyDocument(await this.#fetchDocument(), this.#issuer);
        this.#lastFetch = nowMs;
        this.#nextFetch = nowMs + this.#minRefetch;
        this.#lastError = null;
      } catch (e) {
        this.#nextFetch = nowMs + this.#minRetry;
        this.#lastError = e;
        throw e;
      }
    })().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  async #fetchDocument(): Promise<KeysDocument> {
    const res = await this.#fetch(this.url);
    if (!res.ok) throw new VerificationError(`anubis: keys fetch: status ${res.status}`);
    return JSON.parse(await readCapped(res)) as KeysDocument;
  }
}

/** Reads a response body, refusing one that outgrows the document bound. */
async function readCapped(res: Response): Promise<string> {
  const body = res.body;
  if (!body) {
    // A stand-in Response from a test double may carry no stream.
    const text = await res.text();
    if (Buffer.byteLength(text) > MAX_DOCUMENT_BYTES) throw tooLarge();
    return text;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_DOCUMENT_BYTES) {
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function tooLarge(): VerificationError {
  return new VerificationError(`anubis: keys document exceeds ${MAX_DOCUMENT_BYTES} bytes`);
}
