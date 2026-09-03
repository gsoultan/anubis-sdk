import type { KeyObject } from "node:crypto";
import { publicKeyFromRaw, b64urlDecode } from "./paseto.js";
import { VerificationError } from "./errors.js";

/**
 * kid is attacker-controlled input — it arrives inside tokens — so it may only
 * ever index a bounded, pre-loaded, in-memory map. Never a database query, a
 * filesystem path, or a per-token network fetch.
 */
const MAX_KEYS = 64;

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

export function parseKeyDocument(doc: KeysDocument): Map<string, KeyObject> {
  if (!doc || !Array.isArray(doc.keys)) throw new VerificationError("anubis: keys document has no keys");
  if (doc.keys.length > MAX_KEYS) {
    throw new VerificationError(`anubis: keys document has ${doc.keys.length} keys, max ${MAX_KEYS}`);
  }
  const out = new Map<string, KeyObject>();
  for (const k of doc.keys) {
    if (k.alg !== "Ed25519") continue; // pinned algorithm; nothing negotiable
    out.set(k.kid, publicKeyFromRaw(b64urlDecode(k.public_key)));
  }
  return out;
}

/**
 * Fetches and caches the key document. On an unknown kid it refetches at most
 * once per minRefetchMs — a stream of garbage kids must not translate into a
 * stream of outbound requests.
 */
export class KeyCache {
  #keys: Map<string, KeyObject> | null = null;
  #lastFetch = 0;
  #inflight: Promise<void> | null = null;

  constructor(
    private readonly url: string,
    private readonly minRefetchMs = 30_000,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async get(kid: string): Promise<KeyObject> {
    const hit = this.#keys?.get(kid);
    if (hit) return hit;

    if (!this.#keys || Date.now() - this.#lastFetch >= this.minRefetchMs) {
      try {
        await this.#refresh();
      } catch (e) {
        // Stale keys beat no keys; the unknown-kid rejection below still stands.
        if (!this.#keys) throw e;
      }
      const found = this.#keys?.get(kid);
      if (found) return found;
    }
    throw new VerificationError(`anubis: unknown kid ${JSON.stringify(kid)}`);
  }

  /** Single-flight: a burst of unknown kids must produce one fetch, not a burst. */
  #refresh(): Promise<void> {
    if (this.#inflight) return this.#inflight;
    this.#inflight = (async () => {
      this.#lastFetch = Date.now();
      const res = await this.fetchImpl(this.url);
      if (!res.ok) throw new VerificationError(`anubis: keys fetch: status ${res.status}`);
      this.#keys = parseKeyDocument((await res.json()) as KeysDocument);
    })().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }
}
