import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";

import { KeyCache, parseKeyDocument, type KeyEntry, type KeysDocument } from "./keys.js";
import { Verifier, assertFetchableKeysUrl } from "./verifier.js";

const T0 = 1_700_000_000;

function newKey(kid: string, extra: Partial<KeyEntry> = {}): KeyEntry {
  const { publicKey } = generateKeyPairSync("ed25519");
  const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
  return { kid, alg: "Ed25519", public_key: x, ...extra };
}

function doc(issuer: string, ...keys: KeyEntry[]): KeysDocument {
  return { issuer, keys };
}

/** A keys endpoint the test can swap, count and stall. */
function server(document: KeysDocument | string) {
  const state = {
    body: typeof document === "string" ? document : JSON.stringify(document),
    status: 200,
    hits: 0,
    gate: null as Promise<void> | null,
  };
  const fetchImpl = (async () => {
    state.hits++;
    if (state.gate) await state.gate;
    return new Response(state.body, { status: state.status });
  }) as unknown as typeof fetch;
  return { state, fetchImpl };
}

function cache(url: string, fetchImpl: typeof fetch, issuer = ""): KeyCache {
  return new KeyCache(url, { issuer, fetchImpl, ttlMs: 300_000, minRefetchMs: 30_000, minRetryMs: 1_000 });
}

describe("parseKeyDocument", () => {
  test("binds the document to an issuer", () => {
    const k = newKey("k1");
    expect(() => parseKeyDocument(doc("https://a.test", k), "https://a.test")).not.toThrow();
    expect(() => parseKeyDocument(doc("https://evil.test", k), "https://a.test")).toThrow(/issued by/);
    expect(() => parseKeyDocument(doc("", k), "https://a.test")).not.toThrow(); // omitted: nothing to bind
    expect(() => parseKeyDocument(doc("https://evil.test", k), "")).not.toThrow(); // caller did not bind
  });

  test("bounds the key count", () => {
    const keys = Array.from({ length: 65 }, (_, i) => newKey(`k${i}`));
    expect(() => parseKeyDocument(doc("", ...keys))).toThrow(/max 64/);
  });

  test("pins the algorithm", () => {
    const set = parseKeyDocument(doc("", newKey("k1"), { ...newKey("k2"), alg: "RS256" }));
    expect(set.get("k1", T0)).toBeDefined();
    expect(set.get("k2", T0)).toBeUndefined();
  });

  test("enforces each key's validity window", () => {
    const set = parseKeyDocument(
      doc(
        "",
        newKey("future", { not_before: T0 + 60 }),
        newKey("past", { not_after: T0 }),
        newKey("unbounded"),
      ),
    );
    expect(set.get("future", T0)).toBeUndefined();
    expect(set.get("future", T0 + 120)).toBeDefined();
    expect(set.get("past", T0 - 1)).toBeDefined();
    expect(set.get("past", T0)).toBeUndefined(); // not_after is exclusive
    expect(set.get("unbounded", T0 + 10_000_000)).toBeDefined();
  });
});

describe("KeyCache", () => {
  // The gap this closes: a cache that refetches only on an unknown kid never
  // notices a key being withdrawn, so a compromised key keeps verifying
  // tokens for the lifetime of the process.
  test("propagates revocation once the document goes stale", async () => {
    const { state, fetchImpl } = server(doc("", newKey("k1"), newKey("k2")));
    const c = cache("https://a.test/keys", fetchImpl);

    expect(await c.get("k2", T0)).toBeDefined();
    state.body = JSON.stringify(doc("", newKey("k1"))); // k2 withdrawn

    expect(await c.get("k2", T0 + 60)).toBeDefined(); // inside the TTL
    await expect(c.get("k2", T0 + 360)).rejects.toThrow(/unknown kid/);
  });

  test("rate limits what an unknown kid can provoke", async () => {
    const { state, fetchImpl } = server(doc("", newKey("k1")));
    const c = cache("https://a.test/keys", fetchImpl);

    for (let i = 0; i < 50; i++) {
      await expect(c.get("garbage", T0)).rejects.toThrow(/unknown kid/);
    }
    expect(state.hits).toBe(1);

    await expect(c.get("garbage", T0 + 31)).rejects.toThrow(/unknown kid/);
    expect(state.hits).toBe(2);
  });

  test("a cold start is single-flight", async () => {
    const { state, fetchImpl } = server(doc("", newKey("k1")));
    let release!: () => void;
    state.gate = new Promise<void>((r) => {
      release = r;
    });
    const c = cache("https://a.test/keys", fetchImpl);

    const all = Promise.all(Array.from({ length: 32 }, () => c.get("k1", T0)));
    release();
    expect((await all).length).toBe(32);
    expect(state.hits).toBe(1);
  });

  test("stale keys beat no keys", async () => {
    const { state, fetchImpl } = server(doc("", newKey("k1")));
    const c = cache("https://a.test/keys", fetchImpl);

    expect(await c.get("k1", T0)).toBeDefined();
    state.status = 500;
    expect(await c.get("k1", T0 + 360)).toBeDefined(); // stale, endpoint down
  });

  // Until the first fetch lands nothing verifies, but a down endpoint must
  // still not take one outbound request per inbound request.
  test("rate limits a failing bootstrap", async () => {
    const { state, fetchImpl } = server(doc("", newKey("k1")));
    state.status = 500;
    const c = cache("https://a.test/keys", fetchImpl);

    for (let i = 0; i < 20; i++) {
      await expect(c.get("k1", T0)).rejects.toThrow(/status 500/);
    }
    expect(state.hits).toBe(1);

    await expect(c.get("k1", T0 + 2)).rejects.toThrow(/status 500/);
    expect(state.hits).toBe(2);
  });

  test("refuses a document from another deployment", async () => {
    const { fetchImpl } = server(doc("https://staging.test", newKey("k1")));
    const c = cache("https://a.test/keys", fetchImpl, "https://prod.test");
    await expect(c.get("k1", T0)).rejects.toThrow(/issued by/);
  });

  test("refuses a document that outgrows the bound", async () => {
    const oversized = JSON.stringify({ issuer: "", keys: [], pad: "x".repeat(1 << 20) });
    const { fetchImpl } = server(oversized);
    const c = cache("https://a.test/keys", fetchImpl);
    await expect(c.get("k1", T0)).rejects.toThrow(/exceeds/);
  });
});

describe("keysUrl", () => {
  test("must be integrity-protected", () => {
    for (const ok of [
      "https://anubis.internal/.well-known/anubis-keys.json",
      "http://127.0.0.1:8080/keys.json",
      "http://[::1]:8080/keys.json",
      "http://localhost:8080/keys.json",
    ]) {
      expect(() => assertFetchableKeysUrl(ok)).not.toThrow();
    }
    for (const bad of ["http://anubis.internal/keys.json", "http://10.0.0.7/keys.json", "file:///keys.json"]) {
      expect(() => assertFetchableKeysUrl(bad)).toThrow();
    }
  });

  test("the verifier refuses to be built on plaintext", () => {
    expect(
      () => new Verifier({ issuer: "https://a.test", audience: "billing-api", keysUrl: "http://a.test/keys.json" }),
    ).toThrow(/plaintext http/);
  });
});
