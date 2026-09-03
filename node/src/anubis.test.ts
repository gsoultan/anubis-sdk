import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";

import { Client, Tokens } from "./client.js";
import { TokenSource } from "./tokensource.js";
import { Principal, Verifier } from "./verifier.js";
import { AuthMethods, Identity, Method, Permission, Permissions, Role, Roles, Scopes } from "./identity.js";
import { b64urlEncode, pae } from "./paseto.js";
import { DeniedError, RefreshReuseError, StateMismatchError, StepUpRequiredError } from "./errors.js";

const ISSUER = "https://anubis.test";
const APP = "billing-api";

// ---- a signing fixture ----------------------------------------------------

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPublic = (publicKey.export({ format: "jwk" }) as { x: string }).x;

function mint(claims: Record<string, unknown>, key: KeyObject = privateKey): string {
  const body = Buffer.from(
    JSON.stringify({
      iss: ISSUER,
      aud: [APP],
      exp: Math.floor(Date.now() / 1000) + 600,
      iat: Math.floor(Date.now() / 1000),
      ...claims,
    }),
  );
  const footer = Buffer.from(JSON.stringify({ kid: "k1" }));
  const sig = cryptoSign(null, pae(Buffer.from("v4.public."), body, footer, Buffer.alloc(0)), key);
  return `v4.public.${b64urlEncode(Buffer.concat([body, sig]))}.${b64urlEncode(footer)}`;
}

const keysDocument = { issuer: ISSUER, keys: [{ kid: "k1", alg: "Ed25519", public_key: rawPublic }] };

function newVerifier(overrides: Record<string, unknown> = {}): Verifier {
  return new Verifier({ issuer: ISSUER, audience: APP, staticKeys: keysDocument, ...overrides });
}

// ---- a fake Anubis over fetch ---------------------------------------------

/** encodeErrorInfo writes anubis.v1.ErrorInfo on the protobuf wire, exactly as
 * Connect would, so the client's hand-rolled decoder is genuinely exercised. */
function encodeErrorInfo(code: string, requestId: string): string {
  const field = (n: number, v: string) =>
    v ? Buffer.concat([Buffer.from([(n << 3) | 2, v.length]), Buffer.from(v)]) : Buffer.alloc(0);
  return Buffer.concat([field(1, code), field(2, requestId)]).toString("base64");
}

interface FakeState {
  calls: Record<string, number>;
  decision: Record<string, unknown>;
  liveRefresh: string;
  consumed: Set<string>;
  refreshDelayMs: number;
  codes: Map<string, { challenge: string; redirectUri: string; clientId: string }>;
}

function fakeAnubis() {
  const state: FakeState = {
    calls: {},
    decision: { allow: true },
    liveRefresh: "anb_rt_1",
    consumed: new Set(),
    refreshDelayMs: 0,
    codes: new Map(),
  };

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const connectError = (code: string, message: string, status = 401) =>
    json(
      {
        code: "unauthenticated",
        message,
        details: [{ type: "anubis.v1.ErrorInfo", value: encodeErrorInfo(code, "req_test") }],
      },
      status,
    );

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : String(input));
    const name = url.pathname;
    state.calls[name] = (state.calls[name] ?? 0) + 1;
    const body = init?.body ? String(init.body) : "";

    switch (name) {
      case "/anubis.v1.AuthzService/Authorize":
        return json(state.decision);

      case "/anubis.v1.AuthService/Refresh": {
        if (state.refreshDelayMs) await new Promise((r) => setTimeout(r, state.refreshDelayMs));
        const presented = JSON.parse(body).refresh_token as string;
        if (presented !== state.liveRefresh || state.consumed.has(presented)) {
          return connectError("refresh_token_reuse_detected", "Token family revoked.");
        }
        state.consumed.add(presented);
        state.liveRefresh = `anb_rt_${Math.random().toString(36).slice(2)}`;
        return json({
          tokens: {
            accessToken: mint({ sub: "usr_1" }),
            refreshToken: state.liveRefresh,
            tokenType: "Bearer",
            expiresIn: 600,
            sessionId: "ses_1",
          },
        });
      }

      case "/anubis.v1.TokenService/Introspect":
        // protojson renders int64 as a JSON STRING. A client assuming a number
        // breaks here, which is why the fake spells it out.
        return json({ active: true, sub: "usr_1", exp: String(Math.floor(Date.now() / 1000) + 60) });

      case "/v1/authorize": {
        const q = url.searchParams;
        const code = `code_${Math.random().toString(36).slice(2)}`;
        state.codes.set(code, {
          challenge: q.get("code_challenge") ?? "",
          redirectUri: q.get("redirect_uri") ?? "",
          clientId: q.get("client_id") ?? "",
        });
        return json({ code, state: q.get("state") });
      }

      case "/v1/token": {
        const form = new URLSearchParams(body);
        const entry = state.codes.get(form.get("code") ?? "");
        state.codes.delete(form.get("code") ?? "");
        if (!entry) return json({ error: "invalid_pkce", message: "unknown code" }, 400);
        const { createHash } = await import("node:crypto");
        const challenge = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
        if (challenge !== entry.challenge) {
          return json({ error: "invalid_pkce", message: "verifier mismatch" }, 400);
        }
        // The browser endpoint answers snake_case, unlike every procedure above.
        return json({
          access_token: mint({ sub: "usr_1" }),
          refresh_token: state.liveRefresh,
          token_type: "Bearer",
          expires_in: 600,
          session_id: "ses_1",
        });
      }

      default:
        return json({ error: "not_found", message: name }, 404);
    }
  };

  return { state, fetchImpl };
}

function newClient(fetchImpl: typeof fetch, opts: Record<string, unknown> = {}): Client {
  return new Client("https://anubis.test", {
    clientId: APP,
    apiKey: "anb_live_ab12cd34_s3cr3t",
    tenant: "impack",
    fetchImpl,
    ...opts,
  });
}

const principal = new Principal(
  { iss: ISSUER, sub: "usr_1", aud: [APP], exp: 0, iat: 0, amr: ["pwd"], auth_time: 1 },
  "v4.public.test",
);

// ---- PASETO ---------------------------------------------------------------

describe("paseto", () => {
  // Golden vectors from the PASETO specification. These pin the exact byte
  // layout the signature covers; drift here is a cross-implementation token
  // break, and this is the same table the Go implementation asserts.
  test("PAE matches the specification vectors", () => {
    expect(pae().toString("hex")).toBe("0000000000000000");
    expect(pae(Buffer.from("")).toString("hex")).toBe("01000000000000000000000000000000");
    expect(pae(Buffer.from("test")).toString("hex")).toBe(
      "0100000000000000040000000000000074657374",
    );
    expect(pae(Buffer.from("test"), Buffer.from("")).toString("hex")).toBe(
      "02000000000000000400000000000000746573740000000000000000",
    );
  });
});

// ---- verification ---------------------------------------------------------

describe("verifier", () => {
  test("verifies a well-formed token", async () => {
    const claims = await newVerifier().verify(mint({ sub: "usr_1", roles: ["billing.clerk"] }));
    expect(claims.sub).toBe("usr_1");
    expect(claims.roles).toEqual(["billing.clerk"]);
  });

  test("refuses to be built without an audience", () => {
    expect(() => new Verifier({ issuer: ISSUER, audience: "", staticKeys: keysDocument })).toThrow(
      /refusing to skip the aud check/,
    );
  });

  test("rejects a token minted for another application", async () => {
    const other = mint({ sub: "usr_1", aud: ["hr-api"] });
    await expect(newVerifier().verify(other)).rejects.toThrow(/audience mismatch/);
  });

  test("rejects an expired token and one from the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expect(newVerifier().verify(mint({ sub: "u", exp: now - 3600 }))).rejects.toThrow(/expired/);
    await expect(newVerifier().verify(mint({ sub: "u", nbf: now + 3600 }))).rejects.toThrow(/not yet valid/);
  });

  test("rejects a token signed by the wrong key", async () => {
    const attacker = generateKeyPairSync("ed25519");
    await expect(newVerifier().verify(mint({ sub: "u" }, attacker.privateKey))).rejects.toThrow(
      /signature verification failed/,
    );
  });

  test("rejects an unknown kid without any I/O", async () => {
    const v = new Verifier({ issuer: ISSUER, audience: APP, staticKeys: keysDocument });
    const body = Buffer.from(JSON.stringify({ iss: ISSUER, sub: "u", aud: [APP] }));
    const footer = Buffer.from(JSON.stringify({ kid: "not-a-key" }));
    const sig = cryptoSign(null, pae(Buffer.from("v4.public."), body, footer, Buffer.alloc(0)), privateKey);
    const token = `v4.public.${b64urlEncode(Buffer.concat([body, sig]))}.${b64urlEncode(footer)}`;
    await expect(v.verify(token)).rejects.toThrow(/unknown kid/);
  });

  test("rejects malformed tokens without throwing anything unexpected", async () => {
    const v = newVerifier();
    for (const bad of ["", "v4.public", "v2.public.abc", "v4.public.", "v4.public.!!!", "v4.public.AAAA"]) {
      await expect(v.verify(bad)).rejects.toThrow();
    }
  });
});

// ---- sign-in --------------------------------------------------------------

describe("login", () => {
  test("round trips through PKCE", async () => {
    const { fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);

    const begin = c.beginLogin({ redirectUri: "https://app.example.com/callback" });
    const url = new URL(begin.url);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(begin.url).not.toContain("code_verifier");
    expect(begin.cookie).toContain("HttpOnly");

    const authorized = (await (await fetchImpl(begin.url, {})).json()) as { code: string; state: string };
    const cookieValue = begin.cookie.split(";")[0]!;
    const { tokens } = await c.completeLogin({
      url: `https://app.example.com/callback?code=${authorized.code}&state=${authorized.state}`,
      cookieHeader: cookieValue,
    });
    expect(tokens.accessToken).toStartWith("v4.public.");
    // snake_case from the browser endpoint has to decode.
    expect(tokens.expiresIn).toBe(600);
  });

  test("refuses to exchange a code when the state does not match", async () => {
    const { state, fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);
    const begin = c.beginLogin({ redirectUri: "https://app.example.com/callback" });
    const authorized = (await (await fetchImpl(begin.url, {})).json()) as { code: string };
    const before = state.calls["/v1/token"] ?? 0;

    await expect(
      c.completeLogin({
        url: `https://app.example.com/callback?code=${authorized.code}&state=attacker-chosen`,
        cookieHeader: begin.cookie.split(";")[0]!,
      }),
    ).rejects.toBeInstanceOf(StateMismatchError);
    expect(state.calls["/v1/token"] ?? 0).toBe(before);
  });

  test("refuses a callback with no login cookie", async () => {
    const { fetchImpl } = fakeAnubis();
    await expect(
      newClient(fetchImpl).completeLogin({ url: "https://app.example.com/cb?code=a&state=b" }),
    ).rejects.toBeInstanceOf(StateMismatchError);
  });
});

// ---- decisions ------------------------------------------------------------

describe("authorize", () => {
  test("allows and denies, naming the failing axis", async () => {
    const { state, fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);

    await c.require(principal, "billing:invoice:approve", { org: "o1" });

    state.decision = { allow: false, reason: "scope_mismatch", failingAxis: "customer", message: "no grant" };
    const err = await c.require(principal, "billing:invoice:approve", {}).catch((e) => e);
    expect(err).toBeInstanceOf(DeniedError);
    expect((err as DeniedError).failingAxis).toBe("customer");
    expect(String((err as DeniedError).permission)).toBe("billing:invoice:approve");
  });

  test("surfaces a step-up refusal as its own type and builds the re-auth redirect", async () => {
    const { state, fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);
    state.decision = {
      allow: false,
      reason: "step_up_required",
      requiredAmr: ["otp"],
      currentAmr: ["pwd"],
      maxAuthAge: "2m",
    };
    const err = await c.require(principal, "billing:invoice:approve", {}).catch((e) => e);
    expect(err).toBeInstanceOf(StepUpRequiredError);

    expect((err as StepUpRequiredError).requiredAmr.has(Method.OTP)).toBe(true);
    expect((err as StepUpRequiredError).maxAuthAgeSeconds).toBe(120);

    const redirect = c.beginStepUp(err, { redirectUri: "https://app.example.com/callback" });
    const q = new URL(redirect.url).searchParams;
    expect(q.get("prompt")).toBe("login");
    expect(q.get("acr_values")).toBe("otp");
    expect(q.get("max_age")).toBe("120");
  });
});

// ---- rotation -------------------------------------------------------------

describe("token rotation", () => {
  test("concurrent callers produce exactly one refresh", async () => {
    const { state, fetchImpl } = fakeAnubis();
    state.refreshDelayMs = 25;
    const c = newClient(fetchImpl);
    const expired = new Tokens({
      accessToken: "old",
      refreshToken: "anb_rt_1",
      expiresIn: 1,
      sessionId: "ses_1",
      issuedAt: Date.now() - 3_600_000,
    });
    const ts = new TokenSource(c, expired);

    const results = await Promise.all(Array.from({ length: 20 }, () => ts.token()));
    expect(state.calls["/anubis.v1.AuthService/Refresh"]).toBe(1);
    for (const r of results) expect(r.accessToken).toBe(results[0]!.accessToken);
  });

  test("onRotate runs before token() resolves and persists the new pair", async () => {
    const { fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);
    let persisted: Tokens | null = null;
    const ts = new TokenSource(c, new Tokens({
      accessToken: "old",
      refreshToken: "anb_rt_1",
      expiresIn: 1,
      sessionId: "ses_1",
      issuedAt: Date.now() - 3_600_000,
    })).onRotate((t) => {
      persisted = t;
    });

    const got = await ts.token();
    expect(persisted).not.toBeNull();
    expect(persisted!.refreshToken).toBe(got.refreshToken);
    expect(got.refreshToken).not.toBe("anb_rt_1");
  });

  test("reuse is its own error and is not reachable as an auth failure", async () => {
    const { fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);
    await c.refresh("anb_rt_1");
    const err = await c.refresh("anb_rt_1").catch((e) => e);
    // The stable code survived the base64 protobuf error detail.
    expect(err).toBeInstanceOf(RefreshReuseError);
    expect(String(err)).toContain("theft");
  });
});

describe("introspection", () => {
  test("decodes int64 fields that arrive as JSON strings", async () => {
    const { fetchImpl } = fakeAnubis();
    const out = (await newClient(fetchImpl).introspect("v4.public.x")) as Record<string, unknown>;
    expect(out.active).toBe(true);
    expect(Number(out.exp)).toBeGreaterThan(0);
  });
});

describe("construction", () => {
  test("refuses plain http, a malformed api key, and two identities at once", () => {
    expect(() => new Client("http://anubis.test", {})).toThrow(/must be https/);
    expect(() => new Client("https://anubis.test", { apiKey: "nope" })).toThrow(/anb_live_/);
    expect(
      () => new Client("https://anubis.test", { apiKey: "anb_live_ab12cd34_s3cr3t", clientSecret: "s" }),
    ).toThrow(/different callers/);
  });
});

// ---- the vocabulary -------------------------------------------------------

describe("value types", () => {
  test("Permission knows its parts and both spellings", () => {
    const p = Permission.of("billing:invoice:approve");
    expect(p.app).toBe("billing");
    expect(p.resource).toBe("invoice");
    expect(p.action).toBe("approve");
    // The naming rule that costs people real time: a manifest declares
    // permissions WITHOUT the application prefix, everything else uses the
    // full key.
    expect(p.manifest()).toBe("invoice:approve");
    expect(Permission.from("billing", "invoice", "approve").equals(p)).toBe(true);
  });

  test("a malformed permission reports nothing rather than a plausible part", () => {
    for (const bad of ["", "approve", "invoice:approve", "a:b:c:d", "a::c"]) {
      const p = Permission.of(bad);
      expect(p.isValid).toBe(false);
      expect(p.app).toBe("");
    }
  });

  test("authorize refuses a malformed permission before spending a decision", async () => {
    const { state, fetchImpl } = fakeAnubis();
    const c = newClient(fetchImpl);
    await expect(c.authorize(principal, "invoice:approve")).rejects.toThrow(/not a permission key/);
    expect(state.calls["/anubis.v1.AuthzService/Authorize"] ?? 0).toBe(0);
  });

  test("Role separates the application prefix from the manifest name", () => {
    const r = Role.of("billing.clerk");
    expect(r.app).toBe("billing");
    expect(r.name).toBe("clerk");
    expect(Role.from("billing", "clerk").equals(r)).toBe(true);
    // An unprefixed role reports no application rather than pretending.
    expect(Role.of("clerk").app).toBe("");
  });

  test("Roles compares the full prefixed name", () => {
    const rs = new Roles(["billing.clerk", "billing.approver", "hr.viewer"]);
    expect(rs.has("billing.clerk")).toBe(true);
    expect(rs.has("clerk")).toBe(false);
    expect(rs.hasAny("nope.none", "hr.viewer")).toBe(true);
    expect(rs.ofApp("billing").size).toBe(2);
  });

  test("Scopes are immutable and sorted", () => {
    const base = new Scopes({ org: "o1" });
    const with2 = base.with("customer", "c1");
    expect(base.axes()).toEqual(["org"]);
    expect(with2.node("customer")).toBe("c1");
    // One printable form, which is also what keeps a decision cache from
    // keying the same question many ways.
    expect(String(with2)).toBe("customer=c1 org=o1");
    const merged = with2.merge({ org: "o2", product: "p1" });
    expect(merged.node("org")).toBe("o2");
    expect(merged.node("customer")).toBe("c1");
    expect(new Scopes().isEmpty).toBe(true);
  });

  test("Scopes.owner names the reserved axis", () => {
    expect(Scopes.owner("usr_applicant").node("_owner")).toBe("usr_applicant");
  });

  test("AuthMethods.hasAll requires every method, not any", () => {
    const m = new AuthMethods([Method.Password, Method.OTP]);
    expect(m.has(Method.OTP)).toBe(true);
    expect(m.hasAll(Method.Password, Method.OTP)).toBe(true);
    expect(m.hasAll(Method.Password, Method.DeviceKey)).toBe(false);
  });

  test("Permissions narrows by application", () => {
    const ps = new Permissions(["billing:invoice:approve", "billing:invoice:read", "hr:person:read"]);
    expect(ps.has("billing:invoice:approve")).toBe(true);
    expect(ps.ofApp("billing").size).toBe(2);
  });
});

describe("identity", () => {
  test("a principal answers who and what without claim-set spelunking", () => {
    const authTime = Math.floor(Date.now() / 1000) - 40 * 60;
    const p = new Principal(
      {
        iss: ISSUER,
        sub: "usr_1",
        aud: [APP],
        exp: Math.floor(Date.now() / 1000) + 600,
        iat: authTime,
        sid: "ses_9",
        tid: "tnt_impack",
        realm: "internal",
        roles: ["billing.clerk"],
        scopes: { org: "o1", customer: "c1" },
        amr: ["pwd"],
        ial: 2,
        auth_time: authTime,
      },
      "v4.public.x",
    );

    expect(p.subject).toBe("usr_1");
    expect(p.session).toBe("ses_9");
    expect(p.hasRole("billing.clerk")).toBe(true);
    expect(p.scopes.node("customer")).toBe("c1");

    const id: Identity = p.identity;
    expect(id.activeScope("org")).toBe("o1");
    // Authentication time is not issue time: a refresh mints a token with no
    // fresh proof, which is exactly why step-up is decided against this.
    expect(id.authAgeMs).toBeGreaterThan(39 * 60 * 1000);
    expect(id.isApplication).toBe(false);
    expect(String(id)).toBe("usr_1 [customer=c1 org=o1]");
  });

  test("a client-credentials subject is recognisable", () => {
    const p = new Principal({ iss: ISSUER, sub: "app_batch", aud: [APP], exp: 0, iat: 0 }, "t");
    expect(p.identity.isApplication).toBe(true);
  });
});

describe("tokens", () => {
  test("expose lifetime, expiry and whether they can rotate", () => {
    const issued = Date.now();
    const t = new Tokens({ accessToken: "a", refreshToken: "r", expiresIn: 600, issuedAt: issued });
    expect(t.lifetimeMs).toBe(600_000);
    expect(t.expiry?.getTime()).toBe(issued + 600_000);
    expect(t.hasRefresh).toBe(true);
    // A client-credentials pair has no refresh token; it is re-minted instead.
    expect(new Tokens({ accessToken: "a" }).hasRefresh).toBe(false);
  });
});
