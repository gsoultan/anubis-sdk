import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  ApiError,
  AuthError,
  DeniedError,
  EnrolmentRequiredError,
  StateMismatchError,
  StepUpRequiredError,
  UnavailableError,
  classify,
} from "./errors.js";
import { Principal, type Verifier } from "./verifier.js";
import {
  AuthMethods,
  Identity,
  Permission,
  Permissions,
  Roles,
  Scopes,
  parseAgeSeconds,
  toDate,
  type PermissionLike,
  type ScopesLike,
} from "./identity.js";
import { parse as pasetoParse } from "./paseto.js";

/** Connect derives these from the proto package and service name, so they
 * change only if the proto does. */
const PROC = {
  login: "/anubis.v1.AuthService/Login",
  verifyMfa: "/anubis.v1.AuthService/VerifyMfa",
  refresh: "/anubis.v1.AuthService/Refresh",
  logout: "/anubis.v1.AuthService/Logout",
  logoutAll: "/anubis.v1.AuthService/LogoutAll",
  logoutSession: "/anubis.v1.AuthService/LogoutSession",
  clientCredentials: "/anubis.v1.AuthService/ClientCredentials",
  authorize: "/anubis.v1.AuthzService/Authorize",
  explain: "/anubis.v1.AuthzService/Explain",
  switchScope: "/anubis.v1.AuthzService/SwitchScope",
  introspect: "/anubis.v1.TokenService/Introspect",
  getMe: "/anubis.v1.SessionService/GetMe",
  listSessions: "/anubis.v1.SessionService/ListSessions",
} as const;

/** The browser-facing flows. Not Connect procedures: these speak form encoding
 * and snake_case JSON. */
const PATH = { authorize: "/v1/authorize", token: "/v1/token", logout: "/v1/logout" } as const;

const LOGIN_COOKIE = "anubis_login";
const LOGIN_TTL_MS = 10 * 60 * 1000;
/** Refresh a little early: a token valid when the request leaves and expired
 * when it arrives is a 401 nobody can reproduce. */
const REFRESH_MARGIN_S = 30;

/**
 * An issued credential pair.
 *
 * `refreshToken` is single-use: every refresh returns a rotated pair and kills
 * the one presented. Store the new pair before discarding the old — see
 * TokenSource, which does that and is the only safe way to hold these in a
 * process serving concurrent requests.
 */
export class Tokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly tokenType: string;
  readonly expiresIn: number;
  readonly sessionId: string;
  readonly issuedAt: number;

  constructor(init: {
    accessToken: string;
    refreshToken?: string;
    tokenType?: string;
    expiresIn?: number;
    sessionId?: string;
    issuedAt?: number;
  }) {
    this.accessToken = init.accessToken;
    this.refreshToken = init.refreshToken ?? "";
    this.tokenType = init.tokenType ?? "Bearer";
    this.expiresIn = init.expiresIn ?? 0;
    this.sessionId = init.sessionId ?? "";
    this.issuedAt = init.issuedAt ?? Date.now();
  }

  /** How long the access token is good for, in milliseconds. */
  get lifetimeMs(): number {
    return this.expiresIn * 1000;
  }

  /** When the access token stops being accepted. */
  get expiry(): Date | null {
    return this.expiresIn ? new Date(this.issuedAt + this.lifetimeMs) : null;
  }

  /** Whether this pair can be rotated. A client-credentials token cannot: it
   * is re-minted from the application's own secret instead. */
  get hasRefresh(): boolean {
    return this.refreshToken !== "";
  }

  /** From a Connect procedure, which answers in protojson's camelCase. */
  static fromConnect(t: Record<string, unknown>, now: number): Tokens {
    return new Tokens({
      accessToken: String(t.accessToken ?? ""),
      refreshToken: String(t.refreshToken ?? ""),
      tokenType: String(t.tokenType ?? "Bearer"),
      expiresIn: Number(t.expiresIn ?? 0),
      sessionId: String(t.sessionId ?? ""),
      issuedAt: now,
    });
  }

  /** From the browser token endpoint, which writes its JSON by hand in
   * snake_case. The asymmetry is the server's; a client has to carry it. */
  static fromHttp(t: Record<string, unknown>, now: number): Tokens {
    return new Tokens({
      accessToken: String(t.access_token ?? ""),
      refreshToken: String(t.refresh_token ?? ""),
      tokenType: String(t.token_type ?? "Bearer"),
      expiresIn: Number(t.expires_in ?? 0),
      sessionId: String(t.session_id ?? ""),
      issuedAt: now,
    });
  }
}

/**
 * Anubis's answer.
 *
 * A denial is an answer, not a failure: the reason and the failing axis are
 * always populated on a refusal, because a deny nobody can explain is a
 * support ticket.
 */
export class Decision {
  constructor(
    readonly allow: boolean,
    readonly reason: string,
    readonly failingAxis: string,
    readonly message: string,
    readonly requiredAmr: AuthMethods,
    readonly maxAuthAge: string,
    readonly currentAmr: AuthMethods,
    readonly authAge: string,
    readonly permission?: Permission,
    readonly subject?: string,
  ) {}

  /** Whether the refusal can be cured by re-authenticating. */
  get needsStepUp(): boolean {
    return this.reason === "step_up_required";
  }

  /** How fresh the authentication has to be, in seconds. */
  get maxAuthAgeSeconds(): number | undefined {
    return parseAgeSeconds(this.maxAuthAge);
  }

  /** Throw the typed refusal, or return cleanly when allowed. */
  orThrow(): void {
    if (this.allow) return;
    if (this.needsStepUp) {
      throw new StepUpRequiredError(
        this.requiredAmr,
        this.currentAmr,
        this.maxAuthAge,
        this.authAge,
        this.permission,
      );
    }
    throw new DeniedError(this.reason, this.failingAxis, this.message, this.permission);
  }

  static fromWire(out: Record<string, any>, permission: Permission, subject: string): Decision {
    return new Decision(
      Boolean(out.allow),
      String(out.reason ?? ""),
      String(out.failingAxis ?? ""),
      String(out.message ?? ""),
      new AuthMethods(out.requiredAmr ?? []),
      String(out.maxAuthAge ?? ""),
      new AuthMethods(out.currentAmr ?? []),
      String(out.authAge ?? ""),
      permission,
      subject,
    );
  }
}

export interface ClientOptions {
  /** The registered application slug — also its client_id and the aud its
   * tokens carry. */
  clientId?: string;
  /** Only meaningful for web/server/service kinds. An spa has none: a secret
   * shipped to a browser is not a secret. */
  clientSecret?: string;
  /** anb_live_ tenant key. The tenant's credential, not a person's. */
  apiKey?: string;
  tenant?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface LoginParams {
  redirectUri: string;
  scope?: string[];
  realm?: string;
  page?: string;
  tenant?: string;
  nonce?: string;
  prompt?: string;
  acrValues?: string[];
  maxAge?: number;
}

export interface BeginLoginResult {
  url: string;
  state: string;
  /** Set this as a Set-Cookie header before redirecting. It carries the PKCE
   * verifier, which must never reach the browser's URL bar. */
  cookie: string;
}

export interface LoginResult {
  tokens?: Tokens;
  mfa?: { token: string; methods: AuthMethods; expiresIn: number };
  /** Rides ALONGSIDE tokens while the deadline is ahead. A client that ignores
   * it costs its user access on the deadline with no notice. */
  enrolmentDue?: { factors: string[]; deadline: Date };
}

export class Client {
  readonly #base: string;
  readonly #opts: Required<Pick<ClientOptions, "timeoutMs" | "headers">> & ClientOptions;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;

  constructor(baseUrl: string, opts: ClientOptions = {}) {
    const u = new URL(baseUrl);
    if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
      throw new Error(
        `anubis: base url ${baseUrl} must be https — browser sign-in needs it, and so does a credential`,
      );
    }
    if (opts.apiKey && opts.clientSecret) {
      // Two credentials means two identities. A client holding both picks one
      // by accident, and the audit trail then names the wrong caller.
      throw new Error("anubis: an api key and a client secret are different callers — use one client for each");
    }
    if (opts.apiKey && !opts.apiKey.startsWith("anb_live_")) {
      throw new Error('anubis: an api key looks like "anb_live_<prefix>_<secret>"');
    }
    this.#base = baseUrl.replace(/\/+$/, "");
    this.#opts = { timeoutMs: 10_000, headers: {}, ...opts };
    this.#fetch = opts.fetchImpl ?? fetch;
    this.#now = opts.now ?? Date.now;
  }

  // ---- sign-in ------------------------------------------------------------

  /**
   * Start an authorization-code sign-in with PKCE.
   *
   * The verifier and state are generated here and stored in the returned
   * cookie, so the callback can check them. Neither is the caller's to manage.
   */
  beginLogin(p: LoginParams): BeginLoginResult {
    if (!this.#opts.clientId) throw new Error("anubis: beginLogin needs clientId");
    if (!p.redirectUri) {
      throw new Error("anubis: beginLogin needs a redirectUri registered on the application");
    }
    const state = randomBytes(32).toString("base64url");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    const q = new URLSearchParams({
      response_type: "code",
      client_id: this.#opts.clientId,
      redirect_uri: p.redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: (p.scope ?? ["openid"]).join(" "),
    });
    const optional: Record<string, string | undefined> = {
      tenant: p.tenant ?? this.#opts.tenant,
      realm: p.realm,
      page: p.page,
      nonce: p.nonce,
      prompt: p.prompt,
      acr_values: p.acrValues?.join(" "),
      max_age: p.maxAge ? String(p.maxAge) : undefined,
    };
    for (const [k, v] of Object.entries(optional)) if (v) q.set(k, v);

    const pending = JSON.stringify({ s: state, v: verifier, r: p.redirectUri, c: this.#now() });
    const value = Buffer.from(pending).toString("base64url");
    return {
      url: `${this.#base}${PATH.authorize}?${q}`,
      state,
      // Lax rather than Strict: the browser returns from Anubis's origin by
      // top-level navigation, and Strict would withhold the cookie on exactly
      // the request that needs it.
      cookie: `${LOGIN_COOKIE}=${value}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
    };
  }

  /**
   * Handle the callback: check the state, exchange the code, return tokens.
   *
   * The state comparison happens before anything is exchanged, and there is no
   * option that turns it off. A caller cannot forget a check that was never
   * theirs to make.
   */
  async completeLogin(args: {
    url: string;
    cookieHeader?: string | null;
  }): Promise<{ tokens: Tokens; clearCookie: string }> {
    const url = new URL(args.url, "https://callback.invalid");
    const err = url.searchParams.get("error");
    if (err) {
      throw new ApiError(err, url.searchParams.get("error_description") ?? "", "", 400);
    }
    const raw = readCookie(args.cookieHeader, LOGIN_COOKIE);
    if (!raw) throw new StateMismatchError("no login in progress for this browser");

    let pending: { s: string; v: string; r: string; c: number };
    try {
      pending = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    } catch {
      throw new StateMismatchError("login cookie is unreadable");
    }
    if (this.#now() - pending.c > LOGIN_TTL_MS) {
      throw new StateMismatchError("the sign-in took longer than 10 minutes");
    }
    const got = url.searchParams.get("state") ?? "";
    if (!constantTimeEqual(got, pending.s)) {
      throw new StateMismatchError("callback state is not the one this browser was sent with");
    }
    const code = url.searchParams.get("code");
    if (!code) throw new StateMismatchError("callback carried no code");

    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: pending.v,
      redirect_uri: pending.r,
      client_id: this.#opts.clientId ?? "",
    });
    // Sent because the discovery document advertises client_secret_post. Note
    // that the token endpoint does not currently verify it — PKCE is what
    // binds the exchange — so this is forward compatibility, not the proof.
    if (this.#opts.clientSecret) form.set("client_secret", this.#opts.clientSecret);

    const body = await this.#request(PATH.token, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    // The browser endpoint answers in snake_case, unlike every Connect
    // procedure. That asymmetry is the server's, and a client must handle it.
    return {
      tokens: Tokens.fromHttp(body as Record<string, unknown>, this.#now()),
      clearCookie: `${LOGIN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    };
  }

  /** Sign in directly. First-party native and CLI applications only — a
   * password typed anywhere but Anubis's origin is one you now own. */
  async login(cred: {
    username: string;
    password: string;
    tenant?: string;
    realm?: string;
    clientId?: string;
    deviceFp?: string;
  }): Promise<LoginResult> {
    const out = (await this.#rpc(
      PROC.login,
      {
        tenant: cred.tenant ?? this.#opts.tenant ?? "",
        realm: cred.realm ?? "",
        username: cred.username,
        password: cred.password,
        client_id: cred.clientId ?? this.#opts.clientId ?? "",
        device_fp: cred.deviceFp ?? "",
      },
      false,
    )) as Record<string, any>;

    if (out.enrolmentRequired) {
      throw new EnrolmentRequiredError(
        new AuthMethods(out.enrolmentRequired.factors ?? []),
        // protojson renders int64 as a JSON string, so this arrives quoted.
        new Date(Number(out.enrolmentRequired.deadline ?? 0) * 1000),
        out.enrolmentRequired.grantToken ?? "",
      );
    }
    const result: LoginResult = {};
    if (out.tokens) result.tokens = this.#tokens(out.tokens);
    if (out.mfa) {
      result.mfa = {
        token: out.mfa.mfaToken,
        methods: new AuthMethods(out.mfa.methods ?? []),
        expiresIn: Number(out.mfa.expiresIn ?? 0),
      };
    }
    if (out.enrolmentDue) {
      result.enrolmentDue = {
        factors: out.enrolmentDue.factors ?? [],
        deadline: new Date(Number(out.enrolmentDue.deadline ?? 0) * 1000),
      };
    }
    return result;
  }

  async verifyMfa(mfaToken: string, code: string): Promise<Tokens> {
    const out = (await this.#rpc(PROC.verifyMfa, { mfa_token: mfaToken, code }, false)) as any;
    if (!out?.tokens) throw new Error("anubis: mfa verification returned no tokens");
    return this.#tokens(out.tokens);
  }

  // ---- decisions ----------------------------------------------------------

  /**
   * Ask whether the verified caller may do something; throw a typed error if
   * not.
   *
   * The subject, amr and auth_time come from the principal the middleware
   * verified. A caller assembling this by hand leaves amr and auth_time out,
   * and that turns every step-up rule into a silent permanent denial that
   * looks like a permissions bug.
   */
  async require(
    principal: Principal,
    permission: PermissionLike,
    scopes?: ScopesLike,
  ): Promise<void> {
    (await this.authorize(principal, permission, scopes)).orThrow();
  }

  /** The same question, answered as data. */
  async authorize(
    principal: Principal,
    permission: PermissionLike,
    scopes?: ScopesLike,
  ): Promise<Decision> {
    const p = Permission.of(permission);
    if (!p.isValid) {
      // Caught here rather than answered with a denial, because a denial for a
      // permission that cannot exist is indistinguishable from one for a
      // permission the caller does not hold.
      throw new Error(`anubis: "${p}" is not a permission key — expected app:resource:action`);
    }
    const id = principal.identity;
    const out = (await this.#rpc(
      PROC.authorize,
      {
        subject: id.subject,
        permission: p.key,
        scopes: Scopes.of(scopes).toWire(),
        amr: id.methods.toStrings(),
        auth_time: id.authenticatedAt ? Math.floor(id.authenticatedAt.getTime() / 1000) : 0,
      },
      true,
      principal.token,
    )) as Record<string, any>;
    return Decision.fromWire(out, p, id.subject);
  }

  /** The full evaluation tree. Reach for it the moment a denial is not
   * obvious: past two axes, "why" stops being answerable by reading grants. */
  async explain(principal: Principal, permission: PermissionLike, scopes?: ScopesLike) {
    return (await this.#rpc(
      PROC.explain,
      {
        subject: principal.subject,
        permission: Permission.of(permission).key,
        scopes: Scopes.of(scopes).toWire(),
      },
      true,
      principal.token,
    )) as { allow: boolean; reason: string; failingAxis: string; detailJson: string };
  }

  /** Turn a step-up refusal into the sign-in redirect that satisfies it. It is
   * a fresh authorization request, because that is what re-authentication is. */
  beginStepUp(err: unknown, p: LoginParams): BeginLoginResult {
    if (!(err instanceof StepUpRequiredError)) {
      throw new Error("anubis: beginStepUp needs a step-up refusal");
    }
    return this.beginLogin({
      ...p,
      prompt: "login",
      acrValues: p.acrValues ?? err.requiredAmr.toStrings(),
      maxAge: p.maxAge ?? err.maxAuthAgeSeconds,
    });
  }

  // ---- sessions -----------------------------------------------------------

  /** Rotate a pair once. Prefer TokenSource, which serialises this: calling it
   * from concurrent handlers is how a client reports itself for theft. */
  async refresh(refreshToken: string): Promise<Tokens> {
    const out = (await this.#rpc(PROC.refresh, { refresh_token: refreshToken }, false)) as any;
    if (!out?.tokens) throw new Error("anubis: refresh returned no tokens");
    return this.#tokens(out.tokens);
  }

  async clientCredentials(audience?: string): Promise<Tokens> {
    if (!this.#opts.clientId || !this.#opts.clientSecret) {
      throw new Error("anubis: client credentials need clientId and clientSecret");
    }
    const out = (await this.#rpc(
      PROC.clientCredentials,
      {
        tenant: this.#opts.tenant ?? "",
        client_id: this.#opts.clientId,
        client_secret: this.#opts.clientSecret,
        audience: audience ?? "",
      },
      false,
    )) as any;
    return new Tokens({
      accessToken: out.accessToken,
      tokenType: out.tokenType ?? "Bearer",
      expiresIn: Number(out.expiresIn ?? 0),
      issuedAt: this.#now(),
    });
  }

  async introspect(token: string, principal?: Principal) {
    return (await this.#rpc(PROC.introspect, { token }, true, principal?.token)) as Record<string, unknown>;
  }

  logoutUrl(p: { tenant?: string; postLogoutRedirectUri?: string; page?: string } = {}): string {
    const q = new URLSearchParams();
    const optional: Record<string, string | undefined> = {
      tenant: p.tenant ?? this.#opts.tenant,
      post_logout_redirect_uri: p.postLogoutRedirectUri,
      page: p.page,
    };
    for (const [k, v] of Object.entries(optional)) if (v) q.set(k, v);
    return q.size ? `${this.#base}${PATH.logout}?${q}` : `${this.#base}${PATH.logout}`;
  }

  async logoutAll(principal: Principal): Promise<void> {
    await this.#rpc(PROC.logoutAll, {}, true, principal.token);
  }

  /**
   * Verify a back-channel logout token and return the event.
   *
   * The event-claim check is what stops somebody replaying a captured ACCESS
   * token here to sign a user out at will: an access token passes every other
   * check, because the same issuer minted it for the same audience.
   */
  static async verifyLogoutToken(
    verifier: Verifier,
    token: string,
  ): Promise<{ sessionId: string; subject: string; tenant: string }> {
    const claims = await verifier.verify(token);
    // Safe to read the raw message now: the signature covering it is checked.
    const { message } = pasetoParse(token);
    const body = JSON.parse(message.toString("utf8")) as {
      events?: Record<string, unknown>;
      sid?: string;
    };
    if (!body.events?.["http://schemas.openid.net/event/backchannel-logout"]) {
      throw new Error("anubis: not a back-channel logout token (no logout event claim)");
    }
    return { sessionId: body.sid ?? claims.sid ?? "", subject: claims.sub, tenant: claims.tid ?? "" };
  }

  // ---- transport ----------------------------------------------------------

  #tokens(t: Record<string, unknown>): Tokens {
    return Tokens.fromConnect(t, this.#now());
  }

  /**
   * Request fields go out with their proto names (snake_case). protojson
   * accepts those as well as lowerCamelCase, and they are what the API
   * documentation shows — so a body copied from the docs and one built here
   * are the same body.
   */
  async #rpc(procedure: string, body: unknown, needsAuth: boolean, bearer?: string): Promise<unknown> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (needsAuth) {
      const credential = this.#opts.apiKey ?? bearer;
      if (!credential) {
        throw new Error(
          "anubis: no credential — configure apiKey, or pass the principal whose token should be presented",
        );
      }
      headers.authorization = `Bearer ${credential}`;
    }
    return this.#request(procedure, { method: "POST", headers, body: JSON.stringify(body) });
  }

  async #request(path: string, init: RequestInit): Promise<unknown> {
    const headers = new Headers(init.headers);
    for (const [k, v] of Object.entries(this.#opts.headers)) headers.set(k, v);
    if (this.#opts.tenant) headers.set("x-anubis-tenant", this.#opts.tenant);

    const signal = AbortSignal.timeout(this.#opts.timeoutMs);
    let res: Response;
    try {
      // redirect: "error" — a Connect procedure has no reason to redirect, and
      // following one would carry the credential to whatever host it names.
      res = await this.#fetch(this.#base + path, { ...init, headers, signal, redirect: "error" });
    } catch (e) {
      throw new UnavailableError(e);
    }
    const text = await res.text();
    if (!res.ok) throw classify(parseWireError(text, res.status), res.headers);
    return text ? JSON.parse(text) : {};
  }
}

// ---- error decoding -------------------------------------------------------

/** Covers both shapes Anubis answers with: the Connect error object and the
 * plain-HTTP envelope. One vocabulary, two transports — but not one field name
 * for the code. */
function parseWireError(text: string, status: number): ApiError {
  let w: Record<string, any>;
  try {
    w = JSON.parse(text);
  } catch {
    return new ApiError("", text.slice(0, 512), "", status);
  }
  let code: string = w.error || w.code || "";
  let requestId: string = w.request_id ?? "";
  let details: Record<string, string> = {};

  if (Array.isArray(w.details)) {
    for (const d of w.details) {
      if (typeof d?.type === "string" && d.type.endsWith("ErrorInfo") && typeof d.value === "string") {
        const info = decodeErrorInfo(d.value);
        code = info.code || code;
        requestId = info.requestId || requestId;
        details = info.details;
      }
    }
  } else if (w.details && typeof w.details === "object") {
    details = w.details as Record<string, string>;
  }
  return new ApiError(code, w.message ?? "", requestId, status, details);
}

/**
 * Read anubis.v1.ErrorInfo straight off the protobuf wire.
 *
 * Depending on a protobuf runtime to read three fields would cost every
 * consumer of this package a dependency, and the whole point of the offline
 * half is that it costs them nothing.
 *
 *   string code = 1; string request_id = 2; map<string,string> details = 3;
 */
function decodeErrorInfo(b64: string): { code: string; requestId: string; details: Record<string, string> } {
  const out = { code: "", requestId: "", details: {} as Record<string, string> };
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, "base64");
  } catch {
    return out;
  }
  let i = 0;
  while (i < buf.length) {
    const [tag, tagLen] = varint(buf, i);
    if (tagLen === 0 || (tag & 7) !== 2) return out;
    i += tagLen;
    const [size, sizeLen] = varint(buf, i);
    if (sizeLen === 0) return out;
    i += sizeLen;
    const payload = buf.subarray(i, i + size);
    if (payload.length < size) return out;
    i += size;

    const field = tag >>> 3;
    if (field === 1) out.code = payload.toString("utf8");
    else if (field === 2) out.requestId = payload.toString("utf8");
    else if (field === 3) {
      const entry = decodeErrorInfo(payload.toString("base64"));
      // A map entry is key = field 1, value = field 2 — the same shapes.
      if (entry.code) out.details[entry.code] = entry.requestId;
    }
  }
  return out;
}

function varint(b: Buffer, at: number): [number, number] {
  let value = 0;
  let shift = 0;
  for (let i = at; i < b.length && i - at < 10; i++) {
    const byte = b[i]!;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [value >>> 0, i - at + 1];
    shift += 7;
  }
  return [0, 0];
}

// ---- small helpers --------------------------------------------------------

function readCookie(header: string | null | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

/** Constant time because the comparison is against an attacker-supplied value,
 * and a state that leaks byte by byte is a state that can be guessed. */
function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length || ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}

export { REFRESH_MARGIN_S };
