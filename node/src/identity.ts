/**
 * The SDK's vocabulary.
 *
 * Every type here was a string, a string[] or a Record<string, string> once,
 * and each of those was a place where a caller could pass the right shape with
 * the wrong meaning and find out at runtime — or worse, not find out, because
 * a mistyped axis is answered with a denial that looks exactly like a real one.
 *
 * The API accepts the plain forms too (`PermissionLike`, `ScopesLike`), so
 * nothing below is ceremony you have to perform to make a call. It is there
 * for when you want to ask a question of a value rather than parse it again.
 */

/** A permission key, or the string that spells one. */
export type PermissionLike = Permission | string;
/** A scope set, or the plain object that spells one. */
export type ScopesLike = Scopes | Record<string, string>;
/** A role, or its name. */
export type RoleLike = Role | string;

/**
 * A full permission key: `app:resource:action`.
 *
 * The full key is what tokens carry and what `authorize` takes. Inside an
 * application manifest the same permission is written WITHOUT the application
 * prefix — `invoice:approve` — and that asymmetry has cost people real time.
 * `manifest()` makes the two forms convertible instead of a thing to remember.
 */
export class Permission {
  private readonly segments: readonly [string, string, string] | null;

  private constructor(readonly key: string) {
    const parts = key.split(":");
    this.segments =
      parts.length === 3 && parts.every((p) => p !== "")
        ? [parts[0]!, parts[1]!, parts[2]!]
        : null;
  }

  static of(key: PermissionLike): Permission {
    return key instanceof Permission ? key : new Permission(key);
  }

  static from(app: string, resource: string, action: string): Permission {
    return new Permission(`${app}:${resource}:${action}`);
  }

  /** The application slug the permission belongs to, or "" if malformed. */
  get app(): string {
    return this.segments?.[0] ?? "";
  }

  get resource(): string {
    return this.segments?.[1] ?? "";
  }

  get action(): string {
    return this.segments?.[2] ?? "";
  }

  /** Whether the key has the three non-empty parts Anubis requires. */
  get isValid(): boolean {
    return this.segments !== null;
  }

  /** The permission as a manifest writes it: `resource:action`, no prefix. */
  manifest(): string {
    return this.segments ? `${this.resource}:${this.action}` : this.key;
  }

  equals(other: PermissionLike): boolean {
    return this.key === Permission.of(other).key;
  }

  toString(): string {
    return this.key;
  }

  toJSON(): string {
    return this.key;
  }
}

/**
 * A granted role, which Anubis returns prefixed with the application that
 * defined it: a manifest declaring `clerk` for `billing` yields `billing.clerk`.
 *
 * Comparing a returned role against the unprefixed manifest name is the
 * mistake this type exists to make visible.
 */
export class Role {
  private constructor(readonly value: string) {}

  static of(role: RoleLike): Role {
    return role instanceof Role ? role : new Role(role);
  }

  static from(app: string, name: string): Role {
    return new Role(`${app}.${name}`);
  }

  /** The application that defined the role, or "" for an unprefixed one. */
  get app(): string {
    const dot = this.value.indexOf(".");
    return dot >= 0 ? this.value.slice(0, dot) : "";
  }

  /** The role as the manifest declared it, without the prefix. */
  get name(): string {
    const dot = this.value.indexOf(".");
    return dot >= 0 ? this.value.slice(dot + 1) : this.value;
  }

  equals(other: RoleLike): boolean {
    return this.value === Role.of(other).value;
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }
}

/** The set of roles a caller holds. */
export class Roles implements Iterable<Role> {
  private readonly items: readonly Role[];

  constructor(roles: readonly RoleLike[] = []) {
    this.items = roles.map((r) => Role.of(r));
  }

  [Symbol.iterator](): Iterator<Role> {
    return this.items[Symbol.iterator]();
  }

  get size(): number {
    return this.items.length;
  }

  has(role: RoleLike): boolean {
    const want = Role.of(role);
    return this.items.some((r) => r.equals(want));
  }

  hasAny(...roles: RoleLike[]): boolean {
    return roles.some((r) => this.has(r));
  }

  /** Narrow to the roles one application defined. */
  ofApp(app: string): Roles {
    return new Roles(this.items.filter((r) => r.app === app));
  }

  toArray(): Role[] {
    return [...this.items];
  }

  toStrings(): string[] {
    return this.items.map((r) => r.value);
  }

  toJSON(): string[] {
    return this.toStrings();
  }
}

/** An effective permission set — what a caller may do, expanded from every role. */
export class Permissions implements Iterable<Permission> {
  private readonly items: readonly Permission[];

  constructor(permissions: readonly PermissionLike[] = []) {
    this.items = permissions.map((p) => Permission.of(p));
  }

  [Symbol.iterator](): Iterator<Permission> {
    return this.items[Symbol.iterator]();
  }

  get size(): number {
    return this.items.length;
  }

  has(permission: PermissionLike): boolean {
    const want = Permission.of(permission);
    return this.items.some((p) => p.equals(want));
  }

  hasAny(...permissions: PermissionLike[]): boolean {
    return permissions.some((p) => this.has(p));
  }

  ofApp(app: string): Permissions {
    return new Permissions(this.items.filter((p) => p.app === app));
  }

  toStrings(): string[] {
    return this.items.map((p) => p.key);
  }

  toJSON(): string[] {
    return this.toStrings();
  }
}

/** The reserved axis for self-scoped access: the owner of the record touched. */
export const OWNER_AXIS = "_owner";

/**
 * The target node on each axis an action touches.
 *
 * Supply every axis the action could be constrained on. Within an axis, any
 * granted node at or above the target satisfies it; across axes, all must
 * hold. On a strict axis an omitted axis is DENIED, not ignored — fail-closed
 * is the whole design, and "I forgot an axis" and "they may not do this" are
 * the same answer from outside.
 *
 * Immutable: `with` and `merge` return copies, so a scope set shared between
 * handlers cannot change underneath one of them.
 */
export class Scopes {
  private readonly entries: Readonly<Record<string, string>>;

  constructor(entries: Readonly<Record<string, string>> = {}) {
    this.entries = { ...entries };
  }

  static of(scopes: ScopesLike | undefined | null): Scopes {
    if (scopes instanceof Scopes) return scopes;
    return new Scopes(scopes ?? {});
  }

  /** The scope set for self-scoped access, naming the reserved axis so it
   * cannot be misspelt into a silent denial. */
  static owner(subject: string): Scopes {
    return new Scopes({ [OWNER_AXIS]: subject });
  }

  with(axis: string, node: string): Scopes {
    return new Scopes({ ...this.entries, [axis]: node });
  }

  merge(other: ScopesLike): Scopes {
    return new Scopes({ ...this.entries, ...Scopes.of(other).entries });
  }

  node(axis: string): string | undefined {
    return this.entries[axis];
  }

  /** The axes supplied, sorted, so a scope set has one printable form. */
  axes(): string[] {
    return Object.keys(this.entries).sort();
  }

  get isEmpty(): boolean {
    return Object.keys(this.entries).length === 0;
  }

  /** The plain object the API expects. */
  toWire(): Record<string, string> {
    return { ...this.entries };
  }

  toJSON(): Record<string, string> {
    return this.toWire();
  }

  toString(): string {
    return this.axes()
      .map((axis) => `${axis}=${this.entries[axis]}`)
      .join(" ");
  }
}

/** The methods Anubis mints today. A realm may require others later; the type
 * is open, and these are the ones worth having a name for. */
export const Method = {
  Password: "pwd",
  OTP: "otp",
  DeviceKey: "device_key",
} as const;

/**
 * The methods a caller authenticated with — the `amr` claim.
 *
 * Step-up decisions turn on it, which is why it travels on every authorization
 * request.
 */
export class AuthMethods implements Iterable<string> {
  private readonly items: readonly string[];

  constructor(methods: readonly string[] = []) {
    this.items = [...methods];
  }

  [Symbol.iterator](): Iterator<string> {
    return this.items[Symbol.iterator]();
  }

  get size(): number {
    return this.items.length;
  }

  has(method: string): boolean {
    return this.items.includes(method);
  }

  /** Every listed method was used — the local form of a step-up check,
   * answerable without asking Anubis. */
  hasAll(...methods: string[]): boolean {
    return methods.every((m) => this.has(m));
  }

  toStrings(): string[] {
    return [...this.items];
  }

  toJSON(): string[] {
    return this.toStrings();
  }

  toString(): string {
    return this.items.join(" ");
  }
}

/**
 * Who a caller is and what they hold, in one place.
 *
 * It answers the question every application asks first — who is this, what
 * roles do they have, what are they scoped to right now — without reaching
 * into a claim set and remembering which fields mean what.
 *
 * It is a VIEW OF A SESSION, not of a person. `roles` and `scopes` are what
 * this token was minted with: the roles held at issuance, and the ONE node per
 * axis the session is currently acting as. It is not the full set of nodes the
 * person is entitled to — that lives in grants, on the admin plane.
 */
export class Identity {
  constructor(
    readonly subject: string,
    readonly session: string,
    readonly tenant: string,
    readonly realm: string,
    readonly roles: Roles,
    readonly scopes: Scopes,
    readonly methods: AuthMethods,
    readonly assurance: number,
    readonly authenticatedAt: Date | null,
    readonly expiresAt: Date | null,
  ) {}

  /** How long ago the caller authenticated, in milliseconds. */
  get authAgeMs(): number {
    return this.authenticatedAt ? Date.now() - this.authenticatedAt.getTime() : 0;
  }

  /** A service acting as itself rather than a person: no session, no refresh. */
  get isApplication(): boolean {
    return this.subject.startsWith("app_");
  }

  /** The cheap local check. It answers "does this token say so", which is not
   * the same question as "may they do this" — roles are an input to a
   * decision, not the decision. Reach for `require` when it matters. */
  hasRole(role: RoleLike): boolean {
    return this.roles.has(role);
  }

  /** The node this session is acting as on one axis. */
  activeScope(axis: string): string | undefined {
    return this.scopes.node(axis);
  }

  toString(): string {
    return this.scopes.isEmpty ? this.subject : `${this.subject} [${this.scopes}]`;
  }
}

/** Unix seconds as the wire carries them, or null when absent. */
export function toDate(seconds: number | string | undefined | null): Date | null {
  const n = typeof seconds === "string" ? Number.parseInt(seconds, 10) : seconds;
  return n ? new Date(n * 1000) : null;
}

/** Parse a duration Anubis expressed as a string ("2m"). */
export function parseAgeSeconds(value: string): number | undefined {
  const m = /^(\d+)(s|m|h)$/.exec(value.trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  return m[2] === "s" ? n : m[2] === "m" ? n * 60 : n * 3600;
}
