import { REFRESH_MARGIN_S, Tokens, type Client } from "./client.js";

/**
 * Holds a token pair and keeps it fresh.
 *
 * Refresh tokens are single-use and rotate. Two concurrent handlers that both
 * notice an expired access token will both refresh; one wins, and the other
 * presents a token Anubis has already consumed. Anubis reads that, correctly,
 * as theft — and revokes the family and the session. A client without this
 * logs its own users out under concurrency, and pages a human doing it.
 *
 * So refreshes are single-flight: the first caller refreshes, everyone else
 * awaits that same promise. One refresh per rotation, always.
 */
export class TokenSource {
  #tokens: Tokens;
  #inflight: Promise<Tokens> | null = null;
  #onRotate?: (t: Tokens) => void | Promise<void>;

  constructor(
    private readonly client: Client,
    tokens: Tokens,
    private readonly now: () => number = Date.now,
    /** Client credentials re-mint from their own secret and never hold a
     * refresh token; a user session cannot refresh without one. */
    private readonly mint?: () => Promise<Tokens>,
  ) {
    this.#tokens = tokens;
  }

  /**
   * Register a callback for every new pair.
   *
   * It is awaited BEFORE token() resolves, so a process that dies between the
   * two has already stored the new pair. Storing afterwards loses the rotation
   * on a crash and produces the same self-inflicted theft signal this class
   * exists to prevent.
   */
  onRotate(fn: (t: Tokens) => void | Promise<void>): this {
    this.#onRotate = fn;
    return this;
  }

  current(): Tokens {
    return this.#tokens;
  }

  async token(): Promise<Tokens> {
    if (this.#valid()) return this.#tokens;
    // Somebody is already rotating: await their result rather than starting a
    // second rotation, because the second one is the theft signal.
    if (this.#inflight) return this.#inflight;

    this.#inflight = this.#rotate().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  async #rotate(): Promise<Tokens> {
    const current = this.#tokens;
    const next = this.mint
      ? await this.mint()
      : await this.client.refresh(requireRefreshToken(current));

    // A re-mint returns no refresh token; carry the old one forward so the
    // source stays usable. Tokens is immutable, so this is a new pair rather
    // than a field assignment — a shared reference cannot change underneath a
    // caller that already read it.
    const adopted = next.hasRefresh
      ? next
      : new Tokens({ ...next, refreshToken: current.refreshToken });
    // Adopted before the persist callback runs: the old refresh token is
    // already dead on the server, so holding it after a failed persist would
    // guarantee a reuse refusal next time.
    this.#tokens = adopted;

    if (this.#onRotate) await this.#onRotate(adopted);
    return adopted;
  }

  #valid(): boolean {
    if (!this.#tokens.accessToken) return false;
    const expiry = this.#tokens.expiry;
    // No expiry known: the only honest reading is that it is still good, since
    // refreshing on every call would burn a rotation per request.
    if (!expiry) return true;
    return this.now() + REFRESH_MARGIN_S * 1000 < expiry.getTime();
  }
}

function requireRefreshToken(t: Tokens): string {
  if (!t.hasRefresh) {
    throw new Error("anubis: the access token has expired and there is no refresh token — sign in again");
  }
  return t.refreshToken;
}
