/**
 * Express / Connect-style adapters.
 *
 * Typed structurally rather than against @types/express, so this package keeps
 * its promise of no dependencies. Anything with the shape below works —
 * Express, Connect, Restify.
 */
import type { Client } from "./client.js";
import { DeniedError, StepUpRequiredError } from "./errors.js";
import type { PermissionLike, ScopesLike } from "./identity.js";
import { Principal, Verifier } from "./verifier.js";

interface Req {
  headers: Record<string, string | string[] | undefined>;
  anubis?: Principal;
}
interface Res {
  status(code: number): Res;
  setHeader(name: string, value: string): void;
  end(body?: string): void;
}
type Next = (err?: unknown) => void;

/** Rejects requests without a valid bearer token and attaches the principal as
 * req.anubis. 401s carry WWW-Authenticate so standard clients know to
 * re-authenticate. */
export function requireToken(verifier: Verifier) {
  return async (req: Req, res: Res, next: Next): Promise<void> => {
    const header = req.headers.authorization;
    const token = Verifier.bearer(Array.isArray(header) ? header[0] : header);
    if (!token) return unauthorized(res, "missing bearer token");
    try {
      const claims = await verifier.verify(token);
      req.anubis = new Principal(claims, token);
      next();
    } catch {
      unauthorized(res, "invalid token");
    }
  };
}

/** Guards a route with a permission check. Mount inside requireToken, which is
 * what puts the principal on the request. */
export function requires(
  client: Client,
  permission: PermissionLike,
  scopes: (req: Req) => ScopesLike = () => ({}),
) {
  return async (req: Req, res: Res, next: Next): Promise<void> => {
    if (!req.anubis) return unauthorized(res, "missing bearer token");
    try {
      await client.require(req.anubis, permission, scopes(req));
      next();
    } catch (e) {
      if (e instanceof StepUpRequiredError) {
        // The same machine-readable signal an insufficient-amr rejection uses,
        // so a client that handles one handles both.
        res.setHeader("WWW-Authenticate", 'Bearer error="insufficient_user_authentication"');
        res.status(401).end("step-up authentication required");
        return;
      }
      if (e instanceof DeniedError) {
        res.status(403).end(e.message);
        return;
      }
      next(e);
    }
  };
}

function unauthorized(res: Res, message: string): void {
  res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
  res.status(401).end(message);
}
