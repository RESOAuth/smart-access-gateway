// The sign-in session.
//
// There is no session store. The session *is* the cookie: an AES-256-GCM
// sealed record whose key is derived from the master secret, so it cannot be
// read or altered by the browser and cannot be replayed into any other
// purpose. That keeps SAG stateless and keeps confidentiality in a symmetric
// primitive, which is already resistant to a quantum adversary.
//
// Two lifetimes bound it. `exp` is the idle timeout and is pushed forward each
// time the session is used; `abs` is the absolute cap and never moves, so a
// session cannot be kept alive indefinitely by touching it.

import { seal, unseal, SealError } from './crypto/secrets.js';
import { nowSeconds, randomToken } from './util/bytes.js';
import { serialiseCookie, parseCookies } from './util/http.js';
import { sha256b64u } from './crypto/secrets.js';

const PURPOSE = 'session';

/**
 * The cookie name for a given scope.
 *
 * With per-RP sessions each relying party gets its own cookie, named after a
 * hash of the client id rather than the id itself, so the cookie jar does not
 * enumerate which applications a person uses.
 */
export async function cookieNameFor(config, clientId) {
  // Callers have already applied the per-client scope override. A client id
  // therefore always means an isolated cookie, even when the instance default
  // is shared.
  if (!clientId) return config.session.cookieName;
  const tag = (await sha256b64u('cookie ' + clientId)).slice(0, 12).replaceAll('-', '').replaceAll('_', '');
  return config.session.cookieName + '_' + tag;
}

/** Which client id scopes a session cookie, after client overrides. */
export function sessionClientFor(config, client) {
  const scope = client?.sessionScope || config.session.scope;
  return scope === 'rp' ? client?.clientId : undefined;
}

/**
 * Build a fresh session record.
 *
 * @param {object} args
 * @param {string} args.email     Normalised address
 * @param {string} args.acr
 * @param {string[]} args.amr
 * @param {string} [args.upstream]      Upstream id that authenticated them
 * @param {string} [args.upstreamLabel] Human-readable name for that upstream
 * @param {object} [args.claims]        Upstream claims worth keeping (name, picture)
 */
export function newSession(config, args) {
  const now = nowSeconds();
  return {
    v: 1,
    sid: randomToken(16),
    email: args.email,
    acr: args.acr,
    amr: args.amr || [],
    auth_time: args.authTime ?? now,
    upstream: args.upstream,
    upstreamLabel: args.upstreamLabel,
    claims: args.claims || undefined,
    iat: now,
    exp: now + config.session.idleTtlSeconds,
    abs: now + config.session.maxLifetimeSeconds,
  };
}

/**
 * Re-authentication on top of an existing session.
 *
 * The session identifier survives, so a relying party watching `sid` sees one
 * continuous session, but `auth_time`, `acr` and `amr` move to the new, usually
 * stronger, authentication. The absolute cap is not extended: stepping up
 * should not buy more total lifetime.
 */
export function reauthenticate(config, session, args) {
  const now = nowSeconds();
  return {
    ...session,
    email: args.email ?? session.email,
    acr: args.acr,
    amr: args.amr || [],
    auth_time: now,
    upstream: args.upstream,
    upstreamLabel: args.upstreamLabel,
    claims: args.claims || session.claims,
    exp: now + config.session.idleTtlSeconds,
  };
}

/** Push the idle timeout forward, never past the absolute cap. */
export function touch(config, session) {
  const now = nowSeconds();
  return { ...session, exp: Math.min(now + config.session.idleTtlSeconds, session.abs) };
}

export async function sealSession(config, session) {
  return seal(config.secrets[0], PURPOSE, session);
}

/**
 * Read and validate the session from a request. Returns undefined when there
 * is none, or when what is there is expired, tampered with, or sealed under a
 * secret we no longer hold.
 */
export async function readSession(config, request, clientId, stateStore) {
  const name = await cookieNameFor(config, clientId);
  return readSessionByName(config, request, name, stateStore);
}

/** Read one explicitly named cookie, used when a global logout clears many. */
export async function readSessionByName(config, request, name, stateStore) {
  const raw = parseCookies(request).get(name);
  if (!raw) return undefined;
  try {
    const session = await unseal(config.secrets, PURPOSE, raw);
    const now = nowSeconds();
    if (typeof session.abs === 'number' && session.abs < now) return undefined;
    if (!session.email || !session.sid) return undefined;
    if (stateStore && (await stateStore.has(revocationKey(session.sid)))) return undefined;
    return session;
  } catch (err) {
    if (err instanceof SealError) return undefined;
    throw err;
  }
}

/**
 * Revoke every copy of a session until its natural absolute expiry.
 *
 * `claim` is deliberately used rather than an overwrite: repeated logout is
 * harmless, and every backend already gives claims an atomic TTL.
 */
export async function revokeSession(stateStore, session) {
  if (!stateStore || !session?.sid || !Number.isFinite(session.abs)) return;
  const ttl = session.abs - nowSeconds();
  if (ttl > 0) await stateStore.claim(revocationKey(session.sid), ttl);
}

const revocationKey = (sid) => 'session-revoked:' + sid;

const cookiePath = (config) => (config.devMode ? config.basePath || '/' : '/');

/**
 * A Set-Cookie value for a session.
 *
 * SameSite=Lax is right rather than Strict: the browser arrives at /authorize
 * by a top-level navigation from the relying party, which Lax permits and
 * Strict would block, breaking silent sign-in for every cross-site relying
 * party. It still withholds the cookie from cross-site POSTs and subresources.
 */
export async function sessionCookie(config, session, clientId) {
  const name = await cookieNameFor(config, clientId);
  const value = await sealSession(config, session);
  return serialiseCookie(name, value, {
    maxAge: Math.max(0, session.exp - nowSeconds()),
    sameSite: 'Lax',
    secure: !config.insecureTransport,
    path: cookiePath(config),
  });
}

export async function clearSessionCookie(config, clientId) {
  const name = await cookieNameFor(config, clientId);
  return serialiseCookie(name, '', {
    maxAge: 0,
    sameSite: 'Lax',
    secure: !config.insecureTransport,
    path: cookiePath(config),
  });
}

/**
 * Every session cookie the browser is currently holding for this instance.
 *
 * Needed for a global sign-out under per-RP scope, where the names are hashes
 * and so cannot be recomputed without knowing every client id. Matching on the
 * configured prefix finds them all.
 */
export function allSessionCookieNames(config, request) {
  const prefix = config.session.cookieName;
  return [...parseCookies(request).keys()].filter((n) => n === prefix || n.startsWith(prefix + '_'));
}

export function clearCookieByName(config, name) {
  return serialiseCookie(name, '', {
    maxAge: 0,
    sameSite: 'Lax',
    secure: !config.insecureTransport,
    path: cookiePath(config),
  });
}

/** Is this session usable for a request with these constraints? */
export function sessionIsFresh(session, { maxAge, clockSkew = 60 } = {}) {
  const now = nowSeconds();
  if (typeof session.exp === 'number' && session.exp + clockSkew < now) return false;
  if (typeof session.abs === 'number' && session.abs < now) return false;
  if (maxAge !== undefined && session.auth_time + maxAge < now) return false;
  return true;
}
