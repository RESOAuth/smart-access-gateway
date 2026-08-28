// Working out who is asking.
//
// A relying party can be described in four ways, checked in this order:
//
//   1. Statically, by environment variable. Always available, no network.
//   2. From a client store - Cloudflare KV or S3 - keyed by client id.
//   3. As an opaque client: a GUID whose record lives in the store, with a
//      hashed secret or a JWKS.
//   4. By Client ID Metadata Document: the client id is an https URL that
//      serves its own metadata. No registration step at all.
//
// The first three are configuration an operator controls. CIMD is not, so it
// carries the most restrictions: public-network resolution, an optional
// allow-list of domains, and a size cap. Trusting a domain means trusting the
// redirect URIs its documents declare.

import { OAuthError } from '../util/errors.js';
import { BodyTooLargeError, fetchWithTimeout, readJsonLimited, readTextLimited } from '../util/http.js';
import { nowSeconds } from '../util/bytes.js';
import { isIpAddress, isLoopbackIp, isPublicIp } from '../util/ip.js';

/** Normalise whatever a source produced into one client shape. */
function normalise(raw) {
  return {
    source: raw.source,
    clientId: raw.clientId,
    clientName: raw.clientName || raw.clientId,
    clientSecret: raw.clientSecret,
    clientSecretDigest: raw.clientSecretDigest,
    redirectUris: raw.redirectUris || [],
    postLogoutRedirectUris: raw.postLogoutRedirectUris || [],
    jwks: raw.jwks,
    jwksUri: raw.jwksUri,
    tokenEndpointAuthMethod: raw.tokenEndpointAuthMethod || 'none',
    scopes: raw.scopes?.length ? raw.scopes : undefined,
    acrValues: raw.acrValues || [],
    idTokenSignedResponseAlg: raw.idTokenSignedResponseAlg,
    sessionScope: raw.sessionScope,
    logoutConfirm: raw.logoutConfirm,
    subjectType: raw.subjectType,
    sectorIdentifier: raw.sectorIdentifier,
    sanitisePlusEmails: raw.sanitisePlusEmails,
    requirePkce: raw.requirePkce !== false,
    logoUri: raw.logoUri,
    policyUri: raw.policyUri,
    tosUri: raw.tosUri,
  };
}

const isConfidential = (client) => client.tokenEndpointAuthMethod !== 'none';

/**
 * Exact-match redirect URI check.
 *
 * OAuth 2.1 removed prefix and wildcard matching because every variant of it
 * has been used to smuggle a code to an attacker's page. The only concession
 * is the loopback port, which RFC 8252 requires to be ignored because a native
 * application cannot know which port it will get.
 */
export function redirectUriAllowed(client, candidate, schemes = ['*']) {
  let want;
  try {
    want = new URL(candidate);
  } catch {
    return false;
  }
  const scheme = want.protocol.slice(0, -1).toLowerCase();
  if (!schemes.includes('*') && !schemes.includes(scheme)) return false;
  for (const registered of client.redirectUris) {
    let have;
    try {
      have = new URL(registered);
    } catch {
      continue;
    }
    if (have.href === want.href) return true;
    const loopback = (h) => h === '127.0.0.1' || h === '[::1]' || h === 'localhost';
    if (
      loopback(have.hostname) &&
      loopback(want.hostname) &&
      have.protocol === want.protocol &&
      have.hostname === want.hostname &&
      have.pathname === want.pathname &&
      have.search === want.search
    ) {
      return true;
    }
  }
  return false;
}

export function postLogoutRedirectAllowed(client, candidate, schemes = ['*']) {
  if (!client?.postLogoutRedirectUris?.length) return false;
  return redirectUriAllowed({ redirectUris: client.postLogoutRedirectUris }, candidate, schemes);
}

// ---------------------------------------------------------------------------
// CIMD
// ---------------------------------------------------------------------------

const cimdCache = new Map();
const MAX_CIMD_CACHED = 500;

function rememberCimd(clientId, client, ttlSeconds) {
  if (ttlSeconds <= 0) return;
  const now = nowSeconds();
  for (const [key, entry] of cimdCache) {
    if (entry.expiresAt <= now) cimdCache.delete(key);
  }
  if (cimdCache.size >= MAX_CIMD_CACHED) {
    const oldest = cimdCache.keys().next().value;
    if (oldest !== undefined) cimdCache.delete(oldest);
  }
  cimdCache.set(clientId, { client, expiresAt: now + ttlSeconds });
}

function cimdDomainAllowed(cimd, url) {
  if (!cimd.allowedDomains.length) return true;
  const host = url.hostname.toLowerCase();
  return cimd.allowedDomains.some((entry) => {
    const d = entry.toLowerCase().replace(/^\*?\./, '');
    if (host === d) return true;
    return cimd.allowSubdomains && host.endsWith('.' + d);
  });
}

const MAX_DNS_RESPONSE_BYTES = 64 * 1024;

async function resolveAddresses(config, hostname, resolver) {
  if (resolver && typeof resolver.resolve === 'function') {
    const results = await Promise.allSettled(['A', 'AAAA'].map((type) => resolver.resolve(hostname, type)));
    return results.flatMap((result) => (result.status === 'fulfilled' ? result.value || [] : [])).map(String);
  }

  const query = async (type, recordType) => {
    const url = new URL(config.dns.resolverUrl);
    url.searchParams.set('name', hostname);
    url.searchParams.set('type', type);
    const res = await fetchWithTimeout(
      url.toString(),
      { headers: { accept: 'application/dns-json' } },
      config.dns.timeoutMs,
    );
    if (!res.ok) throw new Error('DNS resolver returned HTTP ' + res.status);
    const body = await readJsonLimited(res, MAX_DNS_RESPONSE_BYTES);
    if (!Array.isArray(body.Answer)) return [];
    return body.Answer.filter((answer) => answer.type === recordType && typeof answer.data === 'string').map((answer) => answer.data);
  };

  const results = await Promise.allSettled([query('A', 1), query('AAAA', 28)]);
  if (results.every((result) => result.status === 'rejected')) throw results[0].reason;
  return results.flatMap((result) => (result.status === 'fulfilled' ? result.value : []));
}

/** Refuse CIMD fetches that could reach an address outside the public Internet. */
async function assertPublicCimdTarget(config, url, resolver) {
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (config.devMode && (hostname === 'localhost' || isLoopbackIp(hostname))) return;
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new OAuthError('invalid_client', 'Client metadata must be served from a public network address');
  }

  let addresses;
  if (isIpAddress(hostname)) addresses = [hostname];
  else {
    try {
      addresses = await resolveAddresses(config, hostname, resolver);
    } catch {
      throw new OAuthError('invalid_client', 'Could not resolve the client metadata host');
    }
  }
  if (addresses.length === 0) throw new OAuthError('invalid_client', 'Could not resolve the client metadata host');
  if (addresses.some((address) => !isPublicIp(String(address).replace(/^\[|\]$/g, '')))) {
    throw new OAuthError('invalid_client', 'Client metadata must be served from a public network address');
  }
}

/** A CIMD key endpoint must be controlled by the same client origin. */
function cimdJwksUri(value, documentUrl) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new OAuthError('invalid_client', 'Client metadata jwks_uri must be a URL');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new OAuthError('invalid_client', 'Client metadata jwks_uri must be a URL');
  }
  if (url.username || url.password || url.origin !== documentUrl.origin) {
    throw new OAuthError('invalid_client', 'Client metadata jwks_uri must share the document origin');
  }
  return url.href;
}

/**
 * Fetch a Client ID Metadata Document.
 *
 * The document's URL *is* the client id, so it authenticates itself: only
 * somebody controlling that origin can change what the client claims to be.
 * Redirects are refused for the same reason - following one would let the
 * origin in the client id hand off to another.
 */
async function resolveCimd(config, clientId, deps = {}) {
  const cimd = config.clients.cimd;
  if (!cimd.enabled) return undefined;
  let url;
  try {
    url = new URL(clientId);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' && !(config.devMode && url.protocol === 'http:')) return undefined;
  if (url.username || url.password) {
    throw new OAuthError('invalid_client', 'A client ID metadata document URL must not contain a username or password');
  }
  if (url.hash) throw new OAuthError('invalid_client', 'A client ID metadata document URL must not have a fragment');
  if (!cimdDomainAllowed(cimd, url)) {
    throw new OAuthError('invalid_client', 'This deployment does not accept client metadata from ' + url.hostname);
  }
  await assertPublicCimdTarget(config, url, deps.resolver);

  const cached = cimdCache.get(clientId);
  if (cached && cached.expiresAt > nowSeconds()) return cached.client;
  if (cached) cimdCache.delete(clientId);

  const res = await fetchWithTimeout(clientId, { headers: { accept: 'application/json' } }, 5000);
  if (!res.ok) throw new OAuthError('invalid_client', 'Could not read client metadata (HTTP ' + res.status + ')');
  let body;
  try {
    body = await readTextLimited(res, cimd.maxDocumentBytes);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      throw new OAuthError('invalid_client', 'Client metadata document is larger than this deployment accepts');
    }
    throw err;
  }
  let doc;
  try {
    doc = JSON.parse(body);
  } catch {
    throw new OAuthError('invalid_client', 'Client metadata document is not valid JSON');
  }
  const redirectUris = Array.isArray(doc.redirect_uris) ? doc.redirect_uris : [];
  for (const uri of redirectUris) {
    try {
      new URL(uri);
    } catch {
      throw new OAuthError('invalid_client', 'Client metadata contains a malformed redirect URI');
    }
  }
  if (redirectUris.length === 0) {
    throw new OAuthError('invalid_client', 'Client metadata document declares no redirect_uris');
  }

  const client = normalise({
    source: 'cimd',
    clientId,
    clientName: doc.client_name,
    redirectUris,
    postLogoutRedirectUris: doc.post_logout_redirect_uris || [],
    jwks: doc.jwks,
    jwksUri: cimdJwksUri(doc.jwks_uri, url),
    // A CIMD client has no shared secret by construction; it is public unless
    // it published keys, in which case it can prove possession of one.
    tokenEndpointAuthMethod: doc.jwks || doc.jwks_uri ? 'private_key_jwt' : 'none',
    scopes: typeof doc.scope === 'string' ? doc.scope.split(/\s+/).filter(Boolean) : undefined,
    idTokenSignedResponseAlg: doc.id_token_signed_response_alg,
    logoUri: doc.logo_uri,
    policyUri: doc.policy_uri,
    tosUri: doc.tos_uri,
    requirePkce: true,
  });
  rememberCimd(clientId, client, cimd.cacheTtlSeconds);
  return client;
}

export function clearCimdCache() {
  cimdCache.clear();
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/**
 * Find the relying party with this client id.
 *
 * @param {object} config
 * @param {string} clientId
 * @param {object} [deps] { store } - a client store, when one is configured
 * @returns {Promise<object|undefined>}
 */
export async function resolveClient(config, clientId, deps = {}) {
  if (!clientId) return undefined;

  // A statically configured client is explicit operator intent, so it is never
  // gated by the opaque or CIMD switches.
  const stat = config.clients.static.find((c) => c.clientId === clientId);
  if (stat) return normalise(stat);

  // Every store-held client is an opaque one by construction: the store is
  // keyed by bare identifier, and a key containing a scheme and slashes is
  // refused outright, so a URL client id can never name a store record. An
  // operator who turns opaque clients off is therefore saying every relying
  // party must be either statically configured or self-describing.
  if (deps.store && config.clients.opaque.enabled) {
    const record = await deps.store.get(clientId);
    if (record) return normalise({ source: 'store', clientId, ...record });
  }

  if (clientId.startsWith('https://') || clientId.startsWith('http://')) {
    return resolveCimd(config, clientId, deps);
  }
  return undefined;
}

/**
 * Which of this deployment's routes a client may use, for discovery output.
 *
 * The authentication methods are the interesting part. When clients can only
 * ever come from the environment, the answer is exactly what those clients use,
 * so a deployment with one confidential relying party does not advertise
 * `none` and invite a public client that would be refused. As soon as a store
 * or a metadata document can introduce a client we have not seen, every method
 * the code supports is back on the list, because any of them might turn up.
 */
export function clientCapabilities(config) {
  const ALL = ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'];
  const dynamic = config.clients.cimd.enabled || config.clients.store.backend !== 'none';
  let authMethods = ALL;
  if (!dynamic) {
    const used = new Set(config.clients.static.map((c) => c.tokenEndpointAuthMethod || 'none'));
    // A statically configured client with a JWKS can authenticate that way
    // whatever its declared method says, because that is what the JWKS is for.
    if (config.clients.static.some((c) => c.jwks || c.jwksUri)) used.add('private_key_jwt');
    authMethods = ALL.filter((m) => used.has(m));
    // Never an empty list, which some client libraries reject outright. It
    // happens when a deployment has no clients at all and no way to acquire
    // one, and then the honest answer is what the code can do rather than
    // nothing: there is no client for the narrower answer to be about.
    if (authMethods.length === 0) authMethods = ALL;
  }
  return {
    static: config.clients.static.length,
    cimd: config.clients.cimd.enabled,
    opaque: config.clients.opaque.enabled,
    store: config.clients.store.backend,
    dynamic,
    authMethods,
  };
}

export { isConfidential, normalise as normaliseClient };
