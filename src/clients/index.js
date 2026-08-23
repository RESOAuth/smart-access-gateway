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
// carries the most restrictions: an allow list of domains, a size cap, and a
// requirement that every redirect URI sits under the document's own origin.

import { OAuthError } from '../util/errors.js';
import { fetchWithTimeout } from '../util/http.js';
import { nowSeconds } from '../util/bytes.js';

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
export function redirectUriAllowed(client, candidate) {
  let want;
  try {
    want = new URL(candidate);
  } catch {
    return false;
  }
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

export function postLogoutRedirectAllowed(client, candidate) {
  if (!client?.postLogoutRedirectUris?.length) return false;
  return redirectUriAllowed({ redirectUris: client.postLogoutRedirectUris }, candidate);
}

// ---------------------------------------------------------------------------
// CIMD
// ---------------------------------------------------------------------------

const cimdCache = new Map();

function cimdDomainAllowed(cimd, url) {
  if (!cimd.allowedDomains.length) return true;
  const host = url.hostname.toLowerCase();
  return cimd.allowedDomains.some((entry) => {
    const d = entry.toLowerCase().replace(/^\*?\./, '');
    if (host === d) return true;
    return cimd.allowSubdomains && host.endsWith('.' + d);
  });
}

/**
 * Fetch a Client ID Metadata Document.
 *
 * The document's URL *is* the client id, so it authenticates itself: only
 * somebody controlling that origin can change what the client claims to be.
 * Redirects are refused for the same reason - following one would let the
 * origin in the client id hand off to another.
 */
async function resolveCimd(config, clientId) {
  const cimd = config.clients.cimd;
  if (!cimd.enabled) return undefined;
  let url;
  try {
    url = new URL(clientId);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' && !(config.devMode && url.protocol === 'http:')) return undefined;
  if (url.hash) throw new OAuthError('invalid_client', 'A client ID metadata document URL must not have a fragment');
  if (!cimdDomainAllowed(cimd, url)) {
    throw new OAuthError('invalid_client', 'This deployment does not accept client metadata from ' + url.hostname);
  }

  const cached = cimdCache.get(clientId);
  if (cached && cached.expiresAt > nowSeconds()) return cached.client;

  const res = await fetchWithTimeout(clientId, { headers: { accept: 'application/json' } }, 5000);
  if (!res.ok) throw new OAuthError('invalid_client', 'Could not read client metadata (HTTP ' + res.status + ')');
  const body = await res.text();
  if (body.length > cimd.maxDocumentBytes) {
    throw new OAuthError('invalid_client', 'Client metadata document is larger than this deployment accepts');
  }
  let doc;
  try {
    doc = JSON.parse(body);
  } catch {
    throw new OAuthError('invalid_client', 'Client metadata document is not valid JSON');
  }
  if (doc.client_id !== clientId) {
    throw new OAuthError('invalid_client', 'Client metadata document does not claim its own URL as client_id');
  }
  const redirectUris = Array.isArray(doc.redirect_uris) ? doc.redirect_uris : [];
  // Every redirect URI must sit under the same origin as the document, so
  // publishing a document can never redirect codes somewhere else.
  for (const uri of redirectUris) {
    let u;
    try {
      u = new URL(uri);
    } catch {
      throw new OAuthError('invalid_client', 'Client metadata contains a malformed redirect URI');
    }
    if (u.origin !== url.origin) {
      throw new OAuthError('invalid_client', 'Client metadata redirect URIs must share the document origin');
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
    postLogoutRedirectUris: (doc.post_logout_redirect_uris || []).filter(
      (u) => tryOrigin(u) === url.origin,
    ),
    jwks: doc.jwks,
    jwksUri: doc.jwks_uri,
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
  if (cimd.cacheTtlSeconds > 0) {
    cimdCache.set(clientId, { client, expiresAt: nowSeconds() + cimd.cacheTtlSeconds });
  }
  return client;
}

function tryOrigin(u) {
  try {
    return new URL(u).origin;
  } catch {
    return undefined;
  }
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
    return resolveCimd(config, clientId);
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
