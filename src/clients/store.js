// Client records held outside the environment.
//
// An enterprise with many relying parties does not want a redeploy to add one,
// so records can live in Cloudflare KV or an S3 bucket as JSON keyed by client
// id. Both backends are read-only from SAG's point of view: whatever manages
// the records is somebody else's problem, which keeps the identity path free
// of write credentials.

import { fetchWithTimeout, readJsonLimited } from '../util/http.js';
import { signRequest, credentialsFromEnv } from '../crypto/sigv4.js';
import { nowSeconds } from '../util/bytes.js';

/** Client ids appear in a key path, so they must not be able to escape it. */
function safeKey(clientId) {
  if (!/^[A-Za-z0-9._~:-]{1,128}$/.test(clientId)) return undefined;
  return clientId;
}

/** Translate a stored JSON record into the shape resolveClient expects. */
function fromRecord(clientId, doc) {
  if (!doc || typeof doc !== 'object') return undefined;
  const redirectUris = doc.redirect_uris || doc.redirectUris || [];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) return undefined;
  const sessionScope = doc.session_scope || doc.sessionScope;
  if (sessionScope !== undefined && sessionScope !== 'shared' && sessionScope !== 'rp') return undefined;
  return {
    clientId,
    clientName: doc.client_name || doc.clientName,
    // A stored secret is always a digest: "sha256:<hex>". Storing the secret
    // itself would mean a bucket read is enough to impersonate a client.
    clientSecretDigest: doc.client_secret_digest || doc.clientSecretDigest,
    redirectUris,
    postLogoutRedirectUris: doc.post_logout_redirect_uris || doc.postLogoutRedirectUris || [],
    jwks: doc.jwks,
    jwksUri: doc.jwks_uri || doc.jwksUri,
    tokenEndpointAuthMethod:
      doc.token_endpoint_auth_method ||
      doc.tokenEndpointAuthMethod ||
      (doc.client_secret_digest || doc.clientSecretDigest ? 'client_secret_basic' : doc.jwks || doc.jwks_uri ? 'private_key_jwt' : 'none'),
    scopes: typeof doc.scope === 'string' ? doc.scope.split(/\s+/).filter(Boolean) : doc.scopes,
    acrValues: doc.acr_values || doc.acrValues || [],
    idTokenSignedResponseAlg: doc.id_token_signed_response_alg || doc.idTokenSignedResponseAlg,
    sessionScope,
    subjectType: doc.subject_type || doc.subjectType,
    sectorIdentifier: doc.sector_identifier || doc.sectorIdentifier,
    // Tri-state: absent means the instance default, which is not the same
    // answer as false.
    sanitisePlusEmails: doc.sanitise_plus_emails ?? doc.sanitisePlusEmails,
    requirePkce: doc.require_pkce ?? doc.requirePkce ?? true,
    logoUri: doc.logo_uri || doc.logoUri,
    // Shown on the sign-in pages, in place of the instance-wide links.
    tosUri: doc.tos_uri || doc.tosUri,
    policyUri: doc.policy_uri || doc.policyUri,
    logoutConfirm: doc.logout_confirm || doc.logoutConfirm,
  };
}

// A miss is cached for much less time than a hit.
//
// Both need caching: without it, a flood of invented client ids would be a
// store lookup each. But the two are not equally expensive to get wrong. A
// stale hit means a record edited a minute ago has not taken effect yet. A
// stale miss means a relying party that exists is being told it does not -
// which is what an operator sees for a whole minute after adding a record, and
// what an instance sees if its very first lookup lands while the store is still
// being populated. Ten seconds is still ample protection against a flood.
const MISS_TTL_SECONDS = 10;
const MAX_S3_RECORD_BYTES = 64 * 1024;

// A cap, because the keys are attacker-chosen: every /authorize with an
// invented client_id is a negative entry, and an unbounded map would make a
// loop of them a way to exhaust a Worker isolate's memory.
const MAX_CACHED = 500;

/**
 * Make room for one entry.
 *
 * Expired entries go first, because they are free to lose - and a flood of
 * invented client ids is entirely expired entries within ten seconds, so in the
 * case this cap exists for nothing live is evicted at all. Only if everything
 * is still live does the oldest go, which Map's insertion order gives us.
 */
function evict(entries) {
  const now = nowSeconds();
  let freed = false;
  for (const [key, entry] of entries) {
    if (entry.expiresAt <= now) {
      entries.delete(key);
      freed = true;
    }
  }
  if (freed) return;
  const oldest = entries.keys().next().value;
  if (oldest !== undefined) entries.delete(oldest);
}

/** A short-lived, bounded read-through cache, including negative results. */
function withCache(loader, ttlSeconds) {
  const entries = new Map();
  return async (clientId) => {
    if (ttlSeconds <= 0) return loader(clientId);
    const hit = entries.get(clientId);
    if (hit && hit.expiresAt > nowSeconds()) return hit.value;
    const value = await loader(clientId);
    const ttl = value === undefined ? Math.min(ttlSeconds, MISS_TTL_SECONDS) : ttlSeconds;
    // Delete before setting, so a refreshed entry moves to the back of the
    // insertion order rather than staying wherever it first landed. Without
    // that, a busy legitimate client whose entry happened to be inserted early
    // stays the eviction candidate for ever and goes to the store every time.
    entries.delete(clientId);
    if (entries.size >= MAX_CACHED) evict(entries);
    entries.set(clientId, { value, expiresAt: nowSeconds() + ttl });
    return value;
  };
}

/**
 * A store that arrives as a binding: a Cloudflare KV namespace, or the
 * directory-backed one the Node adapter builds. Both answer get(key) with the
 * parsed record, so neither needs a special case here.
 */
function createBoundStore(config, env) {
  const { backend, kvBindingName } = config.clients.store;
  // eslint-disable-next-line security/detect-object-injection -- binding name is configured by operator
  const binding = env?.[kvBindingName];
  if (!binding || typeof binding.get !== 'function') {
    throw new Error(
      backend === 'file'
        ? 'CLIENTS_STORE_BACKEND is file, which only the Node adapter can provide. Nothing is bound as ' + kvBindingName + '.'
        : 'CLIENTS_STORE_BACKEND is cf-kv but no KV namespace is bound as ' + kvBindingName,
    );
  }
  const prefix = config.clients.store.prefix;
  return async (clientId) => {
    const key = safeKey(clientId);
    if (!key) return undefined;
    const doc = await binding.get(prefix + key + '.json', { type: 'json' });
    return fromRecord(clientId, doc);
  };
}

function createS3Store(config, env) {
  const { s3Bucket, s3Region, prefix, s3Endpoint } = config.clients.store;
  if (!s3Bucket) throw new Error('CLIENTS_STORE_BACKEND is s3 but CLIENTS_STORE_S3_BUCKET is not set');
  if (!s3Region) throw new Error('CLIENTS_STORE_BACKEND is s3 but no region is set');
  const credentials = credentialsFromEnv(env ?? {});
  // Anything that is not S3 itself gets path style addressing, because a
  // bucket cannot be a subdomain of a hostname that is not S3's. The region
  // still matters: it is part of the signature's scope either way.
  const objectUrl = (key) =>
    s3Endpoint
      ? `${s3Endpoint}/${s3Bucket}/${prefix}${key}.json`
      : `https://${s3Bucket}.s3.${s3Region}.amazonaws.com/${prefix}${key}.json`;
  return async (clientId) => {
    const key = safeKey(clientId);
    if (!key) return undefined;
    const url = objectUrl(key);
    const headers = await signRequest({
      method: 'GET',
      url,
      service: 's3',
      region: s3Region,
      credentials,
    });
    const res = await fetchWithTimeout(url, { method: 'GET', headers }, 4000);
    if (res.status === 404 || res.status === 403) return undefined;
    if (!res.ok) throw new Error('client store read failed with HTTP ' + res.status);
    return fromRecord(clientId, await readJsonLimited(res, MAX_S3_RECORD_BYTES));
  };
}

/**
 * @returns {Promise<{get(clientId): Promise<object|undefined>}|undefined>}
 */
export async function createClientStore(config, env) {
  const backend = config.clients.store.backend;
  if (backend === 'none') return undefined;
  const loader = backend === 's3' ? createS3Store(config, env) : createBoundStore(config, env);
  const cached = withCache(loader, config.clients.store.cacheTtlSeconds);
  return {
    backend,
    get: async (clientId) => {
      try {
        return await cached(clientId);
      } catch {
        // A store that is down must not be reported as "no such client", but
        // it must also not take the whole endpoint out for statically
        // configured clients, so the caller sees undefined and the failure is
        // surfaced by the health endpoint instead.
        return undefined;
      }
    },
  };
}
