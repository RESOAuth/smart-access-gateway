// Talking to an upstream identity provider.
//
// SAG is a proxy, so this is the other half of the flow: it is a relying party
// here, and it applies to itself every check it expects its own relying
// parties to apply. PKCE on the outbound request, a nonce bound to the
// transaction, exact issuer and audience validation on the returned id_token.
//
// The round trip is stateless. Everything that has to survive it - the
// original authorisation request, the nonce, the PKCE verifier - is sealed into
// the `state` parameter, which is what the brief means by relaying user
// information through OAuth state. Nothing is written down on our side.

import { fetchWithTimeout, readJsonLimited } from '../util/http.js';
import { randomToken, nowSeconds } from '../util/bytes.js';
import { sha256b64u } from '../crypto/secrets.js';
import { fetchJwks, selectJwk, verifyCompact, decodeJwt, validateClaims } from '../crypto/jose.js';
import { domainOf, normaliseEmail } from '../identity.js';
import { providerFor, labelFor } from './providers.js';

const metadataCache = new Map();
const MAX_METADATA_CACHE_ENTRIES = 100;
const MAX_DISCOVERY_BYTES = 64 * 1024;
const MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;

function checkedRemoteUrl(value, label, allowHttp) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(label + ' is not an absolute URL');
  }
  if (url.username || url.password || (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:'))) {
    throw new Error(label + ' must use https');
  }
  return url.href;
}

function checkMetadata(upstream, metadata, allowHttp) {
  checkedRemoteUrl(metadata.issuer, 'upstream ' + upstream.id + ' issuer', allowHttp);
  for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    // eslint-disable-next-line security/detect-object-injection -- field is from fixed metadata field list
    metadata[field] = checkedRemoteUrl(metadata[field], 'upstream ' + upstream.id + ' ' + field, allowHttp);
  }
  return metadata;
}

function rememberMetadata(url, metadata, ttlSeconds) {
  const now = nowSeconds();
  for (const [key, entry] of metadataCache) {
    if (entry.expiresAt <= now) metadataCache.delete(key);
  }
  metadataCache.delete(url);
  if (metadataCache.size >= MAX_METADATA_CACHE_ENTRIES) {
    const oldest = metadataCache.keys().next().value;
    if (oldest !== undefined) metadataCache.delete(oldest);
  }
  metadataCache.set(url, { metadata, expiresAt: now + ttlSeconds });
}

/**
 * Fetch and cache an upstream's OpenID Connect metadata.
 *
 * Discovery is preferred over hand-configured endpoints because it also
 * supplies the issuer and the JWKS URI, and getting either of those wrong is
 * the difference between validating an id_token and pretending to.
 */
export async function upstreamMetadata(upstream, { ttlSeconds = 3600, allowHttp = false } = {}) {
  const provider = providerFor(upstream.provider);
  const explicit =
    upstream.authorizationEndpoint && upstream.tokenEndpoint && upstream.jwksUri && upstream.issuer;
  if (explicit && upstream.useDiscovery !== true) {
    return checkMetadata(upstream, {
      issuer: upstream.issuer,
      authorization_endpoint: upstream.authorizationEndpoint,
      token_endpoint: upstream.tokenEndpoint,
      jwks_uri: upstream.jwksUri,
    }, allowHttp);
  }

  const discoveredAt = provider.discoveryUrl(upstream);
  if (!discoveredAt) {
    throw new Error(
      'upstream ' + upstream.id + ' needs either an ISSUER to discover from or all of its endpoints set explicitly',
    );
  }
  const url = checkedRemoteUrl(discoveredAt, 'upstream ' + upstream.id + ' discovery URL', allowHttp);
  const cached = metadataCache.get(url);
  if (cached && cached.expiresAt > nowSeconds()) return cached.metadata;

  const res = await fetchWithTimeout(url, { headers: { accept: 'application/json' } }, 5000);
  if (!res.ok) throw new Error('upstream discovery for ' + upstream.id + ' failed with HTTP ' + res.status);
  const metadata = await readJsonLimited(res, MAX_DISCOVERY_BYTES);
  for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer']) {
    // eslint-disable-next-line security/detect-object-injection -- field is from fixed metadata field list
    if (!metadata[field]) throw new Error('upstream ' + upstream.id + ' discovery document has no ' + field);
  }
  // Explicit configuration still wins over a discovered value, so an operator
  // can point at a proxy or a regional endpoint.
  const merged = checkMetadata(upstream, {
    ...metadata,
    issuer: upstream.issuer || metadata.issuer,
    authorization_endpoint: upstream.authorizationEndpoint || metadata.authorization_endpoint,
    token_endpoint: upstream.tokenEndpoint || metadata.token_endpoint,
    jwks_uri: upstream.jwksUri || metadata.jwks_uri,
  }, allowHttp);
  rememberMetadata(url, merged, ttlSeconds);
  return merged;
}

export function clearUpstreamMetadataCache() {
  metadataCache.clear();
}

/**
 * Which upstreams could authenticate this address?
 *
 * The order is the routing rule from the brief: an upstream configured for the
 * exact domain, then one configured for a parent domain, then any `common`
 * upstream, and email OTP behind all of them. Returning a list rather than one
 * choice is what lets the chooser screen appear when a domain genuinely has
 * two routes.
 */
export function upstreamsFor(config, email) {
  const domain = domainOf(email);
  if (!domain) return [];
  const exact = [];
  const parent = [];
  const common = [];
  for (const u of config.upstreams) {
    if (u.isCommon) common.push(u);
    else if (u.domain === domain) exact.push(u);
    else if (domain.endsWith('.' + u.domain)) parent.push(u);
  }
  // A domain-specific match suppresses the common ones: an organisation that
  // has configured its own tenant does not want its people offered the
  // multi-tenant endpoint as well.
  if (exact.length) return exact;
  if (parent.length) return parent;
  return common;
}

/**
 * Start an upstream authorisation request.
 *
 * @returns {Promise<{url: string, state: string}>}
 */
export async function beginUpstream(ctx, upstream, tx, { hinted = false } = {}) {
  const { config } = ctx;
  const metadata = await upstreamMetadata(upstream, { allowHttp: config.devMode });
  const provider = providerFor(upstream.provider);

  const verifier = randomToken(32);
  const nonce = randomToken(16);
  const challenge = await sha256b64u(verifier);

  // The state carries the whole transaction, so the callback needs nothing but
  // what the browser brings back with it.
  const stateTx = {
    ...tx,
    upstream: {
      id: upstream.id,
      verifier,
      nonce,
      redirectUri: ctx.absolute('/callback'),
      startedAt: nowSeconds(),
      // Whether SAG chose this provider from the domain's mail records rather
      // than being told. It changes what an `access_denied` on the way back
      // means: see handleCallback.
      hinted: hinted || undefined,
    },
  };
  const { sealUpstreamState } = await import('../oauth/transaction.js');
  const state = await sealUpstreamState(config, stateTx);

  const url = new URL(metadata.authorization_endpoint);
  const params = url.searchParams;
  params.set('response_type', 'code');
  params.set('client_id', upstream.clientId);
  params.set('redirect_uri', stateTx.upstream.redirectUri);
  params.set('scope', (upstream.scopes || provider.scopes).join(' '));
  params.set('state', state);
  params.set('nonce', nonce);
  params.set('code_challenge', challenge);
  params.set('code_challenge_method', 'S256');
  params.set('response_mode', 'query');

  // Relay what the relying party asked for, so a demand for a stronger
  // authentication is satisfied upstream rather than silently downgraded.
  if (tx.max_age !== undefined) params.set('max_age', String(tx.max_age));
  if (upstream.acrValues?.length) params.set('acr_values', upstream.acrValues.join(' '));
  const prompt = upstreamPrompt(upstream, tx);
  if (prompt) params.set('prompt', prompt);
  if (tx.email) params.set('login_hint', tx.email);
  for (const [k, v] of Object.entries(provider.extraAuthorizationParams(upstream))) {
    if (v !== undefined) params.set(k, v);
  }

  return { url: url.toString(), state, stateTx };
}

function upstreamPrompt(upstream, tx) {
  if (upstream.prompt) return upstream.prompt;
  // prompt=none must propagate: if we cannot answer silently, neither should
  // the upstream be allowed to show a screen.
  if (tx.prompt?.includes('none')) return 'none';
  if (tx.prompt?.includes('login')) return 'login';
  if (tx.prompt?.includes('select_account')) return 'select_account';
  return undefined;
}

/**
 * Exchange the upstream code and validate the id_token it returns.
 *
 * @returns {Promise<{email: string, claims: object, upstream: object}>}
 */
export async function completeUpstream(ctx, upstream, { code, stateTx }) {
  const { config } = ctx;
  const metadata = await upstreamMetadata(upstream, { allowHttp: config.devMode });
  const provider = providerFor(upstream.provider);

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: stateTx.upstream.redirectUri,
    client_id: upstream.clientId,
    code_verifier: stateTx.upstream.verifier,
  });
  const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  // A public upstream client is possible (PKCE only), so the secret is
  // optional; when there is one it goes in the body rather than Basic, because
  // both Microsoft and Google accept that and it avoids encoding surprises.
  if (upstream.clientSecret) body.set('client_secret', upstream.clientSecret);

  const res = await fetchWithTimeout(
    metadata.token_endpoint,
    { method: 'POST', headers, body: body.toString() },
    8000,
  );
  const payload = await readJsonLimited(res, MAX_TOKEN_RESPONSE_BYTES).catch(() => ({}));
  if (!res.ok) {
    const detail = payload.error_description || payload.error || 'HTTP ' + res.status;
    throw new Error('upstream token exchange failed: ' + detail);
  }
  if (!payload.id_token) throw new Error('upstream returned no id_token');

  const claims = await verifyUpstreamIdToken(upstream, metadata, payload.id_token, {
    nonce: stateTx.upstream.nonce,
    clockSkew: config.tokens.clockSkewSeconds,
    maxAge: stateTx.max_age,
    allowHttp: config.devMode,
  });
  provider.verifyClaims(upstream, claims);

  // `preferred_username` and `upn` are login identifiers, not assertions that
  // the mailbox exists and belongs to this account. On a domain-specific
  // upstream that distinction is academic, because the domain check below
  // bounds whatever comes back to the organisation the upstream was
  // configured for. On a `common` upstream nothing bounds it, so only a claim
  // the provider offers as the address is accepted. See ADR 0019.
  const email = normaliseEmail(
    upstream.isCommon ? claims.email : claims.email || claims.preferred_username || claims.upn,
  );
  if (!email) {
    throw new Error('the upstream did not return an email address for this account');
  }
  // An upstream that will not vouch for the address is not evidence of
  // anything, so it is rejected rather than trusted with a caveat.
  if (claims.email_verified === false) {
    throw new Error('the upstream reports this email address as unverified');
  }
  // A domain-specific upstream must not be able to assert an address outside
  // the domain it was configured for. A common upstream has no domain of its
  // own; what bounds it is in the provider's verifyClaims. See ADR 0019.
  if (!upstream.isCommon) {
    const domain = domainOf(email);
    if (domain !== upstream.domain && !domain.endsWith('.' + upstream.domain)) {
      throw new Error('the upstream returned an address outside the domain it is configured for');
    }
  }

  return { email, claims, upstream };
}

async function verifyUpstreamIdToken(upstream, metadata, token, { nonce, clockSkew, maxAge, allowHttp }) {
  const { header } = decodeJwt(token);
  const jwks = await fetchJwks(metadata.jwks_uri, { allowHttp });
  const jwk = selectJwk(jwks, header);
  const claims = await verifyCompact(token, jwk, {
    algs: ['ES256', 'ES384', 'RS256', 'PS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
  });

  const provider = providerFor(upstream.provider);
  // Microsoft's `common` issuer is a template containing {tenantid}, so the
  // comparison is against the resolved form for this token's tenant.
  const expectedIssuer = provider.issuerTemplate
    ? String(metadata.issuer).replace('{tenantid}', String(claims.tid || ''))
    : metadata.issuer;

  validateClaims(claims, {
    issuer: expectedIssuer,
    audience: upstream.clientId,
    nonce,
    clockSkew,
    maxAge,
  });
  return claims;
}

export { labelFor };

/** Everything about an upstream that is safe to show or log. */
export function describeUpstream(upstream) {
  return {
    id: upstream.id,
    provider: upstream.provider,
    domain: upstream.domain,
    label: labelFor(upstream),
  };
}
