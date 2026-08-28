// Authenticating a relying party at the token endpoint.

import { invalidClient } from '../util/errors.js';
import { unb64, fromUtf8, nowSeconds } from '../util/bytes.js';
import { sha256b64u, verifyDigest } from '../crypto/secrets.js';
import { decodeJwt, verifyCompact, fetchJwks, selectJwk, validateClaims } from '../crypto/jose.js';
import { single } from '../util/http.js';

const PRIVATE_KEY_JWT_ALGS = ['ES256', 'ES384', 'RS256', 'PS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

/**
 * Read the client id and any credential from a token endpoint request.
 *
 * A request must not present more than one credential: two credentials means
 * an ambiguity about which one was actually checked, and RFC 6749 forbids it.
 */
export function readCredentials(request, params) {
  const authorization = request.headers.get('authorization');
  const out = { clientId: single(params, 'client_id'), method: 'none' };

  let presented = 0;
  if (authorization && /^basic /i.test(authorization)) {
    presented++;
    let decoded;
    try {
      decoded = fromUtf8(unb64(authorization.slice(6).trim()));
    } catch {
      throw invalidClient('The Authorization header is not valid HTTP Basic.');
    }
    const colon = decoded.indexOf(':');
    if (colon < 1) throw invalidClient('The Authorization header is not valid HTTP Basic.');
    // RFC 6749 section 2.3.1 requires both halves to be form-urlencoded.
    out.basicId = safeDecode(decoded.slice(0, colon));
    out.secret = safeDecode(decoded.slice(colon + 1));
    out.method = 'client_secret_basic';
    if (out.clientId && out.clientId !== out.basicId) {
      throw invalidClient('The client_id in the body does not match the Authorization header.');
    }
    out.clientId = out.basicId;
  }

  const bodySecret = single(params, 'client_secret');
  if (bodySecret !== undefined) {
    presented++;
    out.secret = bodySecret;
    out.method = 'client_secret_post';
  }

  const assertion = single(params, 'client_assertion');
  if (assertion !== undefined) {
    presented++;
    const type = single(params, 'client_assertion_type');
    if (type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
      throw invalidClient('Unsupported client_assertion_type.');
    }
    out.assertion = assertion;
    out.method = 'private_key_jwt';
  }

  if (presented > 1) throw invalidClient('Present exactly one client credential, not several.');
  return out;
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Verify the credential a client presented against its registration.
 *
 * @param {object} config
 * @param {object} client
 * @param {object} credentials  From readCredentials
 */
export async function authenticateClient(config, client, credentials, replayStore) {
  const registered = client.tokenEndpointAuthMethod || 'none';

  if (registered === 'none') {
    // A public client proves nothing here; PKCE is what protects its code.
    if (credentials.method !== 'none') {
      throw invalidClient('This client is registered as public and must not present a credential.');
    }
    return { method: 'none' };
  }

  if (registered === 'client_secret_basic' || registered === 'client_secret_post') {
    if (credentials.method !== registered) {
      throw invalidClient('This client must authenticate with ' + registered + '.');
    }
    const stored = client.clientSecretDigest || client.clientSecret;
    if (!stored) throw invalidClient('This client has no secret configured.');
    // A stored value may be a digest ("sha256:...") or, for a static client in
    // an environment variable, the secret itself.
    const ok = await verifyDigest(
      client.clientSecretDigest ? client.clientSecretDigest : 'plain:' + client.clientSecret,
      credentials.secret || '',
    );
    if (!ok) throw invalidClient('Client authentication failed.');
    return { method: credentials.method };
  }

  if (registered === 'private_key_jwt') {
    if (credentials.method !== 'private_key_jwt') {
      throw invalidClient('This client must authenticate with a private_key_jwt assertion.');
    }
    await verifyPrivateKeyJwt(config, client, credentials.assertion, replayStore);
    return { method: 'private_key_jwt' };
  }

  throw invalidClient('Unsupported client authentication method: ' + registered);
}

/**
 * Check a private_key_jwt client assertion.
 *
 * The audience must be this issuer, so an assertion minted for another
 * identity provider cannot be forwarded here, and `jti` plus a short lifetime
 * bound how long a captured assertion stays useful. A configured state store
 * also makes the assertion single-use.
 */
export async function verifyPrivateKeyJwt(config, client, assertion, replayStore) {
  let header;
  try {
    ({ header } = decodeJwt(assertion));
  } catch {
    throw invalidClient('The client assertion is not a valid JWT.');
  }
  if (!PRIVATE_KEY_JWT_ALGS.includes(header.alg)) {
    throw invalidClient('Unsupported client assertion algorithm: ' + header.alg + '.');
  }

  let jwks = client.jwks;
  if (!jwks && client.jwksUri) {
    try {
      jwks = await fetchJwks(client.jwksUri, { allowHttp: config.devMode });
    } catch (err) {
      throw invalidClient('Could not read the client JWKS: ' + err.message);
    }
  }
  if (!jwks) throw invalidClient('This client has no keys registered.');

  let jwk;
  try {
    jwk = selectJwk(jwks, header);
  } catch {
    throw invalidClient('No registered key matches the client assertion.');
  }

  let payload;
  try {
    payload = await verifyCompact(assertion, jwk, { algs: PRIVATE_KEY_JWT_ALGS });
  } catch {
    throw invalidClient('The client assertion signature could not be verified.');
  }

  try {
    validateClaims(payload, {
      issuer: client.clientId,
      audience: config.issuer,
      clockSkew: config.tokens.clockSkewSeconds,
    });
  } catch (err) {
    throw invalidClient('The client assertion is not acceptable: ' + err.message);
  }
  if (payload.sub !== client.clientId) throw invalidClient('The client assertion subject must be the client id.');
  if (typeof payload.jti !== 'string' || !payload.jti) {
    throw invalidClient('The client assertion must carry a string jti.');
  }
  if (!Number.isFinite(payload.iat)) throw invalidClient('The client assertion must carry an iat.');
  const lifetime = payload.exp - payload.iat;
  if (lifetime < 0 || lifetime > 300) {
    throw invalidClient('The client assertion lifetime must be between zero and 300 seconds.');
  }

  if (replayStore) {
    // Hash the client-controlled values before they become a store key. The
    // prefix also keeps assertion identifiers separate from code identifiers.
    const tag = await sha256b64u(client.clientId + '\0' + payload.jti);
    const ttl = payload.exp - nowSeconds() + config.tokens.clockSkewSeconds;
    const fresh = await replayStore.claim('client-assertion:' + tag, ttl);
    if (!fresh) throw invalidClient('The client assertion has already been used.');
  }
  return payload;
}

/**
 * A token endpoint request must name a client one way or another.
 * For a public client that is the `client_id` parameter.
 */
export function requireClientId(credentials) {
  if (!credentials.clientId) throw invalidClient('No client_id was presented.');
  return credentials.clientId;
}

export { PRIVATE_KEY_JWT_ALGS };
