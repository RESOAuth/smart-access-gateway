// Issuing tokens.
//
// The id_token is the product; the access token exists only so that /userinfo
// has something to check, and is sealed rather than signed because nothing
// outside SAG ever needs to verify it. That keeps the asymmetric signing path -
// the one that has to be migrated for post-quantum - down to a single use.

import { signCompact } from '../crypto/jose.js';
import { signerKid } from '../keys/index.js';
import { seal, unseal, sha256 } from '../crypto/secrets.js';
import { b64u, nowSeconds, randomToken } from '../util/bytes.js';
import { OAuthError } from '../util/errors.js';
import { outboundClaims } from '../profile.js';

const ACCESS_PURPOSE = 'access';

/**
 * Build the id_token claims for a redeemed code.
 *
 * `at_hash` is included because OIDC requires it whenever an access token is
 * issued alongside, and it lets a relying party confirm the two arrived
 * together.
 */
export async function idTokenClaims(config, { grant, audience, accessToken, nonce }) {
  const now = nowSeconds();
  const claims = {
    iss: config.issuer,
    sub: grant.sub,
    aud: audience,
    iat: now,
    exp: now + config.tokens.idTokenTtlSeconds,
    auth_time: grant.auth_time,
    acr: grant.acr,
    amr: grant.amr,
    sid: grant.sid,
  };
  if (nonce !== undefined) claims.nonce = nonce;
  if (grant.scope?.includes('email')) {
    claims.email = grant.email;
    // SAG only ever asserts an address it has proved control of: either an
    // upstream said so, or a code was delivered to it.
    claims.email_verified = true;
  }
  if (grant.scope?.includes('profile') && grant.claims) {
    Object.assign(claims, outboundClaims(config, grant.claims));
  }
  if (accessToken) claims.at_hash = await leftHalfHash(accessToken);
  return claims;
}

/** OIDC left-most-half hash, used for at_hash and c_hash. */
export async function leftHalfHash(value) {
  const digest = await sha256(value);
  return b64u(digest.subarray(0, digest.length / 2));
}

/**
 * Sign an id_token.
 *
 * The algorithm can be chosen per request so that a relying party ready for
 * ML-DSA can ask for it while everybody else stays on ES256, which is how the
 * post-quantum migration happens without a flag day.
 */
export async function signIdToken(config, signerSet, claims, requestedAlg) {
  let signer;
  try {
    signer = signerSet.select(requestedAlg);
  } catch (err) {
    throw new OAuthError('invalid_request', err.message);
  }
  const kid = await signerKid(signer);
  const header = { typ: 'JWT', kid };
  return signCompact(signer.alg, (bytes) => signer.sign(bytes), header, claims);
}

/**
 * Mint an access token for /userinfo.
 *
 * Opaque to everybody but SAG, self-contained, and short lived. No refresh
 * token is issued: revoking one would need state, and a relying party that
 * wants a longer session can re-run the flow, which SAG can answer silently
 * from its session cookie.
 */
export async function issueAccessToken(config, grant) {
  const now = nowSeconds();
  return seal(config.secrets[0], ACCESS_PURPOSE, {
    v: 1,
    jti: randomToken(12),
    sub: grant.sub,
    client_id: grant.client_id,
    scope: grant.scope,
    email: grant.email,
    acr: grant.acr,
    amr: grant.amr,
    auth_time: grant.auth_time,
    sid: grant.sid,
    claims: grant.claims,
    iat: now,
    exp: now + config.tokens.accessTokenTtlSeconds,
  });
}

export async function readAccessToken(config, token) {
  try {
    return await unseal(config.secrets, ACCESS_PURPOSE, token);
  } catch {
    return undefined;
  }
}

/** The /token response body for an authorisation code grant. */
export function tokenResponse({ accessToken, idToken, expiresIn, scope }) {
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    id_token: idToken,
    scope: scope.join(' '),
  };
}
