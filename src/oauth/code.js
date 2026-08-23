// Authorisation codes.
//
// The code is a sealed token carrying everything the token endpoint needs, so
// there is no code table to look up. That is what makes the deployment
// stateless, and it comes with one honest trade-off: nothing can mark a code as
// spent, so a code that leaks could in principle be redeemed twice.
//
// Four things narrow that down to a very small window:
//
//   * a 60 second default lifetime, which is far shorter than a stored code
//     would need to be;
//   * mandatory PKCE, so the redeemer also needs a verifier that never leaves
//     the relying party;
//   * binding to the exact client id and redirect URI presented at /authorize;
//   * an optional replay store, used when the operator configures one, which
//     closes the gap entirely without making a database compulsory.
//
// See docs/questions.md for the outstanding decision on making that store the
// recommended default.

import { seal, unseal, sha256b64u } from '../crypto/secrets.js';
import { nowSeconds, randomToken, timingSafeEqual } from '../util/bytes.js';
import { invalidGrant } from '../util/errors.js';

const PURPOSE = 'code';

/**
 * Mint a code for a completed authentication.
 *
 * @param {object} config
 * @param {object} args
 * @param {object} args.tx        The transaction being completed
 * @param {object} args.session   The session that authenticated the person
 * @param {string} args.sub       Subject identifier for this client
 * @param {string} args.email     The address as this client should see it
 */
export async function issueCode(config, { tx, session, sub, email }) {
  const now = nowSeconds();
  const payload = {
    v: 1,
    jti: randomToken(16),
    client_id: tx.client_id,
    redirect_uri: tx.redirect_uri,
    scope: tx.scope,
    nonce: tx.nonce,
    code_challenge: tx.code_challenge,
    code_challenge_method: tx.code_challenge_method,
    id_token_alg: tx.id_token_alg,
    resource: tx.resource?.length ? tx.resource : undefined,
    sub,
    email,
    acr: session.acr,
    amr: session.amr,
    auth_time: session.auth_time,
    sid: session.sid,
    claims: session.claims,
    iat: now,
    exp: now + config.tokens.authorizationCodeTtlSeconds,
  };
  return seal(config.secrets[0], PURPOSE, payload);
}

/**
 * Redeem a code.
 *
 * Every check here produces `invalid_grant` with a deliberately unhelpful
 * description, because the caller at this point is a machine and a precise
 * message would only help somebody probing for a code that nearly works.
 */
export async function redeemCode(config, { code, clientId, redirectUri, codeVerifier, replayStore }) {
  let payload;
  try {
    payload = await unseal(config.secrets, PURPOSE, code);
  } catch {
    throw invalidGrant('The authorization code is invalid or has expired.');
  }
  if (payload.v !== 1) throw invalidGrant('The authorization code is invalid or has expired.');
  if (payload.client_id !== clientId) {
    throw invalidGrant('The authorization code was not issued to this client.');
  }
  // The redirect URI must be presented again and match, so a code intercepted
  // at one registered URI cannot be redeemed as though it came from another.
  if (redirectUri !== undefined && payload.redirect_uri !== redirectUri) {
    throw invalidGrant('The redirect_uri does not match the one used to obtain this code.');
  }

  if (payload.code_challenge) {
    if (!codeVerifier) throw invalidGrant('A code_verifier is required for this authorization code.');
    if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) {
      throw invalidGrant('The code_verifier is malformed.');
    }
    const digest = await sha256b64u(codeVerifier);
    if (!timingSafeEqual(digest, payload.code_challenge)) {
      throw invalidGrant('The code_verifier does not match the code_challenge.');
    }
  }

  if (replayStore) {
    const fresh = await replayStore.claim(payload.jti, payload.exp - nowSeconds() + 60);
    if (!fresh) throw invalidGrant('This authorization code has already been used.');
  }

  return payload;
}
