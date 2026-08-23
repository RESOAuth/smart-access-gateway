// The in-flight authorisation request.
//
// Everything SAG needs to remember between the relying party arriving at
// /authorize and the code being issued lives in one sealed token. It travels
// as a hidden form field through the interactive screens - not a cookie, so
// the flow works with third-party cookies blocked - and as the `state`
// parameter across the upstream round trip, which is what the brief means by
// using OAuth state cleverly to relay user information.
//
// Two purposes are used, never one. A transaction handed to the browser is
// sealed as `tx`; the copy handed to an upstream provider is sealed as
// `upstream-state`. Because the purpose is authenticated as additional data,
// a token minted for one can never be accepted as the other.

import { seal, unseal, SealError } from '../crypto/secrets.js';
import { nowSeconds, randomToken } from '../util/bytes.js';

export const TX_PURPOSE = 'tx';
export const UPSTREAM_STATE_PURPOSE = 'upstream-state';

/** Stages the interactive flow can be at. */
export const STAGE = {
  EMAIL: 'email',
  CHOOSE: 'choose',
  OTP: 'otp',
  CONTINUE: 'continue',
};

/**
 * Create a transaction from a validated authorisation request.
 *
 * @param {object} config
 * @param {object} req  Normalised request parameters
 */
export function newTransaction(config, req) {
  const now = nowSeconds();
  return {
    v: 1,
    id: randomToken(12),
    stage: STAGE.EMAIL,
    client_id: req.clientId,
    redirect_uri: req.redirectUri,
    state: req.state,
    nonce: req.nonce,
    scope: req.scope,
    response_type: req.responseType,
    response_mode: req.responseMode,
    code_challenge: req.codeChallenge,
    code_challenge_method: req.codeChallengeMethod,
    acr_values: req.acrValues,
    prompt: req.prompt,
    max_age: req.maxAge,
    login_hint: req.loginHint,
    id_token_alg: req.idTokenAlg,
    resource: req.resource,
    iat: now,
    exp: now + config.tokens.transactionTtlSeconds,
  };
}

export const sealTransaction = (config, tx) => seal(config.secrets[0], TX_PURPOSE, tx);

/**
 * Open a transaction handed back by the browser.
 *
 * A failure here is never the person's fault in any way they can fix, so the
 * caller shows the "start again" page rather than an OAuth error: there is no
 * trustworthy redirect_uri to send an error to once the transaction is gone.
 */
export async function openTransaction(config, token) {
  const tx = await unseal(config.secrets, TX_PURPOSE, token);
  if (!tx || tx.v !== 1 || !tx.client_id) throw new SealError('unrecognised transaction');
  return tx;
}

export const sealUpstreamState = (config, tx) => seal(config.secrets[0], UPSTREAM_STATE_PURPOSE, tx);

export async function openUpstreamState(config, token) {
  const tx = await unseal(config.secrets, UPSTREAM_STATE_PURPOSE, token);
  if (!tx || tx.v !== 1 || !tx.upstream) throw new SealError('unrecognised upstream state');
  return tx;
}

/** Advance a transaction, keeping its identity and deadline. */
export function advance(tx, changes) {
  return { ...tx, ...changes };
}

/**
 * Record that an OTP has been issued.
 *
 * The digest, not the code, is kept. The transaction is encrypted so the code
 * would be safe either way, but a digest means a transaction that somehow
 * escapes - into a log, a referrer, a screenshot - still does not reveal it.
 */
export function withOtp(tx, { digest, expiresAt, resends = 0 }) {
  return {
    ...tx,
    stage: STAGE.OTP,
    otp: { digest, exp: expiresAt, attempts: 0, resends, iat: nowSeconds() },
  };
}

export function withOtpAttempt(tx) {
  return { ...tx, otp: { ...tx.otp, attempts: (tx.otp?.attempts ?? 0) + 1 } };
}

/** Discard the OTP state, for "use a different email address". */
export function withoutOtp(tx) {
  const { otp, email, upstream, ...rest } = tx;
  return { ...rest, stage: STAGE.EMAIL };
}

/**
 * Drop the attempt but keep the address.
 *
 * Used when one route for an address has failed and the person is being offered
 * the others: the upstream leg and any code state have to go, but the address
 * must not, because the screen shows it and the next step routes on it.
 * `withoutOtp` is the other case - going back to asking for an address at all.
 */
export function withoutAttempt(tx) {
  const { otp, upstream, ...rest } = tx;
  return rest;
}

export function expired(tx) {
  return typeof tx.exp === 'number' && tx.exp < nowSeconds();
}
