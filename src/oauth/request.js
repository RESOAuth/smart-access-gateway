// Parsing and validating an authorisation request.
//
// The order of checks is the security-critical part. Until the client and its
// redirect URI are both known good, an error must never be redirected: doing
// so turns the authorisation endpoint into an open redirector. Everything that
// can be checked without trusting the request comes first, and only then does
// `redirectable` become true.

import { OAuthError, invalidRequest } from '../util/errors.js';
import { single } from '../util/http.js';
import { redirectUriAllowed } from '../clients/index.js';
import { normaliseEmail } from '../identity.js';

const RESPONSE_TYPES = new Set(['code']);
const RESPONSE_MODES = new Set(['query', 'form_post']);
const PROMPTS = new Set(['none', 'login', 'consent', 'select_account']);

/**
 * Errors raised before a redirect URI is trusted. The caller renders these as
 * a page, because there is nowhere safe to send them.
 */
export class UnredirectableError extends OAuthError {
  constructor(code, description, status = 400) {
    super(code, description, { status, redirect: false });
    this.name = 'UnredirectableError';
  }
}

/**
 * @param {URLSearchParams} params
 * @param {object} config
 * @param {object} deps  { resolveClient }
 * @returns {Promise<{client: object, request: object}>}
 */
export async function parseAuthorizationRequest(params, config, deps) {
  // --- Stage one: who is asking, and where may we answer? ------------------
  const clientId = single(params, 'client_id');
  if (!clientId) throw new UnredirectableError('invalid_request', 'The client_id parameter is missing.');

  let client;
  try {
    client = await deps.resolveClient(clientId);
  } catch (err) {
    if (err instanceof OAuthError) throw new UnredirectableError(err.code, err.description, err.status);
    throw new UnredirectableError('invalid_client', 'The client could not be identified: ' + err.message);
  }
  if (!client) {
    throw new UnredirectableError('invalid_client', 'No client is registered with that client_id here.', 401);
  }

  const redirectUri = single(params, 'redirect_uri');
  if (!redirectUri) {
    throw new UnredirectableError('invalid_request', 'The redirect_uri parameter is missing.');
  }
  if (!redirectUriAllowed(client, redirectUri)) {
    throw new UnredirectableError(
      'invalid_request',
      'That redirect_uri is not registered for this client. It must match one of the registered values exactly.',
    );
  }

  // --- Stage two: everything else may be reported to the relying party ----
  const state = single(params, 'state');
  const fail = (code, description) => {
    throw new OAuthError(code, description, { redirect: true });
  };

  const responseType = single(params, 'response_type');
  if (!responseType) fail('invalid_request', 'The response_type parameter is missing.');
  if (!RESPONSE_TYPES.has(responseType)) {
    fail(
      'unsupported_response_type',
      'Only the authorization code flow is supported here, so response_type must be "code".',
    );
  }

  const responseMode = single(params, 'response_mode') ?? 'query';
  if (!RESPONSE_MODES.has(responseMode)) {
    fail('invalid_request', 'response_mode must be "query" or "form_post".');
  }

  const scope = (single(params, 'scope') || '').split(/\s+/).filter(Boolean);
  if (!scope.includes('openid')) {
    fail('invalid_scope', 'The scope must include "openid". This service issues identity tokens only.');
  }
  const unknown = scope.filter((s) => !SUPPORTED_SCOPES.has(s));
  if (unknown.length) fail('invalid_scope', 'Unsupported scope: ' + unknown.join(', ') + '.');
  if (client.scopes) {
    const notPermitted = scope.filter((s) => !client.scopes.includes(s));
    if (notPermitted.length) {
      fail('invalid_scope', 'This client may not request: ' + notPermitted.join(', ') + '.');
    }
  }

  // PKCE. OAuth 2.1 makes it mandatory for every client, not just public ones,
  // and only S256 is allowed: "plain" gives no protection against an attacker
  // who can already see the request.
  const codeChallenge = single(params, 'code_challenge');
  const codeChallengeMethod = single(params, 'code_challenge_method') ?? (codeChallenge ? 'S256' : undefined);
  if (client.requirePkce !== false && !codeChallenge) {
    fail('invalid_request', 'A code_challenge is required. This service implements OAuth 2.1, where PKCE is mandatory.');
  }
  if (codeChallenge) {
    if (codeChallengeMethod !== 'S256') {
      fail('invalid_request', 'code_challenge_method must be "S256".');
    }
    if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)) {
      fail('invalid_request', 'The code_challenge is not a valid base64url S256 digest.');
    }
  }

  const nonce = single(params, 'nonce');
  const rawPrompt = single(params, 'prompt');
  // Make account use visible unless the client deliberately asks for a
  // transparent request. `single()` also treats a blank prompt as absent.
  const prompt = rawPrompt === undefined ? ['consent'] : rawPrompt.split(/\s+/).filter(Boolean);
  for (const p of prompt) if (!PROMPTS.has(p)) fail('invalid_request', 'Unsupported prompt value: ' + p + '.');
  if (prompt.includes('none') && prompt.length > 1) {
    fail('invalid_request', 'prompt=none cannot be combined with other prompt values.');
  }

  let maxAge;
  const rawMaxAge = single(params, 'max_age');
  if (rawMaxAge !== undefined) {
    maxAge = Number(rawMaxAge);
    if (!Number.isInteger(maxAge) || maxAge < 0) fail('invalid_request', 'max_age must be a non-negative integer.');
  }

  const acrValues = (single(params, 'acr_values') || '').split(/\s+/).filter(Boolean);
  const required = acrValues.length ? acrValues : config.acr.defaultRequired;
  if (client.acrValues?.length) {
    // A client configured with a floor gets it whether it asked or not.
    for (const a of client.acrValues) if (!required.includes(a)) required.push(a);
  }

  const idTokenAlg = single(params, 'id_token_signed_response_alg') ?? client.idTokenSignedResponseAlg;

  const loginHintRaw = single(params, 'login_hint');
  const loginHint = loginHintRaw ? normaliseEmail(loginHintRaw) : undefined;

  return {
    client,
    request: {
      clientId,
      redirectUri,
      state,
      nonce,
      scope,
      responseType,
      responseMode,
      codeChallenge,
      codeChallengeMethod: codeChallenge ? codeChallengeMethod : undefined,
      acrValues: required,
      prompt,
      maxAge,
      loginHint,
      idTokenAlg,
      resource: params.getAll('resource').filter(Boolean),
      uiLocales: (single(params, 'ui_locales') || '').split(/\s+/).filter(Boolean),
    },
  };
}

export const SUPPORTED_SCOPES = new Set(['openid', 'email', 'profile', 'offline_access']);

/**
 * Build the redirect back to the relying party.
 *
 * `iss` is always included. RFC 9207 added it so a relying party talking to
 * several identity providers cannot be tricked into accepting a code minted by
 * the wrong one.
 */
export function successRedirect(redirectUri, { code, state, issuer }) {
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state !== undefined) url.searchParams.set('state', state);
  url.searchParams.set('iss', issuer);
  return url.toString();
}

export function errorRedirect(redirectUri, error, state, issuer) {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error.code);
  if (error.description) url.searchParams.set('error_description', error.description);
  if (error.uri) url.searchParams.set('error_uri', error.uri);
  if (state !== undefined) url.searchParams.set('state', state);
  url.searchParams.set('iss', issuer);
  return url.toString();
}

export { invalidRequest };
