import { FuzzedDataProvider } from '@jazzer.js/core';
import { loadConfig } from '../../src/config.js';
import { decodeJwt } from '../../src/crypto/jose.js';
import { looksLikeEmail, normaliseEmail, stripPlusTag } from '../../src/identity.js';
import { parseAuthorizationRequest } from '../../src/oauth/request.js';
import { formatCodeForDisplay } from '../../src/otp.js';
import { isIpAddress, isLoopbackIp, isPublicIp } from '../../src/util/ip.js';
import { OAuthError } from '../../src/util/errors.js';
import { parseEnvFile } from '../../tools/datadir.js';

const CLIENT_ID = 'fuzz-client';
const REDIRECT_URI = 'https://app.example.test/callback';
const CODE_CHALLENGE = 'A'.repeat(43);
const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
const client = {
  clientId: CLIENT_ID,
  redirectUris: [REDIRECT_URI],
  scopes: ['openid', 'email', 'profile', 'offline_access'],
  requirePkce: true,
};
const deps = { resolveClient: async (clientId) => (clientId === CLIENT_ID ? client : undefined) };

function value(provider, valid, maxLength = 128) {
  return provider.consumeBoolean() ? valid : provider.consumeString(maxLength);
}

function authorizationParams(input, data) {
  const provider = new FuzzedDataProvider(data);
  const params = new URLSearchParams(input);
  params.set('client_id', value(provider, CLIENT_ID));
  params.set('redirect_uri', value(provider, REDIRECT_URI, 256));
  params.set('response_type', value(provider, 'code'));
  params.set('response_mode', value(provider, 'query'));
  params.set('scope', value(provider, 'openid email'));
  params.set('code_challenge', value(provider, CODE_CHALLENGE));
  params.set('code_challenge_method', value(provider, 'S256'));
  params.set('prompt', value(provider, 'consent'));
  params.set('max_age', value(provider, '300'));
  params.set('acr_values', provider.consumeString(128));
  params.set('login_hint', provider.consumeString(256));
  if (provider.consumeBoolean()) params.append('scope', provider.consumeString(128));
  if (provider.consumeBoolean()) params.append('resource', provider.consumeString(256));
  return params;
}

function exerciseJwtDecoder(input) {
  try {
    const decoded = decodeJwt(input);
    if (!(decoded.signature instanceof Uint8Array) || !(decoded.input instanceof Uint8Array)) {
      throw new Error('decoded JWT contains non-byte binary fields');
    }
  } catch (err) {
    if (err instanceof SyntaxError || err?.message === 'not a compact JWS' || err?.message === 'invalid base64url') return;
    throw err;
  }
}

function exercisePureParsers(input) {
  const normalised = normaliseEmail(input);
  if (normaliseEmail(normalised) !== normalised) throw new Error('email normalisation is not idempotent');

  const untagged = stripPlusTag(input);
  if (stripPlusTag(untagged) !== untagged) throw new Error('plus-tag removal is not idempotent');

  looksLikeEmail(input);
  formatCodeForDisplay(input);
  const env = parseEnvFile(input);
  if (Object.getPrototypeOf(env) !== Object.prototype) throw new Error('environment parser changed the object prototype');

  const address = isIpAddress(input);
  const loopback = isLoopbackIp(input);
  const publicAddress = isPublicIp(input);
  if (loopback && publicAddress) throw new Error('loopback address classified as public');
  if (publicAddress && !address) throw new Error('non-address classified as public');

  exerciseJwtDecoder(input);
}

export async function fuzz(data) {
  const input = data.toString('utf8');
  exercisePureParsers(input);

  try {
    const parsed = await parseAuthorizationRequest(authorizationParams(input, data), config, deps);
    if (parsed.client !== client || parsed.request.clientId !== CLIENT_ID || parsed.request.redirectUri !== REDIRECT_URI) {
      throw new Error('authorization parser accepted an unregistered client or redirect URI');
    }
  } catch (err) {
    if (err instanceof OAuthError) return;
    throw err;
  }
}
