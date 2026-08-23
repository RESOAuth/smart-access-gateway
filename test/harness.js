// A relying party, in about a hundred lines.
//
// The tests drive handleRequest directly rather than over a socket: it is the
// same code every adapter runs, and it means the suite needs no server, no
// port, and no cleanup. The harness keeps a cookie jar and follows redirects
// exactly as a browser would, so a test can assert on the real flow rather
// than on internal calls.

import { handleRequest } from '../src/index.js';
import { b64u, randomBytes } from '../src/util/bytes.js';
import { sha256b64u } from '../src/crypto/secrets.js';
import { resetContextCache } from '../src/context.js';

export const DEV_CLIENT = 'sag-dev-client';
export const DEV_REDIRECT = 'http://127.0.0.1:8788/callback';

/**
 * @param {object} [env] Environment overrides for this instance
 */
export function createInstance(env = {}) {
  // Quiet by default: the tests read one-time codes out of the rendered page,
  // never the console, so the sender's banner is pure noise here.
  const bag = {
    SAG_ISSUER: 'http://localhost:8787',
    SAG_SECRET: 'test-secret-'.repeat(4),
    LOG_LEVEL: 'silent',
    ...env,
  };
  resetContextCache();
  const cookies = new Map();

  /** Fetch, with the cookie jar applied. */
  async function raw(path, init = {}) {
    const url = path.startsWith('http') ? path : bag.SAG_ISSUER + path;
    const headers = new Headers(init.headers || {});
    if (cookies.size && !headers.has('cookie')) {
      headers.set('cookie', [...cookies].map(([k, v]) => k + '=' + v).join('; '));
    }
    const response = await handleRequest(new Request(url, { ...init, headers }), bag);
    for (const raw of response.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(raw)) cookies.delete(name);
      else cookies.set(name, value);
    }
    return response;
  }

  /** POST a form, as a browser submitting one of our pages would. */
  const postForm = (path, fields) =>
    raw(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });

  return {
    env: bag,
    cookies,
    raw,
    postForm,
    json: async (path, init) => {
      const res = await raw(path, init);
      return { res, body: await res.json() };
    },
    text: async (path, init) => {
      const res = await raw(path, init);
      return { res, body: await res.text() };
    },
    clearCookies: () => cookies.clear(),
  };
}

/** A PKCE pair. */
export async function pkce() {
  const verifier = b64u(randomBytes(32));
  return { verifier, challenge: await sha256b64u(verifier) };
}

/** Build an /authorize URL the way a relying party library would. */
export function authorizeUrl({ clientId = DEV_CLIENT, redirectUri = DEV_REDIRECT, challenge, ...extra }) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid email',
    state: 'rp-state-' + b64u(randomBytes(6)),
    nonce: 'rp-nonce-' + b64u(randomBytes(6)),
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) params.delete(k);
    else params.set(k, String(v));
  }
  return { path: '/authorize?' + params.toString(), params };
}

/** Pull the hidden transaction field out of a rendered page. */
export function extractField(html, name = 'tx') {
  const re = new RegExp('name="' + name + '"\\s+value="([^"]*)"');
  const m = html.match(re) || html.match(new RegExp('value="([^"]*)"\\s+name="' + name + '"'));
  return m ? decodeEntities(m[1]) : undefined;
}

/** Pull the code out of the console sender's output, or the dev notice. */
export function extractDevCode(html) {
  const m = html.match(/<code>([0-9A-Z]{6,12})<\/code>/);
  return m ? m[1] : undefined;
}

function decodeEntities(s) {
  return s
    .replaceAll('&amp;', '&')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'");
}

/**
 * Run the whole email-code flow and return the tokens.
 *
 * This is the path a real person takes, screen by screen, so a test that calls
 * it is asserting on the actual product rather than on a shortcut.
 */
export async function signInWithOtp(instance, { email, authorize = {}, expectStage } = {}) {
  const { verifier, challenge } = await pkce();
  const { path, params } = authorizeUrl({ challenge, ...authorize });

  const first = await instance.raw(path);
  if (first.status === 303) {
    // An existing session answered without a page. That is correct behaviour,
    // so say so plainly rather than reporting an empty page: the caller either
    // wants clearCookies() first, or prompt=login.
    throw new Error(
      'the existing session answered silently; call instance.clearCookies() or pass authorize: { prompt: "login" }',
    );
  }
  const firstHtml = await first.text();
  if (expectStage) expectStage(first, firstHtml);

  const tx = extractField(firstHtml);
  if (!tx) throw new Error('no transaction on the first page:\n' + firstHtml.slice(0, 800));

  const otpRes = await instance.postForm('/authorize/email', { tx, email });
  const otpHtml = await otpRes.text();
  const tx2 = extractField(otpHtml);
  const code = extractDevCode(otpHtml);
  if (!code) throw new Error('no development code on the OTP page:\n' + otpHtml.slice(0, 800));

  const done = await instance.postForm('/authorize/otp', { tx: tx2, code });
  if (done.status !== 303) {
    throw new Error('expected a redirect back to the relying party, got ' + done.status + '\n' + (await done.text()).slice(0, 800));
  }
  const location = new URL(done.headers.get('location'));
  const authCode = location.searchParams.get('code');
  if (!authCode) throw new Error('no authorization code in ' + location.toString());

  return {
    authCode,
    verifier,
    state: params.get('state'),
    nonce: params.get('nonce'),
    returnedState: location.searchParams.get('state'),
    iss: location.searchParams.get('iss'),
    redirectUri: params.get('redirect_uri'),
    clientId: params.get('client_id'),
  };
}

/** Redeem a code at /token. */
export async function redeem(instance, { authCode, verifier, clientId = DEV_CLIENT, redirectUri = DEV_REDIRECT, extra = {} }) {
  const res = await instance.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
      ...extra,
    }).toString(),
  });
  return { res, body: await res.json() };
}
