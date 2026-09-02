// The platform adapters, and the Cloudflare HSM signing path.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { envWithResolver } from '../adapters/cloudflare/worker.js';
import { createDnsResolver } from '../adapters/cloudflare/dns.js';
import hsm, { _resetCache } from '../adapters/cloudflare/hsm.js';
import { handler, toLambdaResult } from '../adapters/lambda/handler.js';
import { handleRequest } from '../src/index.js';
import { resetContextCache } from '../src/context.js';
import { publicPartOf, jwkThumbprint, verifyCompact, decodeJwt } from '../src/crypto/jose.js';
import { pkce, authorizeUrl, extractField, DEV_CLIENT } from './harness.js';

const ISSUER = 'https://id.example.test';

/** Generate a signing key the way keygen does. */
async function signingKey(alg = 'ES256') {
  const params = alg === 'ES256' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: alg };
  const pair = await crypto.subtle.generateKey(params, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg };
  const kid = await jwkThumbprint(jwk);
  return { privateJwk: { ...jwk, kid }, publicJwk: publicPartOf({ ...jwk, kid }), kid, alg };
}

// ---------------------------------------------------------------------------
// The HSM Worker
// ---------------------------------------------------------------------------

test('the HSM refuses every request without the shared secret', async () => {
  _resetCache();
  const key = await signingKey();
  const env = { HSM_SHARED_SECRET: 'right-secret', SIGNING_PRIVATE_JWK: JSON.stringify(key.privateJwk) };

  for (const headers of [{}, { 'x-sag-hsm-secret': 'wrong-secret' }, { 'x-sag-hsm-secret': '' }]) {
    const res = await hsm.fetch(new Request('https://sag-hsm.internal/jwks', { headers }), env);
    assert.equal(res.status, 403, 'a missing and a wrong secret must be indistinguishable');
  }
  const ok = await hsm.fetch(
    new Request('https://sag-hsm.internal/jwks', { headers: { 'x-sag-hsm-secret': 'right-secret' } }),
    env,
  );
  assert.equal(ok.status, 200);
});

test('the HSM publishes only public key material and signs on request', async () => {
  _resetCache();
  const key = await signingKey();
  const env = { HSM_SHARED_SECRET: 's', SIGNING_PRIVATE_JWK: JSON.stringify(key.privateJwk) };
  const headers = { 'x-sag-hsm-secret': 's', 'content-type': 'application/json' };

  const jwksRes = await hsm.fetch(new Request('https://sag-hsm.internal/jwks', { headers }), env);
  const jwks = await jwksRes.json();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kid, key.kid);
  assert.equal(jwks.keys[0].d, undefined, 'the private component must never be published');

  const signRes = await hsm.fetch(
    new Request('https://sag-hsm.internal/sign', {
      method: 'POST',
      headers,
      body: JSON.stringify({ alg: 'ES256', input: 'aGVsbG8' }),
    }),
    env,
  );
  const signed = await signRes.json();
  assert.equal(signRes.status, 200);
  assert.ok(signed.signature);
  assert.equal(signed.kid, key.kid);
});

test('the HSM refuses an oversized or empty signing input', async () => {
  _resetCache();
  const key = await signingKey();
  const env = { HSM_SHARED_SECRET: 's', SIGNING_PRIVATE_JWK: JSON.stringify(key.privateJwk) };
  const headers = { 'x-sag-hsm-secret': 's', 'content-type': 'application/json' };

  const send = (input) =>
    hsm.fetch(
      new Request('https://sag-hsm.internal/sign', {
        method: 'POST',
        headers,
        body: JSON.stringify({ alg: 'ES256', input }),
      }),
      env,
    );

  assert.equal((await send('')).status, 400, 'an empty input is not a JWS signing input');
  assert.equal((await send('!!!not base64url!!!')).status, 400);
  // A JWS signing input is small; anything large means this is being used as a
  // general-purpose signing oracle.
  const huge = 'A'.repeat(20000);
  assert.equal((await send(huge)).status, 400);
});

test('the HSM holds several algorithms at once and signs with the one asked for', async (t) => {
  _resetCache();
  t.after(_resetCache);
  const classical = await signingKey('ES256');
  let pq;
  try {
    pq = await signingKey('ML-DSA-44');
  } catch {
    t.skip('this runtime has no ML-DSA support');
    return;
  }

  const env = {
    HSM_SHARED_SECRET: 's',
    SIGNING_ALG: 'ES256',
    SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44',
    SIGNING_PRIVATE_JWK: JSON.stringify(classical.privateJwk),
    SIGNING_PRIVATE_JWK_ML_DSA_44: JSON.stringify(pq.privateJwk),
  };
  const headers = { 'x-sag-hsm-secret': 's', 'content-type': 'application/json' };

  const jwks = await (await hsm.fetch(new Request('https://sag-hsm.internal/jwks', { headers }), env)).json();
  assert.equal(jwks.keys.length, 2);
  assert.equal(jwks.keys[0].kid, classical.kid, 'the primary must be published first');

  const signed = await (
    await hsm.fetch(
      new Request('https://sag-hsm.internal/sign', {
        method: 'POST',
        headers,
        body: JSON.stringify({ alg: 'ML-DSA-44', input: 'aGVsbG8' }),
      }),
      env,
    )
  ).json();
  assert.equal(signed.alg, 'ML-DSA-44');
  assert.equal(signed.kid, pq.kid);
});

test('the main Worker signs id_tokens through the HSM binding', async (t) => {
  _resetCache();
  t.after(_resetCache);
  resetContextCache();
  const key = await signingKey();

  // A service binding is an object with a fetch method, so the HSM Worker can
  // be wired straight in without a network in between.
  const hsmEnv = { HSM_SHARED_SECRET: 'shared', SIGNING_PRIVATE_JWK: JSON.stringify(key.privateJwk) };
  const env = {
    SAG_ISSUER: ISSUER,
    SAG_SECRET: 'a'.repeat(48),
    SIGNING_BACKEND: 'cloudflare-hsm',
    HSM_SHARED_SECRET: 'shared',
    EMAIL_PROVIDER: 'console',
    SAG_DEV: 'true',
    LOG_LEVEL: 'silent',
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: 'https://app.example.test/callback',
    HSM: { fetch: (request) => hsm.fetch(request, hsmEnv) },
  };

  const cookies = new Map();
  const call = async (path, init = {}) => {
    const headers = new Headers(init.headers || {});
    if (cookies.size) headers.set('cookie', [...cookies].map(([k, v]) => k + '=' + v).join('; '));
    const res = await worker.fetch(new Request(ISSUER + path, { ...init, headers }), env, {});
    for (const raw of res.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(';');
      const i = pair.indexOf('=');
      cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
    }
    return res;
  };

  // The JWKS comes from the HSM, and carries no private component.
  const jwks = await (await call('/jwks.json')).json();
  assert.equal(jwks.keys[0].kid, key.kid);
  assert.equal(jwks.keys[0].d, undefined);

  const { verifier, challenge } = await pkce();
  const { path, params } = authorizeUrl({
    challenge,
    clientId: DEV_CLIENT,
    redirectUri: 'https://app.example.test/callback',
  });
  const first = await call(path);
  const tx = extractField(await first.text());
  const otp = await call('/authorize/email', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ tx, email: 'person@example.org' }).toString(),
  });
  const otpHtml = await otp.text();
  const code = otpHtml.match(/<code>([0-9A-Z]+)<\/code>/)[1];
  const done = await call('/authorize/otp', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ tx: extractField(otpHtml), code }).toString(),
  });
  assert.equal(done.status, 303);
  const authCode = new URL(done.headers.get('location')).searchParams.get('code');

  const tokenRes = await call('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: 'https://app.example.test/callback',
      client_id: DEV_CLIENT,
      code_verifier: verifier,
    }).toString(),
  });
  const tokens = await tokenRes.json();
  assert.equal(tokenRes.status, 200, JSON.stringify(tokens));

  // The signature was made inside the HSM, and verifies against its public key.
  const { header } = decodeJwt(tokens.id_token);
  assert.equal(header.kid, key.kid);
  const claims = await verifyCompact(tokens.id_token, key.publicJwk, { algs: ['ES256'] });
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.nonce, params.get('nonce'));
});

// ---------------------------------------------------------------------------
// Lambda
// ---------------------------------------------------------------------------

const lambdaEnv = {
  SAG_ISSUER: ISSUER,
  SAG_SECRET: 'b'.repeat(48),
  SAG_DEV: 'true',
  LOG_LEVEL: 'silent',
  CLIENT_APP_ID: DEV_CLIENT,
  CLIENT_APP_REDIRECT_URIS: 'https://app.example.test/callback',
};

function withLambdaEnv(t) {
  const saved = {};
  for (const [k, v] of Object.entries(lambdaEnv)) {
    saved[k] = process.env[k];
    process.env[k] = v;
  }
  t.after(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    resetContextCache();
  });
  resetContextCache();
}

/** An API Gateway HTTP API v2 event. */
const v2Event = (method, path, { query = '', headers = {}, body, cookies } = {}) => ({
  version: '2.0',
  rawPath: path,
  rawQueryString: query,
  headers: { host: 'id.example.test', 'x-forwarded-proto': 'https', ...headers },
  cookies,
  body,
  isBase64Encoded: false,
  requestContext: { http: { method }, stage: '$default', domainName: 'id.example.test' },
});

test('the Lambda adapter serves discovery from a v2 event', async (t) => {
  withLambdaEnv(t);
  const result = await handler(v2Event('GET', '/.well-known/openid-configuration'));
  assert.equal(result.statusCode, 200);
  assert.equal(result.isBase64Encoded, false, 'JSON must not be base64 encoded');
  const body = JSON.parse(result.body);
  assert.equal(body.issuer, ISSUER);
});

test('the Lambda adapter strips a named stage prefix but keeps the path', async (t) => {
  withLambdaEnv(t);
  const event = v2Event('GET', '/prod/.well-known/openid-configuration');
  event.requestContext.stage = 'prod';
  const result = await handler(event);
  assert.equal(result.statusCode, 200, 'the stage prefix should not have hidden the route');
});

test('the Lambda adapter returns cookies separately, not comma-joined', async (t) => {
  withLambdaEnv(t);
  const { challenge } = await pkce();
  const { path } = authorizeUrl({
    challenge,
    clientId: DEV_CLIENT,
    redirectUri: 'https://app.example.test/callback',
  });
  const [route, query] = path.split('?');

  const first = await handler(v2Event('GET', route, { query }));
  const tx = extractField(first.body);
  const otp = await handler(
    v2Event('POST', '/authorize/email', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx, email: 'person@example.org' }).toString(),
    }),
  );
  const code = otp.body.match(/<code>([0-9A-Z]+)<\/code>/)[1];
  const done = await handler(
    v2Event('POST', '/authorize/otp', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: extractField(otp.body), code }).toString(),
    }),
  );

  assert.equal(done.statusCode, 303);
  assert.ok(Array.isArray(done.cookies), 'Set-Cookie belongs in cookies, not headers');
  assert.equal(done.cookies.length, 1);
  assert.equal(done.headers['set-cookie'], undefined);
  assert.match(done.cookies[0], /^sag_session=/);
  assert.match(done.cookies[0], /HttpOnly/);
  assert.match(done.cookies[0], /SameSite=Lax/);
  assert.match(done.cookies[0], /Secure/);
  assert.match(done.cookies[0], /Path=\//);
});

test('the Lambda adapter reads cookies back out of the v2 cookies array', async (t) => {
  withLambdaEnv(t);
  // Sign in first, to get a session cookie.
  const { challenge } = await pkce();
  const { path } = authorizeUrl({
    challenge,
    clientId: DEV_CLIENT,
    redirectUri: 'https://app.example.test/callback',
  });
  const [route, query] = path.split('?');
  const first = await handler(v2Event('GET', route, { query }));
  const tx = extractField(first.body);
  const otp = await handler(
    v2Event('POST', '/authorize/email', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx, email: 'person@example.org' }).toString(),
    }),
  );
  const code = otp.body.match(/<code>([0-9A-Z]+)<\/code>/)[1];
  const done = await handler(
    v2Event('POST', '/authorize/otp', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: extractField(otp.body), code }).toString(),
    }),
  );
  const cookie = done.cookies[0].split(';')[0];

  // prompt=none proves the cookie was read: it can only succeed from a session.
  const silent = authorizeUrl({
    challenge,
    prompt: 'none',
    clientId: DEV_CLIENT,
    redirectUri: 'https://app.example.test/callback',
  });
  const [silentRoute, silentQuery] = silent.path.split('?');
  const result = await handler(v2Event('GET', silentRoute, { query: silentQuery, cookies: [cookie] }));
  assert.equal(result.statusCode, 303);
  const location = new URL(result.headers.location);
  assert.ok(location.searchParams.get('code'), 'the session cookie was not read: ' + location.search);
});

test('the Lambda adapter handles a base64 encoded body', async (t) => {
  withLambdaEnv(t);
  const event = v2Event('POST', '/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  event.body = Buffer.from('grant_type=refresh_token').toString('base64');
  event.isBase64Encoded = true;

  const result = await handler(event);
  const body = JSON.parse(result.body);
  // Reaching a specific OAuth error proves the body was decoded and parsed.
  assert.equal(body.error, 'unsupported_grant_type');
  assert.match(body.error_description, /Refresh tokens are not issued/);
});

test('the Lambda adapter accepts a v1 REST API event', async (t) => {
  withLambdaEnv(t);
  const result = await handler({
    path: '/healthz',
    httpMethod: 'GET',
    headers: { Host: 'id.example.test', 'X-Forwarded-Proto': 'https' },
    queryStringParameters: null,
    requestContext: { stage: 'prod' },
  });
  assert.equal(result.statusCode, 200);
  assert.equal(JSON.parse(result.body).issuer, ISSUER);
});

test('a binary response is base64 encoded and text is not', async () => {
  const png = await toLambdaResult(new Response(new Uint8Array([1, 2, 3]), { headers: { 'content-type': 'image/png' } }));
  assert.equal(png.isBase64Encoded, true);

  const css = await toLambdaResult(new Response('body{}', { headers: { 'content-type': 'text/css; charset=utf-8' } }));
  assert.equal(css.isBase64Encoded, false);
  assert.equal(css.body, 'body{}');
});

test('the Worker and the Lambda adapter produce the same discovery document', async (t) => {
  withLambdaEnv(t);
  const env = { ...lambdaEnv };

  resetContextCache();
  const viaWorker = await (await worker.fetch(new Request(ISSUER + '/.well-known/openid-configuration'), env, {})).json();
  resetContextCache();
  const viaCore = await (await handleRequest(new Request(ISSUER + '/.well-known/openid-configuration'), env)).json();
  resetContextCache();
  const viaLambda = JSON.parse((await handler(v2Event('GET', '/.well-known/openid-configuration'))).body);

  assert.deepEqual(viaWorker, viaCore);
  assert.deepEqual(viaLambda, viaCore, 'every platform must describe the same deployment');
});

// ---------------------------------------------------------------------------
// The Worker's platform DNS resolver
// ---------------------------------------------------------------------------
//
// A Worker's own `fetch` to a public DNS-over-HTTPS endpoint does not come
// back, so the core's fallback cannot work here and the adapter has to hand it
// `node:dns` instead. Without that, every client whose id is a metadata
// document URL is refused with "Could not resolve the client metadata host".

test('the Worker hands the core a resolver under the binding name', () => {
  const env = { SAG_ISSUER: ISSUER };
  const bag = envWithResolver(env);

  assert.equal(typeof bag.SAG_DNS?.resolve, 'function', 'the core looks for resolve(name, type)');
  assert.equal(env.SAG_DNS, undefined, 'the bindings object Workers hands in must not be mutated');
  assert.equal(bag.SAG_ISSUER, ISSUER, 'everything else must survive the wrapping');
});

// The request context caches against the identity of the bag it was given, so
// a fresh copy per request would throw the config away on every request.
test('the wrapped bag is stable across calls', () => {
  const env = { SAG_ISSUER: ISSUER };
  assert.equal(envWithResolver(env), envWithResolver(env));
});

test('a resolver binding an operator supplied wins', () => {
  const own = { resolve: () => Promise.resolve([]) };
  const bag = envWithResolver({ SAG_DNS: own });
  assert.equal(bag.SAG_DNS, own);
});

test('an explicit DNS_RESOLVER_URL wins, because asking for it is a choice', () => {
  const env = { DNS_RESOLVER_URL: 'https://dns.example.test/resolve' };
  const bag = envWithResolver(env);
  assert.equal(bag, env, 'the bag must be handed through untouched');
  assert.equal(bag.SAG_DNS, undefined);
});

test('DNS_BINDING renames the binding the resolver is supplied under', () => {
  const bag = envWithResolver({ DNS_BINDING: 'OUR_DNS' });
  assert.equal(typeof bag.OUR_DNS?.resolve, 'function');
  assert.equal(bag.SAG_DNS, undefined);
});

test('the Worker resolver refuses a record type it cannot answer', async () => {
  await assert.rejects(() => createDnsResolver().resolve('example.test', 'SRV'), /unsupported record type SRV/);
});

// `lookup`, `lookupService`, and the generic `resolve` throw "Not implemented"
// on Workers, so the resolver must never reach for them.
test('the Worker resolver answers A and AAAA without lookup or resolve', async () => {
  const calls = [];
  const fake = {
    resolve4: (n) => (calls.push('resolve4 ' + n), Promise.resolve(['192.0.2.1'])),
    resolve6: (n) => (calls.push('resolve6 ' + n), Promise.resolve(['2001:db8::1'])),
    resolve: () => Promise.reject(new Error('Not implemented')),
    lookup: () => Promise.reject(new Error('Not implemented')),
  };
  const resolver = createDnsResolver({ resolver: fake });
  assert.deepEqual(await resolver.resolve('a.example.test', 'A'), ['192.0.2.1']);
  assert.deepEqual(await resolver.resolve('a.example.test', 'AAAA'), ['2001:db8::1']);
  assert.deepEqual(calls, ['resolve4 a.example.test', 'resolve6 a.example.test']);
});

// Workers' node:dns returns the whole answer section rather than only the
// records asked for, which Node does not do. The CNAME target below is exactly
// what a real lookup of a GitHub Pages hostname returns alongside the
// addresses; left in, the core reads it as a non-public address and refuses the
// client.
test('the Worker resolver drops answers that are not of the type asked for', async () => {
  const fake = {
    resolve4: () => Promise.resolve(['resoauth.github.io.', '185.199.108.153', '185.199.109.153']),
    resolve6: () => Promise.resolve(['resoauth.github.io.', '2606:50c0:8000::153']),
  };
  const resolver = createDnsResolver({ resolver: fake });
  assert.deepEqual(await resolver.resolve('pages.example.test', 'A'), ['185.199.108.153', '185.199.109.153']);
  assert.deepEqual(await resolver.resolve('pages.example.test', 'AAAA'), ['2606:50c0:8000::153']);
});

test('the same goes for MX and TXT, which get a stray record too', async () => {
  const fake = {
    resolveMx: () => Promise.resolve(['cname.example.test.', { priority: 10, exchange: 'mx.example.test' }]),
    resolveTxt: () => Promise.resolve(['cname.example.test.', ['v=spf1 -all']]),
  };
  const resolver = createDnsResolver({ resolver: fake });
  assert.deepEqual(await resolver.resolve('example.test', 'MX'), ['10 mx.example.test']);
  assert.deepEqual(await resolver.resolve('example.test', 'TXT'), ['v=spf1 -all']);
});

// The textual shape has to match what the DNS-over-HTTPS path and the Node
// adapter produce, or the provider hint reads different answers per platform.
test('the Worker resolver renders MX and TXT the way the other paths do', async () => {
  const fake = {
    resolveMx: () => Promise.resolve([{ priority: 10, exchange: 'mx.example.test' }]),
    resolveTxt: () => Promise.resolve([['v=spf1 ', 'include:_spf.example.test -all']]),
  };
  const resolver = createDnsResolver({ resolver: fake });
  assert.deepEqual(await resolver.resolve('example.test', 'MX'), ['10 mx.example.test']);
  assert.deepEqual(await resolver.resolve('example.test', 'TXT'), ['v=spf1 include:_spf.example.test -all']);
});

test('a hung lookup gives up rather than holding the invocation open', async () => {
  const resolver = createDnsResolver({ timeoutMs: 5, resolver: { resolve4: () => new Promise(() => {}) } });
  await assert.rejects(() => resolver.resolve('slow.example.test', 'A'), /timed out/);
});
