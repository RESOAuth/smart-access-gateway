#!/usr/bin/env node
// Sign in against every instance in the stack, from the outside, over HTTP.
//
//   ./stack.sh verify
//   ./stack.sh verify sag-workers          just the one
//
// The unit tests call handleRequest directly, which is the right way to test
// what SAG decides. This is the other half: whether an instance, in a
// container, on a platform, with a real signing backend and a real state store,
// actually signs somebody in. Everything it checks is something no unit test
// can see -
//
//   * a signature made by KMS or by a separate Worker, verified against the
//     JWKS that instance publishes;
//   * an authorisation code refused the second time, which across four
//     instances means three different store implementations answering "have I
//     seen this?";
//   * a session cookie sealed by one platform and opened again by it, which is
//     what makes the silent second sign-in work;
//   * on Lambda, a request that has been through an API Gateway event and back,
//     cookies and base64 and all;
//   * PEER_JWKS_URLS actually federating - each instance's /jwks.json fetched
//     fresh and checked for the other two instances' signing keys, not just
//     each instance verifying its own id_token against its own JWKS.
//
// It is deliberately a browser rather than a library: it fills the same forms,
// keeps cookies the same way, and reads the one-time code off the page the way
// a person would read it out of their inbox.

import { webcrypto as crypto } from 'node:crypto';

const INSTANCES = [
  {
    name: 'sag-node',
    title: 'Node, in a container',
    issuer: 'http://localhost:8791',
    clientId: 'rp-node',
    redirectUri: 'http://localhost:8801/callback',
    stub: 'http://localhost:8801',
  },
  {
    name: 'sag-workers',
    title: 'Cloudflare Workers, on workerd',
    issuer: 'http://localhost:8792',
    clientId: 'rp-workers',
    redirectUri: 'http://localhost:8802/callback',
    stub: 'http://localhost:8802',
  },
  {
    name: 'sag-lambda',
    title: 'AWS Lambda, behind an API Gateway event',
    issuer: 'http://localhost:8793',
    clientId: 'rp-lambda',
    redirectUri: 'http://localhost:8803/callback',
    stub: 'http://localhost:8803',
    // The one confidential client: its record in the bucket holds a digest.
    clientSecret: 'r-cs-local-stack-rp-lambda-secret-not-for-production',
  },
  {
    // The Node instance again, reached by a client nobody registered: its id is
    // the URL of the metadata document it serves, which SAG fetches. Worth its
    // own entry rather than folding into sag-node, because what is being tested
    // is the client, and its failure modes are its own - a document SAG cannot
    // reach, an origin the deployment does not accept, redirect URIs that do
    // not share the document's origin.
    name: 'rp-cimd',
    title: 'a client that describes itself, registered nowhere',
    issuer: 'http://localhost:8791',
    clientId: 'http://localhost:8804/.well-known/client.json',
    redirectUri: 'http://localhost:8804/callback',
    stub: 'http://localhost:8804',
    // The document is the registration, so checking it is part of checking the
    // client: SAG reads exactly this and nothing else.
    metadataDocument: true,
  },
  {
    name: 'sag-local',
    title: 'Node, with file-backed local identities',
    issuer: 'http://localhost:8794',
    clientId: 'rp-local',
    redirectUri: 'http://localhost:8805/callback',
    stub: 'http://localhost:8805',
    auth: {
      email: process.env.SAG_LOCAL_STACK_EMAIL || 'local.user@local.test',
      password: process.env.SAG_LOCAL_STACK_PASSWORD || 'local-stack-password-not-for-production',
      // Public test seed generated with the fixture. An override makes it
      // possible to replace that fixture without changing this script.
      totpSecret: process.env.SAG_LOCAL_STACK_TOTP_SECRET || 'CMTADK6EESB3ORC5GFPEWRXOYBQMMWCX',
    },
  },
];

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const random = (n) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const decodeEntities = (s) =>
  s
    .replaceAll('&amp;', '&')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'");

const JOSE = {
  ES256: { import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } },
  ES384: { import: { name: 'ECDSA', namedCurve: 'P-384' }, verify: { name: 'ECDSA', hash: 'SHA-384' } },
  RS256: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: 'RSASSA-PKCS1-v1_5' },
  'ML-DSA-44': { import: { name: 'ML-DSA-44' }, verify: { name: 'ML-DSA-44' } },
  'ML-DSA-65': { import: { name: 'ML-DSA-65' }, verify: { name: 'ML-DSA-65' } },
  'ML-DSA-87': { import: { name: 'ML-DSA-87' }, verify: { name: 'ML-DSA-87' } },
};

/** A browser: one cookie jar, no automatic redirects, forms posted as forms. */
function browser() {
  const jar = new Map();
  const call = async (url, init = {}) => {
    const headers = new Headers(init.headers || {});
    if (jar.size) headers.set('cookie', [...jar].map(([k, v]) => k + '=' + v).join('; '));
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    for (const raw of res.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(raw)) jar.delete(name);
      else jar.set(name, pair.slice(eq + 1).trim());
    }
    return res;
  };
  return {
    jar,
    get: (url) => call(url),
    form: (url, fields) =>
      call(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(fields).toString(),
      }),
  };
}

const field = (html, name) => {
  const m =
    html.match(new RegExp('name="' + name + '"\\s+value="([^"]*)"')) ||
    html.match(new RegExp('value="([^"]*)"\\s+name="' + name + '"'));
  return m ? decodeEntities(m[1]) : undefined;
};

/** The development notice on the OTP page, which is where the code appears. */
const devCode = (html) => html.match(/<code>([0-9A-Z]{6,12})<\/code>/)?.[1];

/** Decode an RFC 4648 base32 TOTP seed without adding a stack-only package. */
function base32(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(value || '').toUpperCase().replace(/[\s=-]/g, '');
  if (!clean) throw new Error('the local TOTP seed is empty');
  let bits = 0;
  let held = 0;
  const bytes = [];
  for (const char of clean) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error('the local TOTP seed is not base32');
    held = (held << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((held >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

async function totpCode(secret, step) {
  const key = await crypto.subtle.importKey('raw', base32(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1000000).padStart(6, '0');
}

const localTotpSteps = new Map();

async function nextLocalTotp(instance, afterStep) {
  if (!instance.auth?.totpSecret) return undefined;
  let step = Math.floor(Date.now() / 30000);
  const previous = afterStep ?? localTotpSteps.get(instance.name);
  if (previous !== undefined && step <= previous) {
    // A used TOTP step is persisted in the fixture's writable copy. A verifier
    // rerun in the same 30-second window must wait for a genuinely new code,
    // not weaken the store's replay defence or require the volume to be reset.
    await new Promise((resolve) => setTimeout(resolve, (previous + 1) * 30000 - Date.now() + 250));
    step = Math.floor(Date.now() / 30000);
  }
  localTotpSteps.set(instance.name, step);
  return { code: await totpCode(instance.auth.totpSecret, step), step };
}

async function submitLocalMfa(instance, agent, page) {
  const generated = await nextLocalTotp(instance);
  if (!generated) {
    throw new Error('the local fixture requires TOTP; set SAG_LOCAL_STACK_TOTP_SECRET to its base32 seed');
  }
  let response = await agent.form(new URL('/authorize/local-mfa', instance.issuer).toString(), {
    tx: field(page, 'tx'),
    code: generated.code,
  });
  if (response.status === 303) return response;

  const retryPage = await response.text();
  const retryTx = field(retryPage, 'tx');
  if (!response.ok || !retryTx || !retryPage.includes('name="code"')) {
    throw new Error('/authorize/local-mfa answered ' + response.status + ':\n' + retryPage.slice(0, 400));
  }

  const retry = await nextLocalTotp(instance, generated.step);
  response = await agent.form(new URL('/authorize/local-mfa', instance.issuer).toString(), {
    tx: retryTx,
    code: retry.code,
  });
  return response;
}

async function pkce() {
  const verifier = random(32);
  const digest = await crypto.subtle.digest('SHA-256', Buffer.from(verifier, 'utf8'));
  return { verifier, challenge: b64u(new Uint8Array(digest)) };
}

async function verifyIdToken(token, { jwks, issuer, clientId, nonce }) {
  const [h, p, sig] = token.split('.');
  if (!sig) throw new Error('the id_token is not a compact JWS');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));

  const params = JOSE[header.alg];
  if (!params) throw new Error('unexpected id_token algorithm ' + header.alg);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('the JWKS has no key with kid ' + header.kid);

  const key = await crypto.subtle.importKey('jwk', { ...jwk, ext: true }, params.import, true, ['verify']);
  const ok = await crypto.subtle.verify(
    params.verify,
    key,
    Buffer.from(sig, 'base64url'),
    Buffer.from(h + '.' + p, 'utf8'),
  );
  if (!ok) throw new Error('the id_token signature does not verify against the published JWKS');

  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== issuer) throw new Error('iss is ' + claims.iss + ', expected ' + issuer);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) throw new Error('aud does not include ' + clientId);
  if (claims.exp <= now) throw new Error('the id_token has already expired');
  if (nonce !== undefined && claims.nonce !== nonce) throw new Error('nonce mismatch');
  return { header, claims };
}

function tokenRequest(instance, body) {
  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  if (instance.clientSecret) {
    // RFC 6749 section 2.3.1: both halves form-urlencoded, then base64.
    headers.authorization =
      'Basic ' +
      Buffer.from(encodeURIComponent(instance.clientId) + ':' + encodeURIComponent(instance.clientSecret)).toString('base64');
  }
  return { method: 'POST', headers, body: new URLSearchParams(body).toString() };
}

/** One sign-in, screen by screen, ending in a redirect back to the client. */
async function signIn(instance, agent, meta, { email, extra = {} } = {}) {
  const { verifier, challenge } = await pkce();
  const state = random(16);
  const nonce = random(16);

  const url = new URL(meta.authorization_endpoint);
  for (const [k, v] of Object.entries({
    response_type: 'code',
    client_id: instance.clientId,
    redirect_uri: instance.redirectUri,
    scope: 'openid email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  })) {
    url.searchParams.set(k, v);
  }

  const first = await agent.get(url.toString());
  if (first.status === 303) {
    // An existing session answered without showing a page, which is the point
    // of prompt=none. The caller decides whether that was expected.
    return { silent: true, location: new URL(first.headers.get('location')), verifier, state, nonce };
  }
  if (!first.ok) throw new Error('/authorize answered ' + first.status);

  const emailPage = await first.text();
  const tx = field(emailPage, 'tx');
  if (!tx) throw new Error('the first page carried no transaction:\n' + emailPage.slice(0, 400));

  const routed = await agent.form(new URL('/authorize/email', instance.issuer).toString(), { tx, email });
  if (!routed.ok) throw new Error('/authorize/email answered ' + routed.status);
  const routedPage = await routed.text();
  let done;
  let code;

  if (instance.auth) {
    if (!routedPage.includes('name="password"')) {
      throw new Error('the local account did not reach the password page:\n' + routedPage.slice(0, 400));
    }
    const password = await agent.form(new URL('/authorize/local-password', instance.issuer).toString(), {
      tx: field(routedPage, 'tx'),
      password: instance.auth.password,
    });
    if (password.status === 303) {
      done = password;
    } else {
      if (!password.ok) throw new Error('/authorize/local-password answered ' + password.status);
      const mfaPage = await password.text();
      if (!mfaPage.includes('name="code"')) {
        throw new Error('the local password did not complete or reach the verification-code page:\n' + mfaPage.slice(0, 400));
      }
      done = await submitLocalMfa(instance, agent, mfaPage);
    }
  } else {
    code = devCode(routedPage);
    if (!code) throw new Error('no development code on the code page:\n' + routedPage.slice(0, 400));
    done = await agent.form(new URL('/authorize/otp', instance.issuer).toString(), {
      tx: field(routedPage, 'tx'),
      code,
    });
  }
  if (done.status !== 303) throw new Error('expected a redirect back to the client, got ' + done.status);
  const location = new URL(done.headers.get('location'));
  if (location.searchParams.get('error')) {
    throw new Error('SAG refused: ' + location.searchParams.get('error_description'));
  }
  if (location.searchParams.get('state') !== state) throw new Error('state did not come back intact');
  // RFC 9207, which is what tells a client the response came from the provider
  // it asked rather than one that intercepted the redirect.
  if (location.searchParams.get('iss') !== meta.issuer) throw new Error('iss parameter is missing or wrong');
  return { silent: false, location, verifier, state, nonce, code };
}

/**
 * The same sign-in, but driven through the stub application rather than by this
 * script pretending to be one.
 *
 * Worth doing separately because everything above tests what SAG decides, and
 * this tests whether an application can actually use it: the discovery
 * document, the JWKS fetch, the code exchange and the id_token verification all
 * happen in the stub's own process, and a mistake in any of them looks like a
 * working instance right up until the callback.
 *
 * One cookie jar for both origins, which is also what a browser does: cookies
 * are scoped to a host and ignore the port, so the stack's sessions genuinely
 * do share a jar on localhost. The names differ, so nothing collides.
 */
async function checkStub(instance, email, agent = browser()) {
  // Reuse the authenticated browser for local MFA and ask for a silent
  // authorisation. That still exercises the relying party's discovery, token
  // exchange and id_token verification without trying to reuse a TOTP step,
  // which the identity store correctly refuses.
  let res = await agent.get(instance.stub + '/start' + (instance.auth ? '?prompt=none' : ''));
  let hops = 0;

  while (hops < 12) {
    hops += 1;
    if (res.status === 303 || res.status === 302) {
      res = await agent.get(new URL(res.headers.get('location'), instance.stub).toString());
      continue;
    }
    if (!res.ok) {
      // The stub renders what went wrong on its error page, and that sentence
      // is the whole diagnosis - a bare status code is not.
      const body = await res.text();
      const reason = body.match(/<strong>Sign-in failed<\/strong><br>([^<]*)/)?.[1];
      throw new Error(
        'the stub or the instance answered ' + res.status + (reason ? ': ' + decodeEntities(reason) : '\n' + body.slice(0, 300)),
      );
    }

    const html = await res.text();
    // Whichever screen we are on, answer it the way a person would.
    if (html.includes('name="tx"') && /type="email"|name="email"/.test(html)) {
      res = await agent.form(instance.issuer + '/authorize/email', { tx: field(html, 'tx'), email });
      continue;
    }
    if (html.includes('name="tx"') && html.includes('name="password"') && instance.auth) {
      res = await agent.form(instance.issuer + '/authorize/local-password', {
        tx: field(html, 'tx'),
        password: instance.auth.password,
      });
      continue;
    }
    const code = devCode(html);
    if (html.includes('name="tx"') && code) {
      res = await agent.form(instance.issuer + '/authorize/otp', { tx: field(html, 'tx'), code });
      continue;
    }
    if (html.includes('name="tx"') && html.includes('name="code"') && instance.auth) {
      res = await submitLocalMfa(instance, agent, html);
      continue;
    }
    if (html.includes('Signed in')) {
      if (!html.includes(email)) throw new Error('the stub is signed in as somebody else');
      return;
    }
    throw new Error('the stub stopped on a page this script does not recognise:\n' + html.slice(0, 400));
  }
  throw new Error('the stub never finished signing in');
}

async function checkInstance(instance) {
  const notes = [];
  const agent = browser();
  // A fresh address per run, so repeated runs are not fighting the send limits
  // an instance is meant to enforce.
  const email = instance.auth?.email || 'stack-' + random(4).toLowerCase().replace(/[^a-z0-9]/g, '') + '@example.test';

  // --- What the instance says it is ----------------------------------------
  const healthRes = await fetch(instance.issuer + '/healthz');
  if (!healthRes.ok) throw new Error('/healthz answered ' + healthRes.status);
  const health = await healthRes.json();
  if (health.issuer !== instance.issuer) {
    throw new Error('this instance calls itself ' + health.issuer + ', not ' + instance.issuer);
  }
  notes.push('signing ' + health.signing.primary.backend + ' / ' + health.signing.primary.alg);
  notes.push('clients ' + health.clients.store + (health.clients.static ? ' + ' + health.clients.static + ' static' : ''));
  if (health.signing.primary.ephemeral) throw new Error('the signing key is ephemeral, so nothing here would survive a restart');
  if (Boolean(health.routes?.local) !== Boolean(instance.auth)) {
    throw new Error('the health document reports local authentication as ' + Boolean(health.routes?.local));
  }
  // Whether a state store is configured is no longer published, and does not
  // need to be: the replay attempt further down is the real test of it.

  // A client that describes itself: the document has to be readable at the URL
  // that *is* the client id, and has to say the things SAG would refuse it for.
  if (instance.metadataDocument) {
    const docRes = await fetch(instance.clientId);
    if (!docRes.ok) throw new Error('the metadata document answered ' + docRes.status);
    const doc = await docRes.json();
    if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) {
      throw new Error('the metadata document declares no redirect URIs');
    }
    for (const uri of doc.redirect_uris) new URL(uri);
    if (doc.token_endpoint_auth_method !== 'none') {
      throw new Error('a document served in public must not claim a secret-based auth method');
    }
    notes.push('registered nowhere: ' + doc.redirect_uris.length + ' redirect URI(s)');
  }

  const metaRes = await fetch(instance.issuer + '/.well-known/openid-configuration');
  const meta = await metaRes.json();
  if (meta.issuer !== instance.issuer) throw new Error('discovery calls this instance ' + meta.issuer);
  const jwks = await (await fetch(meta.jwks_uri)).json();
  if (!jwks.keys?.length) throw new Error('the JWKS is empty');

  // --- Sign in -------------------------------------------------------------
  const first = await signIn(instance, agent, meta, { email });
  if (first.silent) throw new Error('a fresh browser was signed in already');

  const tokenRes = await fetch(
    meta.token_endpoint,
    tokenRequest(instance, {
      grant_type: 'authorization_code',
      code: first.location.searchParams.get('code'),
      redirect_uri: instance.redirectUri,
      client_id: instance.clientId,
      code_verifier: first.verifier,
    }),
  );
  const tokens = await tokenRes.json();
  if (!tokenRes.ok) throw new Error('the token exchange failed: ' + (tokens.error_description || tokens.error));

  const { header, claims } = await verifyIdToken(tokens.id_token, {
    jwks,
    issuer: instance.issuer,
    clientId: instance.clientId,
    nonce: first.nonce,
  });
  if (claims.email !== email) throw new Error('the id_token is for ' + claims.email + ', not ' + email);
  if (instance.auth) {
    if ('email_verified' in claims) throw new Error('a local password asserted email_verified');
    const expectedAcr = instance.auth.totpSecret ? 'urn:sag:acr:local-mfa' : 'urn:sag:acr:local-password';
    if (claims.acr !== expectedAcr) throw new Error('local acr is ' + claims.acr + ', expected ' + expectedAcr);
    const expectedAmr = instance.auth.totpSecret ? ['pwd', 'otp', 'mfa'] : ['pwd'];
    for (const method of expectedAmr) {
      if (!claims.amr?.includes(method)) throw new Error('local amr does not include ' + method);
    }
    notes.push('local ' + (instance.auth.totpSecret ? 'password + TOTP' : 'password'));
  } else if (claims.email_verified !== true) {
    throw new Error('email-code authentication did not assert email_verified');
  }
  notes.push('id_token ' + header.alg + ' kid ' + String(header.kid).slice(0, 12));
  notes.push('acr ' + claims.acr);

  // --- The code is single use ----------------------------------------------
  //
  // The only check here that reaches all the way into the platform: an
  // in-process map, a Durable Object, and a DynamoDB conditional write have to
  // give the same answer.
  const replay = await fetch(
    meta.token_endpoint,
    tokenRequest(instance, {
      grant_type: 'authorization_code',
      code: first.location.searchParams.get('code'),
      redirect_uri: instance.redirectUri,
      client_id: instance.clientId,
      code_verifier: first.verifier,
    }),
  );
  if (replay.ok) throw new Error('the authorisation code was accepted twice: the state store is not doing its job');
  notes.push('replay refused (' + (await replay.json()).error + ')');

  // --- The session survives, and prompt=none uses it -----------------------
  const silent = await signIn(instance, agent, meta, { email, extra: { prompt: 'none' } });
  if (!silent.silent) throw new Error('prompt=none showed a page instead of using the existing session');
  if (!silent.location.searchParams.get('code')) {
    throw new Error('prompt=none answered ' + silent.location.searchParams.get('error') + ' rather than a code');
  }
  notes.push('prompt=none silent');

  // --- userinfo, with the access token -------------------------------------
  const userinfo = await fetch(meta.userinfo_endpoint, {
    headers: { authorization: 'Bearer ' + tokens.access_token },
  });
  const profile = await userinfo.json();
  if (!userinfo.ok) throw new Error('/userinfo answered ' + userinfo.status);
  if (!claims.sub) throw new Error('the id_token carries no sub, so SUBJECT_TYPE did not take effect');
  if (profile.sub !== claims.sub) throw new Error('/userinfo is about a different subject');
  if (instance.auth && 'email_verified' in profile) throw new Error('/userinfo asserted email_verified for a local password');
  if (!instance.auth && profile.email_verified !== true) throw new Error('/userinfo omitted email_verified after an email code');

  // And once more through the application, in its own browser.
  await checkStub(instance, instance.auth ? email : 'stub-' + email, instance.auth ? agent : undefined);
  notes.push('the stub at ' + instance.stub + ' signed in too');

  return { notes, kid: header.kid };
}

// ---------------------------------------------------------------------------
// The peer mesh: sag-node, sag-workers and sag-lambda each name the other two
// in PEER_JWKS_URLS (see compose.yml and workers/wrangler.dev.toml), so every
// instance's /jwks.json is meant to describe all three signers. checkInstance
// above already proves each instance's own id_token verifies against its own
// JWKS; this proves the federation itself - that the *other* two instances'
// JWKS documents carry a key each signed with, fetched fresh rather than
// reused from /healthz's cache-only view.
const PEER_MESH = ['sag-node', 'sag-workers', 'sag-lambda'];

async function checkFederation(kidByName) {
  const present = PEER_MESH.filter((name) => kidByName[name]);
  if (present.length < 2) {
    return { skipped: 'fewer than two peers of the mesh ran (' + (present.join(', ') || 'none') + ')' };
  }
  const jwksByName = {};
  for (const name of present) {
    const instance = INSTANCES.find((i) => i.name === name);
    const res = await fetch(instance.issuer + '/.well-known/jwks.json');
    if (!res.ok) throw new Error(name + "'s /jwks.json answered " + res.status);
    jwksByName[name] = await res.json();
  }
  const notes = [];
  for (const name of present) {
    const kids = new Set((jwksByName[name].keys || []).map((k) => k.kid));
    const others = present.filter((p) => p !== name);
    for (const other of others) {
      if (!kids.has(kidByName[other])) {
        throw new Error(name + "'s /jwks.json does not carry " + other + "'s key (kid " + kidByName[other] + ')');
      }
    }
    notes.push(name + ' vouches for ' + others.join(' and '));
  }
  return { notes };
}

// ---------------------------------------------------------------------------

const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const chosen = only.length ? INSTANCES.filter((i) => only.includes(i.name)) : INSTANCES;
if (chosen.length === 0) {
  console.error('No such instance. Try: ' + INSTANCES.map((i) => i.name).join(', '));
  process.exit(2);
}

console.log('\n  Signing in against ' + chosen.length + ' instance(s).\n');
let failed = 0;
const kidByName = {};
for (const instance of chosen) {
  const started = Date.now();
  try {
    const { notes, kid } = await checkInstance(instance);
    if (kid) kidByName[instance.name] = kid;
    console.log('  PASS  ' + instance.name.padEnd(12) + instance.title + ' (' + (Date.now() - started) + 'ms)');
    for (const note of notes) console.log('        ' + note);
  } catch (err) {
    failed += 1;
    console.log('  FAIL  ' + instance.name.padEnd(12) + instance.title);
    console.log('        ' + String(err.message).split('\n').join('\n        '));
  }
  console.log('');
}

try {
  const federation = await checkFederation(kidByName);
  if (federation.skipped) {
    console.log('  SKIP  peer mesh     ' + federation.skipped);
  } else {
    console.log('  PASS  peer mesh     every instance that ran vouches for the others');
    for (const note of federation.notes) console.log('        ' + note);
  }
} catch (err) {
  failed += 1;
  console.log('  FAIL  peer mesh     PEER_JWKS_URLS is not federating correctly');
  console.log('        ' + String(err.message));
}
console.log('');

if (failed) {
  console.error('  ' + failed + ' of ' + chosen.length + ' instance(s) failed. Their logs are the next place to look:');
  console.error('    ./stack.sh logs <name>\n');
  process.exit(1);
}
console.log('  Every instance signed somebody in, refused the code a second time, and reused the session.\n');
