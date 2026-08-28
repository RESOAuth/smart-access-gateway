#!/usr/bin/env node
// A worked relying party, so SAG can be tried without writing a client first.
//
//   Terminal one:  npm run dev
//   Terminal two:  npm run example
//   Browser:       http://127.0.0.1:8788
//
// This is also the shortest honest answer to "what do I have to implement?".
// There is no library here and no dependency: discovery, PKCE, the redirect,
// the code exchange, and verifying the id_token against the published JWKS.
// About a hundred lines of actual work.
//
// It can be any of the three kinds of client SAG accepts, which is the same
// hundred lines either way:
//
//   default                                  a public client, registered by id
//   EXAMPLE_CLIENT_SECRET=...                confidential, client_secret_basic
//   EXAMPLE_USE_CIMD_AND_PUBLIC_CLIENT=1     public, and registered nowhere: its
//                                            client id is the URL of a metadata
//                                            document it serves itself
//
// It is a demonstration, not a template to copy wholesale. The two places a
// real application would differ are marked.

import { createServer } from 'node:http';
import { webcrypto as crypto } from 'node:crypto';

const PORT = Number(process.env.EXAMPLE_PORT || 8788);
const HOST = process.env.EXAMPLE_HOST || '127.0.0.1';
const trim = (value) => String(value).replace(/\/+$/, '');

// Where the browser reaches this application, which in a container is not the
// address it binds to. The redirect_uri has to be the one the browser can
// actually follow, so this is the value that matters.
const ORIGIN = trim(process.env.EXAMPLE_PUBLIC_ORIGIN || 'http://127.0.0.1:' + PORT);
const ISSUER = trim(process.env.SAG_ISSUER || 'http://127.0.0.1:8787');

// Split horizon, for when SAG is not reachable at the same address from here as
// from the browser - a load balancer in front of it, a private network behind
// it. The front channel - /authorize, sign out - must stay exactly as SAG
// published it, because a browser follows those and has its own view of the
// network. The back channel - the token endpoint, the JWKS, /userinfo - is what
// this process fetches, so that is what gets rewritten. Unset when the two
// addresses are the same, which is the normal case and the one the local stack
// arranges deliberately.
const BACKCHANNEL = trim(process.env.EXAMPLE_BACKCHANNEL_ORIGIN || ISSUER);
const backchannel = (url) => (url.startsWith(ISSUER) ? BACKCHANNEL + url.slice(ISSUER.length) : url);

// Failures that happened before the request was sent, and are therefore safe
// to repeat even for a POST: a name that did not resolve, a refused connection,
// a socket dropped while idle.
const NEVER_ARRIVED = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'UND_ERR_SOCKET', 'ETIMEDOUT']);

/**
 * Fetch over the back channel, retrying a connection that never opened.
 *
 * This is the second place a real application would differ from the shortest
 * possible example, and it is not optional. Between an application and its
 * identity provider there is always something that blinks - a container DNS
 * resolver, a load balancer dropping an idle socket, an instance being
 * replaced - and a person who typed their code correctly should not be told
 * their sign-in failed because a name did not resolve once. Note what is *not*
 * retried: anything the server answered, however badly. A 500 from the token
 * endpoint is a real answer and repeating it would only ask twice.
 */
async function backchannelFetch(url, init = {}, attempt = 1) {
  try {
    return await fetch(backchannel(url), init);
  } catch (err) {
    if (attempt < 3 && NEVER_ARRIVED.has(err.cause?.code)) {
      console.warn('  retrying ' + url + ' after ' + err.cause.code);
      await new Promise((resolve) => setTimeout(resolve, 150 * attempt));
      return backchannelFetch(url, init, attempt + 1);
    }
    throw err;
  }
}

// A client that describes itself.
//
// Set EXAMPLE_USE_CIMD_AND_PUBLIC_CLIENT=1 and this application stops being
// registered anywhere: its client id becomes the URL of a metadata document it
// serves itself, and SAG fetches it. The URL *is* the identity, which is what
// makes it work with no registration step at either end - only somebody who
// controls this origin can change what this client claims to be.
//
// Two consequences follow from that, and both are enforced below rather than
// documented and hoped for. The document has to be at an address SAG can
// actually fetch and the browser can actually reach, so it is built from
// EXAMPLE_PUBLIC_ORIGIN and not from the address this process binds to. And
// the configured metadata publisher is trusted to declare its redirect URIs:
// otherwise publishing a document would be a way to have codes delivered
// somewhere else.
const USE_CIMD_AND_PUBLIC_CLIENT = process.env.EXAMPLE_USE_CIMD_AND_PUBLIC_CLIENT === '1';

const CLIENT_ID = USE_CIMD_AND_PUBLIC_CLIENT
  ? ORIGIN + '/.well-known/client.json'
  : process.env.EXAMPLE_CLIENT_ID || 'sag-dev-client';

// Serve the document only when the client id is a URL on this origin - which it
// is in CIMD mode, and may also be if one was configured by hand. A URL
// belonging to somebody else is their document to serve, not ours.
const CIMD_PATH = CLIENT_ID.startsWith(ORIGIN + '/') ? new URL(CLIENT_ID).pathname : undefined;

// Only for a confidential client: a record with a client_secret_digest and
// token_endpoint_auth_method of client_secret_basic. A public client leaves
// this unset and relies on PKCE, which is the right default for a browser or
// mobile application.
const CLIENT_SECRET = process.env.EXAMPLE_CLIENT_SECRET || '';
const LABEL = process.env.EXAMPLE_LABEL || 'Example relying party';
// A cookie is scoped to a host and ignores the port, so two applications on
// two ports of localhost share one cookie jar and would overwrite each other's
// session. Distinct names are the fix, and the same is true of the instances
// they sign in against: see SESSION_COOKIE_NAME in docs/configuration.md.
const COOKIE = process.env.EXAMPLE_COOKIE_NAME || 'example_session';
// Sibling applications to link to, as `label=url` pairs. The local stack uses
// it so that one browser tab can reach every instance.
const PEERS = (process.env.EXAMPLE_PEERS || '')
  .split(',')
  .map((pair) => pair.trim())
  .filter(Boolean)
  .map((pair) => {
    const idx = pair.indexOf('=');
    return idx < 1 ? undefined : { label: pair.slice(0, idx), url: pair.slice(idx + 1) };
  })
  .filter(Boolean);
const REDIRECT_URI = ORIGIN + '/callback';

// A real application would keep these server-side per browser session. Holding
// them in a module-level map is fine for one person on one machine.
const pending = new Map();
const sessions = new Map();

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const random = (n) => b64u(crypto.getRandomValues(new Uint8Array(n)));

async function sha256(input) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from(input, 'utf8')));
}

// --- Discovery -------------------------------------------------------------

let metadataCache;
async function metadata() {
  if (metadataCache) return metadataCache;
  const res = await backchannelFetch(ISSUER + '/.well-known/openid-configuration');
  if (!res.ok) throw new Error('could not read discovery document: HTTP ' + res.status);
  metadataCache = await res.json();
  return metadataCache;
}

async function jwks() {
  const res = await backchannelFetch((await metadata()).jwks_uri);
  if (!res.ok) throw new Error('could not read JWKS: HTTP ' + res.status);
  return res.json();
}

// --- Verifying an id_token -------------------------------------------------

const JOSE_PARAMS = {
  ES256: { import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } },
  ES384: { import: { name: 'ECDSA', namedCurve: 'P-384' }, verify: { name: 'ECDSA', hash: 'SHA-384' } },
  RS256: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: 'RSASSA-PKCS1-v1_5' },
  'ML-DSA-44': { import: { name: 'ML-DSA-44' }, verify: { name: 'ML-DSA-44' } },
  'ML-DSA-65': { import: { name: 'ML-DSA-65' }, verify: { name: 'ML-DSA-65' } },
  'ML-DSA-87': { import: { name: 'ML-DSA-87' }, verify: { name: 'ML-DSA-87' } },
};

/**
 * Verify an id_token properly: signature first, then every claim.
 *
 * Skipping any of these is how relying parties get compromised. The nonce in
 * particular is what ties this token to the request this browser started.
 */
async function verifyIdToken(token, { nonce, clientId }) {
  const [headerPart, payloadPart, signaturePart] = token.split('.');
  if (!signaturePart) throw new Error('not a compact JWS');
  const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));

  const params = JOSE_PARAMS[header.alg];
  if (!params) throw new Error('unsupported id_token algorithm: ' + header.alg);

  const keys = (await jwks()).keys;
  const jwk = keys.find((k) => k.kid === header.kid) || (keys.length === 1 ? keys[0] : undefined);
  if (!jwk) throw new Error('no key in the JWKS matches kid ' + header.kid);

  const key = await crypto.subtle.importKey('jwk', { ...jwk, ext: true }, params.import, true, ['verify']);
  const ok = await crypto.subtle.verify(
    params.verify,
    key,
    Buffer.from(signaturePart, 'base64url'),
    Buffer.from(headerPart + '.' + payloadPart, 'utf8'),
  );
  if (!ok) throw new Error('the id_token signature does not verify');

  const meta = await metadata();
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== meta.issuer) throw new Error('unexpected issuer ' + claims.iss);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) throw new Error('this token is not for us');
  if (claims.exp + 60 < now) throw new Error('the id_token has expired');
  if (claims.nonce !== nonce) throw new Error('nonce mismatch: this token is not for this request');

  return { header, claims };
}

// --- The client metadata document ------------------------------------------

/**
 * What this client says it is, at the URL that is its client id.
 *
 * This is the whole of "registration" for a CIMD client: RFC 7591 client
 * metadata, served as JSON. SAG uses the URL it fetched as the client id; a
 * document may use a different `client_id`, for example for a native client
 * whose redirect URI is on localhost. Its publisher chooses the redirect URIs.
 *
 * There is no secret in here and there never can be: the document is public by
 * construction, so PKCE is what protects the code, and SAG requires it of a
 * CIMD client whatever the document says. Publishing a `jwks_uri` instead is
 * how such a client authenticates at the token endpoint, and that is the one
 * way it stops being public.
 */
const clientMetadata = () => ({
  client_id: CLIENT_ID,
  client_name: LABEL,
  client_uri: ORIGIN,
  redirect_uris: [REDIRECT_URI],
  post_logout_redirect_uris: [ORIGIN + '/'],
  grant_types: ['authorization_code'],
  response_types: ['code'],
  token_endpoint_auth_method: 'none',
  scope: 'openid email profile',
});

// --- The flow --------------------------------------------------------------

async function startSignIn(extra = {}) {
  const meta = await metadata();
  const verifier = random(32);
  const challenge = b64u(await sha256(verifier));
  const state = random(16);
  const nonce = random(16);
  pending.set(state, { verifier, nonce, startedAt: Date.now() });

  const url = new URL(meta.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  // profile as well as email, so the example shows what a relying party is
  // actually given: a display name and a picture when SAG has them, and
  // nothing when it does not.
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  for (const [k, v] of Object.entries(extra)) url.searchParams.set(k, v);
  return url.toString();
}

async function finishSignIn(params) {
  const state = params.get('state');
  const record = state ? pending.get(state) : undefined;
  // An unrecognised state means this response does not belong to a request we
  // started, which is the CSRF check. Never skip it.
  if (!record) throw new Error('unrecognised state: this response did not come from a request we started');
  pending.delete(state);

  const error = params.get('error');
  if (error) throw new Error('SAG refused: ' + error + ' - ' + (params.get('error_description') || ''));

  const meta = await metadata();
  // RFC 9207: confirms the response came from the provider we asked.
  if (params.get('iss') && params.get('iss') !== meta.issuer) {
    throw new Error('the iss parameter does not match the issuer we asked');
  }

  const res = await backchannelFetch(meta.token_endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      // RFC 6749 section 2.3.1: both halves are form-urlencoded before they
      // are base64'd, which matters the moment a secret contains a colon.
      ...(CLIENT_SECRET
        ? {
            authorization:
              'Basic ' +
              Buffer.from(encodeURIComponent(CLIENT_ID) + ':' + encodeURIComponent(CLIENT_SECRET)).toString('base64'),
          }
        : {}),
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.get('code'),
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: record.verifier,
    }).toString(),
  });
  const tokens = await res.json();
  if (!res.ok) throw new Error('token exchange failed: ' + (tokens.error_description || tokens.error));

  const { header, claims } = await verifyIdToken(tokens.id_token, {
    nonce: record.nonce,
    clientId: CLIENT_ID,
  });
  return { tokens, header, claims, jwksUri: (await metadata()).jwks_uri };
}

// --- Pages -----------------------------------------------------------------

const esc = (v) =>
  String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');

const page = (title, body) => `<!DOCTYPE html>
<html lang="en-GB"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} - ${esc(LABEL)}</title>
<style>
  :root { color-scheme: light dark }
  body { margin:0; padding:2rem 1rem; font:1rem/1.55 system-ui,sans-serif;
         max-width:44rem; margin-inline:auto }
  h1 { font-size:1.5rem; margin:0 0 .5rem }
  p.lede { color:#666; margin:0 0 1.5rem }
  a.btn { display:inline-block; padding:.6rem 1rem; background:#1f4fd8; color:#fff;
          border-radius:.375rem; text-decoration:none; font-weight:600; margin:0 .5rem .5rem 0 }
  a.btn.alt { background:transparent; color:inherit; border:1px solid currentColor; font-weight:500 }
  pre { background:rgba(127,127,127,.12); padding:1rem; border-radius:.375rem;
        overflow-x:auto; font-size:.875rem }
  dl { display:grid; grid-template-columns:max-content 1fr; gap:.35rem 1rem; margin:0 0 1.5rem }
  dt { font-weight:600 } dd { margin:0; overflow-wrap:anywhere }
  .err { padding:1rem; border:1px solid #a4102a; color:#a4102a; border-radius:.375rem }
</style></head><body>${body}</body></html>
`;

const peers = () =>
  PEERS.length
    ? `<hr style="margin:2rem 0 1rem;border:0;border-top:1px solid rgba(127,127,127,.3)">
       <p class="lede">Also running: ${PEERS.map((p) => `<a href="${esc(p.url)}">${esc(p.label)}</a>`).join(' &middot; ')}</p>`
    : '';

const home = (session) =>
  page(
    LABEL,
    session
      ? `<h1>Signed in</h1>
       <p class="lede">This application verified the id_token itself, against the keys at
         <code>${esc(session.jwksUri || ISSUER)}</code> - the location the discovery document gave it,
         not one hard-coded here.</p>
       <dl>
         <dt>Email</dt><dd>${esc(session.claims.email)}</dd>
         ${
           session.claims.name
             ? '<dt>Name</dt><dd>' +
               esc(session.claims.name) +
               // A name SAG guessed from the address rather than one an upstream
               // asserted. Saying so is the whole point of the claim: this is a
               // default to confirm, not a fact.
               (session.claims['urn:sag:name_inferred'] ? ' <small>(guessed from the address)</small>' : '') +
               '</dd>'
             : ''
         }
         ${session.claims.picture ? '<dt>Picture</dt><dd><img src="' + esc(session.claims.picture) + '" alt="" width="40" height="40" style="border-radius:50%;vertical-align:middle"></dd>' : ''}
         <dt>Subject</dt><dd><code>${esc(session.claims.sub)}</code></dd>
         <dt>Signed with</dt><dd><code>${esc(session.header.alg)}</code> (kid <code>${esc(session.header.kid)}</code>)</dd>
         <dt>How they signed in</dt><dd><code>${esc(session.claims.acr)}</code></dd>
         <dt>Methods used</dt><dd><code>${esc((session.claims.amr || []).join(', '))}</code></dd>
         <dt>Session id</dt><dd><code>${esc(session.claims.sid)}</code></dd>
       </dl>
       <p>
         <a class="btn alt" href="/start?prompt=none">Silent re-authentication</a>
         <a class="btn alt" href="/start?prompt=consent">Ask to confirm the account</a>
         <a class="btn alt" href="/start?prompt=login">Force a fresh sign-in</a>
         <a class="btn alt" href="/start?acr_values=urn:sag:acr:federated-mfa">Demand MFA</a>
         <a class="btn alt" href="/userinfo">Call /userinfo</a>
         <a class="btn alt" href="/logout">Sign out</a>
       </p>
       <h2 style="font-size:1.125rem">The full id_token</h2>
       <pre>${esc(JSON.stringify(session.claims, null, 2))}</pre>${peers()}`
      : `<h1>${esc(LABEL)}</h1>
       <p class="lede">A hundred lines of plain Node, no dependencies, demonstrating what an
       application has to do to use SAG. It signs in against <code>${esc(ISSUER)}</code>
       as <code>${esc(CLIENT_ID)}</code>${
         CLIENT_SECRET ? ', a confidential client' : CIMD_PATH ? '' : ', a public client'
       }.</p>
       ${
         CIMD_PATH
           ? `<p class="lede">Nobody registered it. Its client id is the URL of
              <a href="${esc(CIMD_PATH)}">the metadata document it serves itself</a>, so SAG
              reads what this client is from the one place only this origin controls.</p>`
           : ''
       }
       <p><a class="btn" href="/start">Sign in with SAG</a></p>
       <p class="lede">Watch the log of the SAG instance it talks to: the sign-in code
       is printed there, and shown on the page as well in development.</p>${peers()}`,
  );

// --- Server ----------------------------------------------------------------

const server = createServer(async (req, res) => {
  const url = new URL(req.url, ORIGIN);
  const cookie = new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)').exec(req.headers.cookie || '')?.[1];
  const session = cookie ? sessions.get(cookie) : undefined;

  const send = (status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
    res.end(body);
  };
  const fail = (err) => {
    // "fetch failed" on its own is not a diagnosis. undici puts the reason -
    // ECONNREFUSED, ECONNRESET, EAI_AGAIN - in err.cause, and an application
    // that throws that away leaves nothing to debug a back channel with. This
    // is one of the places a real application would do more, not less.
    const cause = err.cause?.code || err.cause?.message;
    console.error('  sign-in failed: ' + err.message + (cause ? ' (' + cause + ')' : ''));
    if (err.stack) console.error('  ' + err.stack.split('\n').slice(1, 3).join('\n  '));
    return send(
      400,
      page(
        'Something went wrong',
        `<div class="err"><strong>Sign-in failed</strong><br>The request could not be completed.</div>
      <p class="lede" style="margin-top:1rem">The back channel is
      <code>${esc(BACKCHANNEL)}</code>. This application's log has the rest.</p>
      <p style="margin-top:1.5rem"><a class="btn" href="/">Start again</a></p>`,
      ),
    );
  };

  try {
    if (CIMD_PATH && url.pathname === CIMD_PATH) {
      // Cacheable, because a client id is a stable thing and SAG will cache it
      // anyway - CLIENTS_CIMD_CACHE_TTL, five minutes by default.
      return send(200, JSON.stringify(clientMetadata(), null, 2), {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'public, max-age=300',
      });
    }

    if (url.pathname === '/') return send(200, home(session));

    if (url.pathname === '/start') {
      const extra = {};
      for (const name of ['prompt', 'acr_values', 'max_age', 'login_hint', 'id_token_signed_response_alg']) {
        const value = url.searchParams.get(name);
        if (value) extra[name] = value;
      }
      return send(303, '', { location: await startSignIn(extra) });
    }

    if (url.pathname === '/callback') {
      const result = await finishSignIn(url.searchParams);
      const id = random(16);
      sessions.set(id, result);
      console.log('  signed in: ' + result.claims.email + ' (' + result.header.alg + ', ' + result.claims.acr + ')');
      return send(303, '', {
        location: '/',
        // A real application would set Secure too, over HTTPS.
        'set-cookie': COOKIE + '=' + id + '; Path=/; HttpOnly; SameSite=Lax',
      });
    }

    if (url.pathname === '/userinfo') {
      if (!session) return send(303, '', { location: '/' });
      const meta = await metadata();
      const response = await backchannelFetch(meta.userinfo_endpoint, {
        headers: { authorization: 'Bearer ' + session.tokens.access_token },
      });
      const body = await response.json();
      return send(
        200,
        page(
          'userinfo',
          `<h1>/userinfo</h1><p class="lede">HTTP ${response.status}, using the access token from the code exchange.</p>
           <pre>${esc(JSON.stringify(body, null, 2))}</pre>
           <p><a class="btn alt" href="/">Back</a></p>`,
        ),
      );
    }

    if (url.pathname === '/logout') {
      if (cookie) sessions.delete(cookie);
      const meta = await metadata();
      const target = new URL(meta.end_session_endpoint);
      target.searchParams.set('client_id', CLIENT_ID);
      if (session?.tokens.id_token) target.searchParams.set('id_token_hint', session.tokens.id_token);
      target.searchParams.set('post_logout_redirect_uri', ORIGIN + '/');
      return send(303, '', {
        location: target.toString(),
        'set-cookie': COOKIE + '=; Path=/; Max-Age=0',
      });
    }

    return send(404, page('Not found', '<h1>Not found</h1>'));
  } catch (err) {
    return fail(err);
  }
});

// Ctrl-C, and what a container runtime sends. Without the second, stopping the
// stack waits out the grace period on every application.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

// A metadata document is public, so a secret alongside it is a contradiction
// rather than extra security: SAG derives the authentication method from the
// document, would ignore the secret, and the operator would believe this client
// was confidential. Say so instead of starting.
if (USE_CIMD_AND_PUBLIC_CLIENT && CLIENT_SECRET) {
  console.error(
    '\n  EXAMPLE_USE_CIMD_AND_PUBLIC_CLIENT and EXAMPLE_CLIENT_SECRET are both set.\n' +
      '  A client that describes itself in a public document has no shared secret:\n' +
      '  it is public, and PKCE is what protects its code. Unset one of them.\n',
  );
  process.exit(1);
}

server.listen(PORT, HOST, () => {
  console.log(
    [
      '',
      '  ' + LABEL,
      '  ' + '-'.repeat(40),
      '  Client id   ' + CLIENT_ID + (CLIENT_SECRET ? ' (confidential)' : ' (public, PKCE only)'),
      ...(CIMD_PATH ? ['  Describing  ' + ORIGIN + CIMD_PATH + ' - no registration needed'] : []),
      '  Talking to  ' + ISSUER,
      ...(BACKCHANNEL === ISSUER ? [] : ['  Back channel ' + BACKCHANNEL]),
      '',
      '  Open ' + ORIGIN,
      '',
    ].join('\n'),
  );
});
