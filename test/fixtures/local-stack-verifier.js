// External HTTP responses for the verifier's failure-path tests. No SAG
// implementation is replaced: the real CLI consumes these as remote replies.

import assert from 'node:assert/strict';

const scenario = process.argv[2];
const marker = 'private-authentication-response-marker';
const issuer = 'http://localhost:8794';
const transaction = '<input name="tx" value="opaque-transaction">';
let authorisation;
let factorAttempts = 0;
let previousCode;

if (scenario === 'mfa-retry') {
  let now = 1_800_000_000_000;
  Date.now = () => now;
  globalThis.setTimeout = (callback, delay) => {
    now += delay;
    callback();
  };
}

globalThis.fetch = async (input, init = {}) => {
  const url = new URL(input);
  switch (url.pathname) {
    case '/healthz':
      return Response.json({
        issuer,
        signing: { primary: { backend: 'local', alg: 'ES256', ephemeral: false } },
        clients: { store: 'none', static: 1 },
        routes: { local: true },
      });
    case '/.well-known/openid-configuration':
      return Response.json({
        issuer,
        authorization_endpoint: issuer + '/authorize',
        token_endpoint: issuer + '/token',
        jwks_uri: issuer + '/jwks.json',
      });
    case '/jwks.json':
      return Response.json({ keys: [{ kid: 'test-key' }] });
    case '/authorize':
      assert.equal(url.searchParams.get('acr_values'), 'urn:sag:acr:mfa');
      authorisation = url;
      return new Response(transaction + '<input name="email">');
    case '/authorize/email':
      return new Response(transaction + '<input name="password">');
    case '/authorize/local-password':
      if (scenario === 'password-html') return new Response(marker);
      return new Response(transaction + '<input name="code">');
    case '/authorize/local-mfa': {
      if (scenario === 'mfa-html') return new Response(marker, { status: 500 });
      factorAttempts += 1;
      const code = new URLSearchParams(init.body).get('code');
      if (factorAttempts === 1 && scenario === 'mfa-retry') {
        previousCode = code;
        return new Response(transaction + '<input name="code">' + marker, { status: 400 });
      }
      if (scenario === 'mfa-retry') {
        assert.equal(factorAttempts, 2);
        assert.notEqual(code, previousCode, 'retry must use a new TOTP step');
      }
      const location = new URL('http://localhost:8805/callback');
      location.searchParams.set('code', 'opaque-authorisation-code');
      location.searchParams.set('state', authorisation.searchParams.get('state'));
      location.searchParams.set('iss', issuer);
      return new Response(null, { status: 303, headers: { location: location.href } });
    }
    case '/token':
      if (scenario === 'invalid-json') return new Response('not JSON: ' + marker, { status: 400 });
      return Response.json({ error: 'invalid_grant', error_description: marker }, { status: 400 });
    default:
      throw new Error('unexpected verifier request');
  }
};

process.argv = [process.execPath, 'verify.js', 'sag-local'];
await import('../local-stack/verify.js');
