// /alive: a liveness probe that answers independently of configuration,
// which is what separates it from /healthz. See docs/multi-region.md.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleRequest } from '../src/index.js';
import { resetContextCache } from '../src/context.js';
import { createInstance } from './harness.js';

test('/alive answers ok with a normal configuration', async () => {
  resetContextCache();
  const env = { SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: 'test-secret-'.repeat(4) };
  const res = await handleRequest(new Request('http://localhost:8787/alive'), env);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
});

test('/alive answers ok even when the configuration would refuse to start', async () => {
  resetContextCache();
  // A real hostname with nothing else set: no master secret, no signing key,
  // a console email provider. docs/operations.md documents this exact
  // configuration as one that must refuse to start.
  const env = { SAG_ISSUER: 'https://id.example.com' };

  const alive = await handleRequest(new Request('https://id.example.com/alive'), env);
  assert.equal(alive.status, 200, '/alive must not depend on this instance being usable');
  assert.equal(await alive.text(), 'ok');

  const health = await handleRequest(new Request('https://id.example.com/healthz'), env);
  assert.equal(health.status, 500, '/healthz is the readiness question, and correctly fails here');
});

test('/alive rejects anything but GET', async () => {
  resetContextCache();
  const env = { SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: 'test-secret-'.repeat(4) };
  const res = await handleRequest(new Request('http://localhost:8787/alive', { method: 'POST' }), env);
  assert.equal(res.status, 405);
});

// ---------------------------------------------------------------------------
// What /healthz will and will not say
// ---------------------------------------------------------------------------

test('upstreams are counted by provider, never named', async () => {
  const sag = createInstance({
    UPSTREAM_MICROSOFT_COMMON_CLIENT_ID: 'common:ms-common',
    UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET: 'x',
    UPSTREAM_MICROSOFT_ACMECOM_CLIENT_ID: 'acme.com:ms-acme',
    UPSTREAM_MICROSOFT_ACMECOM_CLIENT_SECRET: 'x',
    UPSTREAM_GOOGLE_COMMON_CLIENT_ID: 'common:g-common',
    UPSTREAM_GOOGLE_COMMON_CLIENT_SECRET: 'x',
  });
  const { body } = await sag.json('/healthz');

  assert.deepEqual(body.routes.upstreams, { google: 1, microsoft: 2 });
  // The domain list is the deployment's customer list, and the client ids are
  // its registrations. Neither is anybody else's business.
  const text = JSON.stringify(body);
  for (const secret of ['acme.com', 'acmecom', 'ms-acme', 'ms-common', 'g-common']) {
    assert.ok(!text.includes(secret), '/healthz must not disclose ' + secret);
  }
});

test('a rejected configuration entry is not quoted back to an anonymous caller', async () => {
  // A rejected entry is almost always a typo in something internal, and
  // /healthz answers anybody. The operator still gets the whole message, with
  // the value in it, through the start-up banner and the log.
  const sag = createInstance({
    // Both are rejected: an origin may not carry a path, and a peer URL has to
    // be absolute. Each rejection message quotes the value back.
    CORS_ALLOWED_ORIGINS: 'https://internal-build.corp.example/callback',
    PEER_JWKS_URLS: 'dr-site.corp.example/.well-known/jwks.json',
    OTP_DIGITS: '6',
  });
  const { body } = await sag.json('/healthz');

  const text = JSON.stringify(body);
  for (const leaked of ['internal-build.corp.example', 'dr-site.corp.example', 'OTP_DIGITS']) {
    assert.ok(!text.includes(leaked), '/healthz must not disclose ' + leaked);
  }
});
