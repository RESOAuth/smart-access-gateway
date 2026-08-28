// Relying parties as files in a directory.
//
// This is what a container or a single VM wants: no KV namespace, no bucket,
// just JSON somebody can edit. The filesystem lives in the Node adapter and
// reaches the core as a binding, exactly as a KV namespace does, so these
// tests drive the real path rather than a stand-in for it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInstance, signInWithOtp, redeem, pkce, authorizeUrl } from './harness.js';
import { createFileClientStore } from '../adapters/node/client-files.js';
import { sha256hex } from '../src/crypto/secrets.js';

const EMAIL = 'person@example.org';
const REDIRECT = 'http://127.0.0.1:8788/callback';

/** A directory of records, and an instance reading from it. */
function withClients(records, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sag-clients-'));
  for (const [name, body] of Object.entries(records)) {
    writeFileSync(join(dir, name), typeof body === 'string' ? body : JSON.stringify(body, null, 2));
  }
  const sag = createInstance({
    CLIENTS_STORE_BACKEND: 'file',
    SAG_CLIENTS: createFileClientStore(dir),
    CLIENTS_STORE_CACHE_TTL: '0',
    ...env,
  });
  return { sag, dir };
}

test('a relying party described by a file can sign somebody in', async () => {
  const { sag } = withClients({
    'ledger.json': {
      client_name: 'Ledger',
      redirect_uris: [REDIRECT],
      tos_uri: 'https://ledger.test/terms',
    },
  });

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, clientId: 'ledger', redirectUri: REDIRECT });
  const html = await (await sag.raw(path)).text();
  assert.match(html, /Continue to <strong>Ledger<\/strong>/, 'the name comes from the file');
  assert.match(html, /<a href="https:\/\/ledger\.test\/terms">Terms of use<\/a>/);

  const flow = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'ledger', redirectUri: REDIRECT },
  });
  const { res, body } = await redeem(sag, { ...flow, clientId: 'ledger', redirectUri: REDIRECT });
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.ok(body.id_token);
});

test('an edit is picked up without a restart', async () => {
  const { sag, dir } = withClients({ 'ledger.json': { client_name: 'Ledger', redirect_uris: [REDIRECT] } });
  const name = async () => {
    const { challenge } = await pkce();
    const { path } = authorizeUrl({ challenge, clientId: 'ledger', redirectUri: REDIRECT });
    return (await sag.raw(path)).text();
  };
  assert.match(await name(), /Continue to <strong>Ledger<\/strong>/);

  writeFileSync(join(dir, 'ledger.json'), JSON.stringify({ client_name: 'General Ledger', redirect_uris: [REDIRECT] }));
  assert.match(await name(), /Continue to <strong>General Ledger<\/strong>/, 'the file is the source of truth');
});

test('a secret is stored as a digest, and the real secret still authenticates', async () => {
  // Reading the file must not be enough to impersonate the relying party,
  // which is what `npm run hash-secret` is for.
  const digest = 'sha256:' + (await sha256hex('the-real-secret'));
  const { sag } = withClients({
    'ledger.json': {
      client_name: 'Ledger',
      redirect_uris: [REDIRECT],
      client_secret_digest: digest,
      token_endpoint_auth_method: 'client_secret_basic',
    },
  });

  const flow = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'ledger', redirectUri: REDIRECT },
  });
  const attempt = (secret) =>
    sag.raw('/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + Buffer.from('ledger:' + secret).toString('base64'),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: flow.authCode,
        redirect_uri: REDIRECT,
        code_verifier: flow.verifier,
      }).toString(),
    });

  const wrong = await attempt('guess');
  assert.equal(wrong.status, 401);
  const right = await attempt('the-real-secret');
  assert.equal(right.status, 200);
});

test('a broken file is one missing client, not an outage for everybody', async () => {
  const { sag } = withClients({
    'broken.json': '{ this is not json',
    'ledger.json': { client_name: 'Ledger', redirect_uris: [REDIRECT] },
  });

  const { challenge } = await pkce();
  const bad = await sag.raw(authorizeUrl({ challenge, clientId: 'broken', redirectUri: REDIRECT }).path);
  assert.equal(bad.status, 401, 'the same answer as any unknown client');
  assert.match(await bad.text(), /not recognised/);

  const good = await sag.raw(authorizeUrl({ challenge, clientId: 'ledger', redirectUri: REDIRECT }).path);
  assert.equal(good.status, 200, 'one bad file must not take the deployment down');
});

test('a record with no redirect URIs is no client at all', async () => {
  // Half a record is more dangerous than none: it would be a client whose
  // redirect matching had nothing to match against.
  const { sag } = withClients({ 'half.json': { client_name: 'Half' } });
  const { challenge } = await pkce();
  const res = await sag.raw(authorizeUrl({ challenge, clientId: 'half', redirectUri: REDIRECT }).path);
  assert.equal(res.status, 401);
});

test('the store cannot be talked into reading outside its own directory', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sag-root-'));
  mkdirSync(join(root, 'clients'));
  writeFileSync(join(root, 'secrets.json'), JSON.stringify({ redirect_uris: ['https://attacker.test/cb'] }));
  const store = createFileClientStore(join(root, 'clients'));

  assert.equal(await store.get('../secrets.json'), null, 'a traversal must read nothing');
  assert.equal(await store.get('/etc/passwd'), null);
  assert.equal(await store.get('nothing-here.json'), null, 'and a missing file is simply missing');
});
