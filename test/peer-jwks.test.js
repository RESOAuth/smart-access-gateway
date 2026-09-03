// Peer deployments of the same issuer: fetching, merging and caching their
// public keys into this instance's own JWKS. See docs/multi-region.md.
//
// No test waits on real time. PEER_JWKS_CACHE_TTL is set to 0 wherever a test
// needs every call to attempt a live fetch, which lets "the peer is up" and
// "the peer just went down" be two different fetch stubs installed one after
// the other, rather than something waited for.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createPeerJwks, mergeJwks, PEER_FETCH_PARAM } from '../src/keys/peers.js';
import { createInstance } from './harness.js';

const DEV = 'http://localhost:8787';
const SECRET = 's'.repeat(32);
const PEER_A = 'https://aws-eu-west-2.auth.example.test/.well-known/jwks.json';
const PEER_B = 'https://cf-workers.auth.example.test/.well-known/jwks.json';

const key = (kid, extra = {}) => ({ kty: 'EC', crv: 'P-256', kid, x: 'x-' + kid, y: 'y-' + kid, ...extra });

const configWith = (overrides = {}) =>
  loadConfig({
    SAG_ISSUER: DEV,
    SAG_SECRET: SECRET,
    PEER_JWKS_URLS: PEER_A,
    PEER_JWKS_CACHE_TTL: '300',
    PEER_JWKS_STALE_TTL: '1000',
    ...overrides,
  });

/** The configured URL a peer fetch of `url` was for, without its marker. */
function withoutPeerParam(url) {
  const u = new URL(url);
  u.searchParams.delete(PEER_FETCH_PARAM);
  return u.href;
}

/** Answers fetch() by exact URL match; anything else fails loudly. */
function fetchStub(script) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = typeof input === 'string' ? input : input.url;
    calls.push(url);
    // Scripts stay keyed on the configured peer URL; a peer fetch asks for the
    // local-only document, so its marker is stripped before matching.
    const asked = withoutPeerParam(url);
    if (!(asked in script)) throw new Error('unexpected fetch in this test: ' + url);
    const answer = script[asked];
    if (answer instanceof Error) throw answer;
    if (typeof answer === 'string') return new Response(answer, { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

test('PEER_JWKS_URLS accepts several URLs and drops a malformed one', () => {
  const config = loadConfig({ SAG_ISSUER: 'https://auth.example.com', SAG_SECRET: SECRET, PEER_JWKS_URLS: [PEER_A, 'not-a-url', PEER_B].join(',') });
  assert.deepEqual(config.peerJwks.urls, [PEER_A, PEER_B]);
  assert.ok(config.internalWarnings.some((w) => w.includes('not-a-url')));
});

test('a plain http peer URL is dropped outside development', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    PEER_JWKS_URLS: 'http://insecure.example.test/.well-known/jwks.json',
  });
  assert.deepEqual(config.peerJwks.urls, []);
  assert.ok(config.internalWarnings.some((w) => /must be an https URL/.test(w)));
});

test('an http peer URL is fine in development', () => {
  const config = loadConfig({ SAG_ISSUER: DEV, SAG_SECRET: SECRET, PEER_JWKS_URLS: 'http://peer.localhost:8787/.well-known/jwks.json' });
  assert.equal(config.peerJwks.urls.length, 1);
});

test('a peer URL on this instance\'s own issuer origin is dropped', () => {
  // The mistake this catches: naming the central hostname instead of the
  // peer's own, which fetches whichever instance answers there - sometimes a
  // peer, sometimes this instance - and so federates only intermittently.
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    PEER_JWKS_URLS: ['https://auth.example.com/.well-known/jwks.json', PEER_A].join(','),
  });
  assert.deepEqual(config.peerJwks.urls, [PEER_A]);
  assert.ok(config.internalWarnings.some((w) => /own issuer origin/.test(w)));
});

test('a peered deployment on the memory cache is warned about it', () => {
  const config = loadConfig({ SAG_ISSUER: 'https://auth.example.com', SAG_SECRET: SECRET, PEER_JWKS_URLS: PEER_A });
  assert.ok(config.internalWarnings.some((w) => /PEER_JWKS_CACHE_BACKEND is "memory"/.test(w)));
});

test('REQUIRE_PEER_JWKS_CACHE refuses the memory backend, and refuses no peers at all', () => {
  const base = { SAG_ISSUER: 'https://auth.example.com', SAG_SECRET: SECRET, REQUIRE_PEER_JWKS_CACHE: 'true' };
  assert.throws(() => loadConfig({ ...base, PEER_JWKS_URLS: PEER_A }), /PEER_JWKS_CACHE_BACKEND is "memory"/);
  // The failure this catches is the peer list itself going missing - a
  // template or a Terraform refactor dropping it looks exactly like a
  // deliberate single-instance deployment otherwise.
  assert.throws(() => loadConfig({ ...base, PEER_JWKS_CACHE_BACKEND: 'cf-kv' }), /names no usable peer/);
  assert.doesNotThrow(() => loadConfig({ ...base, PEER_JWKS_URLS: PEER_A, PEER_JWKS_CACHE_BACKEND: 'cf-kv' }));
});

test('the stale grace period defaults to twice the session max lifetime', () => {
  const config = loadConfig({ SAG_ISSUER: DEV, SAG_SECRET: SECRET, SESSION_MAX_LIFETIME: String(3 * 86400) });
  assert.equal(config.peerJwks.staleTtlSeconds, 6 * 86400);
});

test('no peers configured means no peer jwks service at all', () => {
  const config = loadConfig({ SAG_ISSUER: DEV, SAG_SECRET: SECRET });
  assert.equal(createPeerJwks(config, {}), undefined);
});

// ---------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------

test('mergeJwks keeps this instance\'s own key on a kid collision', () => {
  const local = [key('shared', { note: 'ours' })];
  const peers = [key('shared', { note: 'theirs' }), key('only-peer')];
  assert.deepEqual(mergeJwks(local, peers), [key('shared', { note: 'ours' }), key('only-peer')]);
});

// ---------------------------------------------------------------------------
// Fetching, caching, and the grace period on failure
// ---------------------------------------------------------------------------

test('a healthy peer is fetched once and served from cache after that', async (t) => {
  const stub = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(stub.restore);

  const peer = createPeerJwks(configWith(), {});
  assert.deepEqual(await peer.keys(), [key('peer-1')]);
  assert.deepEqual(await peer.keys(), [key('peer-1')]);
  assert.equal(stub.calls.length, 1, 'the second call must be answered from cache, not a second fetch');
});

test('a peer is asked for its own keys only, not its view of the whole mesh', async (t) => {
  // Otherwise fetching a peer fetches that peer's peers as well, which in a
  // complete mesh of instances all cold at once fans out exponentially - and
  // whichever request loses that race times out and publishes a JWKS with an
  // instance's keys missing.
  const stub = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(stub.restore);

  await createPeerJwks(configWith(), {}).keys();
  assert.equal(new URL(stub.calls[0]).searchParams.get(PEER_FETCH_PARAM), '1');
});

test('one burst of requests to a cold instance makes one fetch per peer', async (t) => {
  const stub = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(stub.restore);
  const peer = createPeerJwks(configWith(), {});

  const answers = await Promise.all([peer.keys(), peer.keys(), peer.keys(), peer.keys()]);
  for (const answer of answers) assert.deepEqual(answer, [key('peer-1')]);
  assert.equal(stub.calls.length, 1, 'the requests that arrived during the fetch must share it');
});

test('a peer answering with an empty key set does not replace its cached keys', async (t) => {
  // A reachable but not-yet-serving peer: a signing backend that has started
  // failing, or an edge error page that happens to parse as JSON. Caching that
  // as a success would drop a live instance's keys for a whole cache TTL, and
  // on a shared cache backend would spread the emptiness to every instance.
  const config = configWith({ PEER_JWKS_CACHE_TTL: '0' });
  const peer = createPeerJwks(config, {});

  const up = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  assert.deepEqual(await peer.keys(), [key('peer-1')]);
  up.restore();

  const empty = fetchStub({ [PEER_A]: { keys: [] } });
  t.after(empty.restore);
  assert.deepEqual(await peer.keys(), [key('peer-1')], 'the last known keys stand instead');
});

test('a peer that goes down keeps serving its last known keys within the grace period', async (t) => {
  const config = configWith({ PEER_JWKS_CACHE_TTL: '0' }); // always due for a refresh attempt
  const peer = createPeerJwks(config, {});

  const up = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  assert.deepEqual(await peer.keys(), [key('peer-1')]);
  up.restore();

  const down = fetchStub({ [PEER_A]: new Error('connect refused') });
  t.after(down.restore);
  const warnings = [];
  const log = { warn: (m) => warnings.push(m) };
  assert.deepEqual(await peer.keys({ log }), [key('peer-1')], 'still within the 1000 second grace period');
  assert.ok(warnings.some((w) => /unreachable, serving its last known keys/.test(w)));
});

test('a peer unreachable for longer than the grace period drops out rather than erroring', async (t) => {
  const config = configWith({ PEER_JWKS_CACHE_TTL: '0', PEER_JWKS_STALE_TTL: '0' });
  const peer = createPeerJwks(config, {});

  const up = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  await peer.keys();
  up.restore();

  const down = fetchStub({ [PEER_A]: new Error('connect refused') });
  t.after(down.restore);
  assert.deepEqual(await peer.keys(), [], 'no grace period left, so this peer contributes nothing rather than failing the request');
});

test('a peer that has never answered is not refetched on every request', async (t) => {
  // The case PEER_JWKS_RETRY_AFTER exists for: nothing is cached, so without
  // a backoff every /jwks.json would pay the whole fetch timeout again.
  const stub = fetchStub({ [PEER_A]: new Error('connect refused') });
  t.after(stub.restore);
  const peer = createPeerJwks(configWith({ PEER_JWKS_CACHE_TTL: '0', PEER_JWKS_RETRY_AFTER: '30' }), {});

  assert.deepEqual(await peer.keys(), []);
  assert.deepEqual(await peer.keys(), []);
  assert.deepEqual(await peer.keys(), []);
  assert.equal(stub.calls.length, 1, 'only the first request may attempt a fetch');
});

test('a peer within its backoff still contributes its graced keys', async (t) => {
  const config = configWith({ PEER_JWKS_CACHE_TTL: '0', PEER_JWKS_RETRY_AFTER: '30' });
  const peer = createPeerJwks(config, {});

  const up = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  assert.deepEqual(await peer.keys(), [key('peer-1')]);
  up.restore();

  const down = fetchStub({ [PEER_A]: new Error('connect refused') });
  t.after(down.restore);
  assert.deepEqual(await peer.keys(), [key('peer-1')], 'the failing fetch still leaves the grace period intact');
  assert.deepEqual(await peer.keys(), [key('peer-1')], 'and the backoff must not drop them either');
  assert.equal(down.calls.length, 1);
});

test('PEER_JWKS_RETRY_AFTER=0 keeps retrying on every request', async (t) => {
  const stub = fetchStub({ [PEER_A]: new Error('connect refused') });
  t.after(stub.restore);
  const peer = createPeerJwks(configWith({ PEER_JWKS_CACHE_TTL: '0', PEER_JWKS_RETRY_AFTER: '0' }), {});

  await peer.keys();
  await peer.keys();
  assert.equal(stub.calls.length, 2);
});

test('a peer that comes back is picked up as soon as its backoff lapses', async (t) => {
  const peer = createPeerJwks(configWith({ PEER_JWKS_CACHE_TTL: '0', PEER_JWKS_RETRY_AFTER: '0' }), {});

  const down = fetchStub({ [PEER_A]: new Error('connect refused') });
  assert.deepEqual(await peer.keys(), []);
  down.restore();

  const up = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(up.restore);
  assert.deepEqual(await peer.keys(), [key('peer-1')], 'a success must clear the backoff, not wait it out');
});

test('a response with no keys array is treated the same as unreachable', async (t) => {
  const stub = fetchStub({ [PEER_A]: { notKeys: [] } });
  t.after(stub.restore);
  const peer = createPeerJwks(configWith({ PEER_JWKS_CACHE_TTL: '0' }), {});
  assert.deepEqual(await peer.keys(), []);
});

test('a response over the size cap is refused rather than parsed', async (t) => {
  // Padded well past the 1,024 byte floor PEER_JWKS_MAX_BYTES enforces.
  const oversized = { keys: [key('peer-1', { pad: 'x'.repeat(2000) })] };
  const stub = fetchStub({ [PEER_A]: oversized });
  t.after(stub.restore);
  const peer = createPeerJwks(configWith({ PEER_JWKS_CACHE_TTL: '0', PEER_JWKS_MAX_BYTES: '1024' }), {});
  assert.deepEqual(await peer.keys(), []);
});

test('a key carrying a private component is dropped, not republished', async (t) => {
  const leaked = { ...key('leaked'), d: 'private-scalar' };
  const stub = fetchStub({ [PEER_A]: { keys: [key('safe'), leaked] } });
  t.after(stub.restore);
  const peer = createPeerJwks(configWith({ PEER_JWKS_CACHE_TTL: '0' }), {});
  const warnings = [];
  const keys = await peer.keys({ log: { warn: (m) => warnings.push(m) } });
  assert.deepEqual(keys, [key('safe')]);
  assert.ok(warnings.some((w) => w.includes('private component')));
});

test('describe reports cache state without ever fetching', async (t) => {
  const stub = fetchStub({}); // any fetch call here is a test failure
  t.after(stub.restore);
  const peer = createPeerJwks(configWith(), {});

  const before = await peer.describe();
  assert.deepEqual(before, [
    { url: PEER_A, key_count: 0, last_fetched_seconds_ago: null, within_cache_ttl: false, within_grace_period: false },
  ]);
  assert.equal(stub.calls.length, 0, 'describe must never fetch, so /healthz stays cheap');
});

// ---------------------------------------------------------------------------
// The cf-kv cache backend
// ---------------------------------------------------------------------------

function fakeKv() {
  const store = new Map();
  return {
    store,
    get: async (k, opts) => {
      const raw = store.get(k);
      if (raw === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(raw) : raw;
    },
    put: async (k, value) => {
      store.set(k, value);
    },
  };
}

test('the cf-kv cache backend round-trips a peer\'s keys across instances', async (t) => {
  const kv = fakeKv();
  const stub = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(stub.restore);

  const config = configWith({ PEER_JWKS_CACHE_BACKEND: 'cf-kv' });
  const first = createPeerJwks(config, { SAG_PEER_JWKS: kv });
  assert.deepEqual(await first.keys(), [key('peer-1')]);
  assert.equal(kv.store.size, 1);

  // A second, independent instance - a different isolate reading the same
  // durable namespace - sees the cached entry without fetching at all.
  const second = createPeerJwks(config, { SAG_PEER_JWKS: kv });
  assert.deepEqual(await second.keys(), [key('peer-1')]);
  assert.equal(stub.calls.length, 1, 'the second instance must not have fetched');
});

test('cf-kv refuses to start without a bound namespace', () => {
  const config = configWith({ PEER_JWKS_CACHE_BACKEND: 'cf-kv' });
  assert.throws(() => createPeerJwks(config, {}), /no KV namespace is bound as SAG_PEER_JWKS/);
});

// ---------------------------------------------------------------------------
// The dynamodb cache backend
// ---------------------------------------------------------------------------

test('the dynamodb cache backend round-trips a peer\'s keys', async (t) => {
  const table = new Map();
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    calls.push(url);
    if (withoutPeerParam(url) === PEER_A) return new Response(JSON.stringify({ keys: [key('peer-1')] }), { status: 200 });
    const target = new Headers(init.headers).get('x-amz-target') || '';
    const body = JSON.parse(init.body);
    if (target.endsWith('GetItem')) return new Response(JSON.stringify({ Item: table.get(body.Key.peer_url.S) }), { status: 200 });
    if (target.endsWith('PutItem')) {
      table.set(body.Item.peer_url.S, body.Item);
      return new Response('{}', { status: 200 });
    }
    throw new Error('unexpected DynamoDB target: ' + target);
  };
  t.after(() => {
    globalThis.fetch = real;
  });

  const config = configWith({ PEER_JWKS_CACHE_BACKEND: 'dynamodb', PEER_JWKS_CACHE_TABLE: 'sag-peer-jwks', PEER_JWKS_CACHE_REGION: 'eu-west-2' });
  const peer = createPeerJwks(config, { AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE', AWS_SECRET_ACCESS_KEY: 'secret' });

  assert.deepEqual(await peer.keys(), [key('peer-1')]);
  assert.equal(table.size, 1);
  const afterFirstFetch = calls.filter((u) => withoutPeerParam(u) === PEER_A).length;

  assert.deepEqual(await peer.keys(), [key('peer-1')], 'served from DynamoDB, within the cache window');
  assert.equal(calls.filter((u) => withoutPeerParam(u) === PEER_A).length, afterFirstFetch, 'no second peer fetch');
});

test('dynamodb cache backend refuses to start without a table', () => {
  const config = configWith({ PEER_JWKS_CACHE_BACKEND: 'dynamodb', PEER_JWKS_CACHE_REGION: 'eu-west-2' });
  assert.throws(() => createPeerJwks(config, {}), /PEER_JWKS_CACHE_TABLE is not set/);
});

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

test('GET /.well-known/jwks.json merges this instance\'s key with a peer\'s', async (t) => {
  const stub = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(stub.restore);

  const sag = createInstance({ PEER_JWKS_URLS: PEER_A });
  const { res, body } = await sag.json('/.well-known/jwks.json');
  assert.equal(res.status, 200);
  assert.equal(body.keys.length, 2, 'this instance\'s own ephemeral key, plus the peer\'s');
  assert.ok(body.keys.some((k) => k.kid === 'peer-1'));
});

test('a peer fetching /.well-known/jwks.json gets this instance\'s own keys only', async (t) => {
  const stub = fetchStub({}); // answering a peer must not fetch anything
  t.after(stub.restore);

  const sag = createInstance({ PEER_JWKS_URLS: PEER_A });
  const { body } = await sag.json('/.well-known/jwks.json?' + PEER_FETCH_PARAM + '=1');
  assert.equal(body.keys.length, 1, 'this instance\'s own ephemeral key, and nothing else');
  assert.equal(stub.calls.length, 0);
});

test('a JWKS missing a peer\'s keys is only cacheable briefly', async (t) => {
  const stub = fetchStub({ [PEER_A]: new Error('connect refused') });
  t.after(stub.restore);

  const sag = createInstance({ PEER_JWKS_URLS: PEER_A, PEER_JWKS_RETRY_AFTER: '30' });
  const { res, body } = await sag.json('/.well-known/jwks.json');
  assert.equal(body.keys.length, 1, 'only this instance\'s own key made it');
  // Pinning an incomplete key set in a relying party's or a CDN's cache for
  // the full five minutes is what turns a brief blip into minutes of tokens
  // failing to verify.
  assert.equal(res.headers.get('cache-control'), 'public, max-age=30');
});

test('a complete JWKS keeps the full cache lifetime', async (t) => {
  const stub = fetchStub({ [PEER_A]: { keys: [key('peer-1')] } });
  t.after(stub.restore);

  const sag = createInstance({ PEER_JWKS_URLS: PEER_A });
  const { res } = await sag.json('/.well-known/jwks.json');
  assert.equal(res.headers.get('cache-control'), 'public, max-age=300');
});

test('/healthz reports peer configuration and freshness without fetching', async (t) => {
  const stub = fetchStub({}); // any fetch here is a test failure
  t.after(stub.restore);

  const sag = createInstance({ PEER_JWKS_URLS: PEER_A + ' ' + PEER_B });
  const { body } = await sag.json('/healthz');
  assert.equal(body.peer_jwks.backend, 'memory');
  assert.deepEqual(body.peer_jwks.peers.map((p) => p.url), [PEER_A, PEER_B]);
  assert.equal(body.peer_jwks.peers[0].last_fetched_seconds_ago, null);
});

test('/healthz reports no peer_jwks section when no peers are configured', async () => {
  const sag = createInstance({});
  const { body } = await sag.json('/healthz');
  assert.equal(body.peer_jwks, false);
});
