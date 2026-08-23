// The one optional piece of state: single-use authorisation codes, and the
// counters behind OTP send limits. Both use the same store.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, extractField, extractDevCode } from './harness.js';
import { createMemoryStore, createStateStore } from '../src/store/index.js';
import { StateGuard } from '../adapters/cloudflare/state-do.js';
import { loadConfig } from '../src/config.js';

const EMAIL = 'person@example.org';

// ---------------------------------------------------------------------------
// The primitives
// ---------------------------------------------------------------------------

test('the memory store claims an identifier exactly once', async () => {
  const store = createMemoryStore();
  assert.equal(await store.claim('abc', 60), true);
  assert.equal(await store.claim('abc', 60), false);
  assert.equal(await store.claim('abc', 60), false);
  assert.equal(await store.claim('def', 60), true, 'a different code is unaffected');
});

test('the memory store counts, and each key counts separately', async () => {
  const store = createMemoryStore();
  assert.equal(await store.increment('a', 60), 1);
  assert.equal(await store.increment('a', 60), 2);
  assert.equal(await store.increment('b', 60), 1);
});

test('the memory store is capped, so it cannot be made to exhaust the instance', async () => {
  // An uncapped map is a memory exhaustion bug waiting for a busy afternoon.
  // Counters may be dropped when it is full: the worst case is an address
  // getting its send allowance back early.
  const store = createMemoryStore({ maxEntries: 100 });
  for (let i = 0; i < 5000; i++) await store.increment('otp-day:' + i, 86400);
  assert.ok(store.size() <= 100, 'the cap must hold: ' + store.size());
});

test('a full memory store refuses a claim rather than forgetting one', async () => {
  // Dropping a live claim would let a spent authorisation code be spent
  // again, silently, which is the opposite of what the store is for. Refusing
  // fails the exchange and the person starts again.
  const store = createMemoryStore({ maxEntries: 3 });
  for (let i = 0; i < 3; i++) assert.equal(await store.claim('code-' + i, 600), true);
  await assert.rejects(() => store.claim('code-4', 600), /in-memory state store is full/);
  assert.equal(await store.claim('code-0', 600), false, 'and it has forgotten nothing');
});

// ---------------------------------------------------------------------------
// Single-use authorisation codes
// ---------------------------------------------------------------------------

test('a code cannot be redeemed twice with a state store configured', async () => {
  const sag = createInstance({ STATE_STORE_BACKEND: 'memory' });
  const flow = await signInWithOtp(sag, { email: EMAIL });

  const first = await redeem(sag, flow);
  assert.equal(first.res.status, 200, JSON.stringify(first.body));

  const second = await redeem(sag, flow);
  assert.equal(second.res.status, 400);
  assert.equal(second.body.error, 'invalid_grant');
  assert.match(second.body.error_description, /already been used/);
});

test('a failed exchange does not consume the code', async () => {
  const sag = createInstance({ STATE_STORE_BACKEND: 'memory' });
  const flow = await signInWithOtp(sag, { email: EMAIL });

  // A wrong verifier fails before the claim, so the person can retry.
  const wrong = await redeem(sag, { ...flow, verifier: 'x'.repeat(43) });
  assert.equal(wrong.body.error, 'invalid_grant');

  const right = await redeem(sag, flow);
  assert.equal(right.res.status, 200, 'a mistyped attempt must not burn the code');
});

test('the health endpoint says nothing about the store either way', async () => {
  // Publishing it would tell a stranger whether replaying a code is worth
  // trying and whether the OTP sender has a ceiling. An operator reads it in
  // the start-up banner and the logs instead.
  for (const env of [{}, { STATE_STORE_BACKEND: 'memory' }]) {
    const { body } = await createInstance(env).json('/healthz');
    for (const field of ['state_store', 'code_replay_prevention', 'otp_send_limits']) {
      assert.equal(body[field], undefined, field + ' must not be published');
    }
    assert.ok(
      !JSON.stringify(body).match(/state store|replay|send limit/i),
      'and nothing may say it in prose either',
    );
  }
});

test('Cloudflare KV is not offered as a backend, because it cannot do this safely', () => {
  // KV has no compare-and-set and is eventually consistent, so a
  // read-then-write would be a race. A security control that fails silently
  // under load is worse than an honest absence, so it is not an option.
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', STATE_STORE_BACKEND: 'cf-kv' }),
    /STATE_STORE_BACKEND must be one of none, memory, cf-durable-object, dynamodb/,
  );
});

test('the older REPLAY_STORE_ names still configure the same store', () => {
  // The store grew a second job; an operator should not have to rewrite their
  // deployment for it, and an error still names the variable they set.
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    REPLAY_STORE_BACKEND: 'dynamodb',
    REPLAY_STORE_TABLE: 'sag-state',
    REPLAY_STORE_REGION: 'eu-west-2',
  });
  assert.equal(config.stateStore.backend, 'dynamodb');
  assert.equal(config.stateStore.table, 'sag-state');
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', REPLAY_STORE_BACKEND: 'cf-kv' }),
    /REPLAY_STORE_BACKEND must be one of/,
  );
});

test('REQUIRE_STATE_STORE turns a missing backend into a startup error', () => {
  // The same shape as REQUIRE_POST_QUANTUM_SIGNING: a deployment template, a
  // copied environment file or a Terraform refactor can drop
  // STATE_STORE_BACKEND, and a missing variable looks exactly like a
  // deliberate choice not to have one unless something shouts.
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', REQUIRE_STATE_STORE: 'true' }),
    /REQUIRE_STATE_STORE is set but STATE_STORE_BACKEND is "none"/,
  );

  const ok = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    STATE_STORE_BACKEND: 'memory',
    REQUIRE_STATE_STORE: 'true',
  });
  assert.equal(ok.stateStore.required, true);
});

test('the memory backend warns when it cannot be trusted', () => {
  const dev = loadConfig({ SAG_ISSUER: 'http://localhost:8787', STATE_STORE_BACKEND: 'memory' });
  assert.ok(!dev.internalWarnings.some((w) => /only prevents code reuse/.test(w)), 'fine for one local process');

  const prod = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    STATE_STORE_BACKEND: 'memory',
  });
  assert.ok(
    prod.internalWarnings.some((w) => /only prevents code reuse within a single instance/.test(w)),
    'a multi-instance deployment must be told',
  );
});

test('having no store at all is said out loud on a real deployment, but only to the operator', () => {
  const prod = loadConfig({ SAG_ISSUER: 'https://id.example.test', SAG_SECRET: 'x'.repeat(48) });
  assert.ok(
    prod.internalWarnings.some((w) => /OTP send limits are not enforced/.test(w)),
    'an operator must be told which controls they do not have',
  );
  assert.ok(
    !prod.warnings.some((w) => /OTP send limits|state store/i.test(w)),
    'and it must stay out of the list /healthz publishes',
  );
});

// ---------------------------------------------------------------------------
// OTP send limits
// ---------------------------------------------------------------------------

/** Walk as far as the code screen and report what it says. */
async function requestCode(sag, email, { tx } = {}) {
  let transaction = tx;
  if (!transaction) {
    const first = await sag.raw('/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'sag-dev-client',
      redirect_uri: 'http://127.0.0.1:8788/callback',
      scope: 'openid email',
      state: 'st',
      nonce: 'no',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    }).toString());
    transaction = extractField(await first.text());
  }
  const res = await sag.postForm('/authorize/email', { tx: transaction, email });
  const html = await res.text();
  return { res, html, tx: extractField(html), code: extractDevCode(html) };
}

test('an address gets a small burst of codes and then has to wait, with no hint that it did', async () => {
  const sag = createInstance({ STATE_STORE_BACKEND: 'memory' });

  const first = await requestCode(sag, EMAIL);
  assert.ok(first.code, 'the first request sends a code');
  // The burst exists because a code that goes to spam otherwise leaves the
  // person with nothing to do for ten minutes.
  const second = await requestCode(sag, EMAIL);
  assert.ok(second.code, 'and one more, for the code that went to spam');

  // The counter cannot live in the transaction, because a person can present
  // an older copy of one. This is what makes the limit real - but nothing on
  // the page says the limit bit, because that would be a hint an attacker
  // could use the same way the enumeration defence in question 6 is careful
  // not to give one.
  const third = await requestCode(sag, EMAIL);
  assert.match(third.html, /<h1>Check your email<\/h1>/, 'the ordinary code screen, not an error');
  assert.ok(!/already been sent|today|wait/i.test(third.html), 'no wording gives away the refusal');
  assert.ok(!third.code, 'and no third code was generated');

  const other = await requestCode(sag, 'someone.else@example.org');
  assert.ok(other.code, 'a different address is unaffected');
});

test('resending is refused by the same limit, quietly, and the earlier code still works', async () => {
  const sag = createInstance({ STATE_STORE_BACKEND: 'memory', OTP_SEND_BURST: '1' });
  const first = await requestCode(sag, EMAIL);

  const resent = await sag.postForm('/authorize/resend', { tx: first.tx });
  const html = await resent.text();
  assert.ok(!/already been sent|ask for another|wait/i.test(html), 'nothing hints that the resend was dropped');
  // The code they already have still works, so the refusal is not a dead end.
  const done = await sag.postForm('/authorize/otp', { tx: extractField(html), code: first.code });
  assert.equal(done.status, 303, 'the code already sent must still be accepted');
});

test('the daily ceiling stops an address being used to send mail all day, quietly', async () => {
  const sag = createInstance({
    STATE_STORE_BACKEND: 'memory',
    OTP_SEND_WINDOW: '0', // isolate the daily limit from the window one
    OTP_SEND_DAILY_LIMIT: '2',
  });

  assert.ok((await requestCode(sag, EMAIL)).code);
  assert.ok((await requestCode(sag, EMAIL)).code);
  const third = await requestCode(sag, EMAIL);
  assert.match(third.html, /<h1>Check your email<\/h1>/);
  assert.ok(!/too many|today|wait/i.test(third.html), 'no wording gives away the daily ceiling either');
  assert.ok(!third.code);
});

test('with no store there are no limits', async () => {
  const sag = createInstance();
  assert.ok((await requestCode(sag, EMAIL)).code);
  assert.ok((await requestCode(sag, EMAIL)).code, 'unenforced without a store, by design');
});

// ---------------------------------------------------------------------------
// The Cloudflare Durable Object
// ---------------------------------------------------------------------------

/** A stand-in for the Durable Object runtime state. */
function stubState() {
  const map = new Map();
  return {
    alarms: [],
    storage: {
      get: async (key) => map.get(key),
      put: async (key, value) => void map.set(key, value),
      deleteAll: async () => void map.clear(),
      setAlarm: async function (at) {
        this._at = at;
      },
    },
    blockConcurrencyWhile: (fn) => fn(),
  };
}

const post = (guard, body) =>
  guard.fetch(
    new Request('https://sag-state.internal/claim', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    }),
  );

test('the Durable Object claims once and refuses afterwards', async () => {
  const guard = new StateGuard(stubState());
  const claim = () => post(guard, { id: 'code-1', ttlSeconds: 120 });

  assert.deepEqual(await (await claim()).json(), { fresh: true });
  assert.deepEqual(await (await claim()).json(), { fresh: false });

  // After the alarm empties the object the identifier is free again, which is
  // correct: by then the code has long expired on its own.
  await guard.alarm();
  assert.deepEqual(await (await claim()).json(), { fresh: true });
});

test('the Durable Object counts without extending its own window', async () => {
  const state = stubState();
  const guard = new StateGuard(state);
  const hit = () => post(guard, { op: 'increment', id: 'otp-day:abc', ttlSeconds: 86400 });

  assert.deepEqual(await (await hit()).json(), { count: 1 });
  const deadline = state.storage._at;
  assert.deepEqual(await (await hit()).json(), { count: 2 });
  assert.equal(state.storage._at, deadline, 'a daily limit must not become a rolling one');
});

test('the Durable Object refuses a malformed request', async () => {
  const guard = new StateGuard(stubState());
  assert.equal((await post(guard, 'not json')).status, 400);
  assert.equal((await post(guard, { ttlSeconds: 60 })).status, 400);
  assert.equal((await guard.fetch(new Request('https://sag-state.internal/claim'))).status, 405);
});

test('the Durable Object store routes one object per key', async () => {
  const objects = new Map();
  const asked = [];
  const namespace = {
    idFromName: (name) => {
      asked.push(name);
      return name;
    },
    get: (id) => {
      if (!objects.has(id)) objects.set(id, new StateGuard(stubState()));
      return { fetch: (url, init) => objects.get(id).fetch(new Request(url, init)) };
    },
  };
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    STATE_STORE_BACKEND: 'cf-durable-object',
  });
  const store = await createStateStore(config, { SAG_STATE: namespace });

  assert.equal(store.backend, 'cf-durable-object');
  assert.equal(store.atomic, true);
  assert.equal(await store.claim('code-a', 60), true);
  assert.equal(await store.claim('code-a', 60), false);
  assert.equal(await store.claim('code-b', 60), true, 'a separate object, so no contention');
  assert.equal(await store.increment('hits-a', 3600), 1);
  assert.equal(await store.increment('hits-a', 3600), 2);
  assert.deepEqual(asked, ['code-a', 'code-a', 'code-b', 'hits-a', 'hits-a']);
});

test('a missing Durable Object binding is a configuration error, not a silent pass', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    STATE_STORE_BACKEND: 'cf-durable-object',
  });
  await assert.rejects(() => createStateStore(config, {}), /no Durable Object namespace is bound as SAG_STATE/);
});

// ---------------------------------------------------------------------------
// DynamoDB
// ---------------------------------------------------------------------------

function dynamoStub(responder) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    calls.push({ url: typeof input === 'string' ? input : input.url, init });
    return responder(calls.length, init);
  };
  return {
    calls,
    restore: () => {
      globalThis.fetch = real;
    },
  };
}

const dynamoConfig = () =>
  loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    STATE_STORE_BACKEND: 'dynamodb',
    STATE_STORE_TABLE: 'sag-state',
    STATE_STORE_REGION: 'eu-west-2',
  });

const awsEnv = { AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE', AWS_SECRET_ACCESS_KEY: 'secret' };

test('DynamoDB claims with a conditional write and reads the refusal correctly', async (t) => {
  const stub = dynamoStub((n) =>
    n === 1
      ? new Response('{}', { status: 200 })
      : new Response(
          JSON.stringify({ __type: 'com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException' }),
          { status: 400 },
        ),
  );
  t.after(stub.restore);

  const store = await createStateStore(dynamoConfig(), awsEnv);
  assert.equal(await store.claim('code-1', 120), true);
  assert.equal(await store.claim('code-1', 120), false);

  const body = JSON.parse(stub.calls[0].init.body);
  assert.equal(body.TableName, 'sag-state');
  assert.equal(body.Item.jti.S, 'code-1');
  // The condition is what makes this atomic rather than a read-then-write,
  // and the second half of it matters as much as the first: DynamoDB deletes
  // expired items on its own schedule, documented as within 48 hours, so
  // without it a ten minute send limit would lock an address out for two days.
  assert.equal(body.ConditionExpression, 'attribute_not_exists(jti) OR #expires < :now');
  assert.equal(body.ExpressionAttributeNames['#expires'], 'expires_at');
  assert.match(body.ExpressionAttributeValues[':now'].N, /^\d+$/);
  // The TTL attribute must be a number, or DynamoDB ignores it and the table
  // grows forever.
  assert.match(body.Item.expires_at.N, /^\d+$/);
  assert.equal(stub.calls[0].init.headers['x-amz-target'], 'DynamoDB_20120810.PutItem');
  assert.match(stub.calls[0].init.headers.authorization, /^AWS4-HMAC-SHA256 .*\/dynamodb\/aws4_request/);
});

test('DynamoDB counts with ADD, which is atomic, and sets the deadline once', async (t) => {
  const stub = dynamoStub((n) => new Response(JSON.stringify({ Attributes: { hits: { N: String(n) } } }), { status: 200 }));
  t.after(stub.restore);

  const store = await createStateStore(dynamoConfig(), awsEnv);
  assert.equal(await store.increment('otp-day:abc', 86400), 1);
  assert.equal(await store.increment('otp-day:abc', 86400), 2);

  const body = JSON.parse(stub.calls[0].init.body);
  assert.equal(stub.calls[0].init.headers['x-amz-target'], 'DynamoDB_20120810.UpdateItem');
  assert.match(body.UpdateExpression, /ADD #hits :one/);
  // if_not_exists keeps a daily bucket daily rather than rolling forward with
  // every request.
  assert.match(body.UpdateExpression, /if_not_exists\(#expires, :exp\)/);
});

test('a DynamoDB failure refuses the exchange rather than waving it through', async (t) => {
  const stub = dynamoStub(() => new Response('{"__type":"InternalServerError"}', { status: 500 }));
  t.after(stub.restore);

  const store = await createStateStore(dynamoConfig(), awsEnv);
  // Letting it through would quietly disable the control whenever the table is
  // unreachable, which is exactly when an attacker would want it disabled.
  await assert.rejects(() => store.claim('code-1', 120), /state store write failed/);
});

test('DynamoDB refuses to start without a table or a region', async () => {
  await assert.rejects(
    () =>
      createStateStore(
        loadConfig({ SAG_ISSUER: 'http://localhost:8787', STATE_STORE_BACKEND: 'dynamodb' }),
        awsEnv,
      ),
    /no table name is set/,
  );
});

test('a store failure surfaces as a refusal at the token endpoint, not a token', async (t) => {
  const sag = createInstance({
    STATE_STORE_BACKEND: 'dynamodb',
    STATE_STORE_TABLE: 'sag-state',
    STATE_STORE_REGION: 'eu-west-2',
    ...awsEnv,
  });
  // Sign in first, so the stub only ever sees the token exchange: the rate
  // limit check deliberately fails open, and this is about the one that does
  // not.
  const flow = await signInWithOtp(sag, { email: EMAIL });

  const stub = dynamoStub(() => new Response('{"__type":"InternalServerError"}', { status: 500 }));
  t.after(stub.restore);
  const { res, body } = await redeem(sag, flow);
  assert.equal(res.status, 500);
  assert.equal(body.error, 'server_error');
});

test('a rate limit store outage does not stop people signing in', async (t) => {
  const stub = dynamoStub(() => new Response('{"__type":"InternalServerError"}', { status: 500 }));
  t.after(stub.restore);

  // Unlike a replayed code, this control protects the operator's mail bill
  // rather than somebody's account, so an outage must not lock everybody out.
  const sag = createInstance({
    STATE_STORE_BACKEND: 'dynamodb',
    STATE_STORE_TABLE: 'sag-state',
    STATE_STORE_REGION: 'eu-west-2',
    ...awsEnv,
  });
  const { code } = await requestCode(sag, EMAIL);
  assert.ok(code, 'the code is still sent when the counter cannot be read');
});
