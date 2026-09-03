// The one place SAG keeps state, and it is optional.
//
// Everything else is sealed into a token the browser carries, but two
// questions cannot be answered that way, because the answer changes and the
// party we are guarding against is the one holding the token:
//
//   1. "Has this authorisation code been redeemed?" - single-use codes.
//   2. "Has this client assertion been presented?" - assertion replay defence.
//   3. "How many codes has this address asked for?" - OTP send limits.
//   4. "Has this session been signed out?" - copied-cookie revocation.
//
// Both reduce to two tiny primitives, so they share one store rather than
// each growing their own:
//
//   claim(id, ttl)      true the first time, false every time after
//   has(id)             whether a live claim exists
//   increment(key, ttl) the running count, starting at 1
//
// Both have to be atomic, which is why Cloudflare KV is deliberately not an
// option here: it has no compare-and-set and is eventually consistent, so a
// read-then-write would be a race, and a security control that fails silently
// under load is worse than an honest absence.

import { fetchWithTimeout } from '../util/http.js';
import { signRequest, credentialsFromEnv } from '../crypto/sigv4.js';
import { nowSeconds } from '../util/bytes.js';

/**
 * A single-process store.
 *
 * Correct for one Node process or one container, and for tests. It is useless
 * across instances, so config.js warns when more than one is plausible.
 *
 * The map is capped, because a store that grows without bound is a memory
 * exhaustion bug waiting for a busy afternoon. Expired records are swept
 * first; only if that is not enough are the oldest records dropped, which for
 * equal lifetimes are the ones nearest to expiring anyway.
 */
export function createMemoryStore({ maxEntries = 10000 } = {}) {
  // Two maps, not one. A counter lives for a day and a claim lives for a
  // minute, so a flood of counters would otherwise evict live claims - and a
  // dropped claim silently re-enables the very replay it exists to prevent.
  const claims = new Map(); // id -> expiresAt
  const counters = new Map(); // key -> { expiresAt, count }

  const sweep = (map, now) => {
    for (const [key, entry] of map) {
      const expiry = typeof entry === 'number' ? entry : entry.expiresAt;
      if (expiry < now) map.delete(key);
    }
  };

  return {
    backend: 'memory',
    atomic: true,
    async claim(id, ttlSeconds) {
      const now = nowSeconds();
      const existing = claims.get(id);
      if (existing !== undefined && existing >= now) return false;
      if (claims.size >= maxEntries) {
        sweep(claims, now);
        if (claims.size >= maxEntries) {
          // Refusing is the safe answer: evicting a live claim would let a
          // spent code be spent again, and quietly. The token exchange fails
          // and the person can start again.
          throw new Error(
            'the in-memory state store is full (' + maxEntries + ' live records). Raise STATE_STORE_MAX_ENTRIES, or use a store that is not in-process.',
          );
        }
      }
      claims.set(id, now + Math.max(1, ttlSeconds));
      return true;
    },
    async has(id) {
      const now = nowSeconds();
      const expiry = claims.get(id);
      if (expiry === undefined) return false;
      if (expiry < now) {
        claims.delete(id);
        return false;
      }
      return true;
    },
    async increment(key, ttlSeconds) {
      const now = nowSeconds();
      const existing = counters.get(key);
      if (existing !== undefined && existing.expiresAt >= now) {
        existing.count += 1;
        return existing.count;
      }
      if (counters.size >= maxEntries) {
        sweep(counters, now);
        // Counters can be dropped where claims cannot: the worst case is an
        // address getting its send allowance back early, not a code being
        // redeemed twice. Oldest first, which for equal windows is the one
        // nearest to expiring anyway.
        let drop = Math.max(1, Math.ceil(maxEntries / 10));
        for (const oldest of counters.keys()) {
          if (counters.size < maxEntries) break;
          counters.delete(oldest);
          if (--drop <= 0) break;
        }
      }
      counters.set(key, { expiresAt: now + Math.max(1, ttlSeconds), count: 1 });
      return 1;
    },
    /** Test and diagnostic hook; never used in the request path. */
    size: () => claims.size + counters.size,
  };
}

/**
 * A Durable Object.
 *
 * Each object handles one request at a time, so both operations are genuinely
 * atomic, and addressing an object by the key spreads the load across as many
 * objects as there are keys. This is the right primitive on Cloudflare.
 */
export function createDurableObjectStore(config, env) {
  const name = config.stateStore.doBindingName;
  // eslint-disable-next-line security/detect-object-injection -- binding name is configured by operator
  const binding = env?.[name];
  if (!binding || typeof binding.idFromName !== 'function') {
    throw new Error('The state store backend is cf-durable-object but no Durable Object namespace is bound as ' + name);
  }
  const call = async (op, key, ttlSeconds) => {
    const stub = binding.get(binding.idFromName(key));
    const res = await stub.fetch('https://sag-state.internal/' + op, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op, id: key, ttlSeconds }),
    });
    if (!res.ok) throw new Error('state store returned HTTP ' + res.status);
    return res.json();
  };
  return {
    backend: 'cf-durable-object',
    atomic: true,
    async claim(id, ttlSeconds) {
      const body = await call('claim', id, ttlSeconds);
      return body.fresh === true;
    },
    async has(id) {
      const body = await call('has', id, 0);
      return body.claimed === true;
    },
    async increment(key, ttlSeconds) {
      const body = await call('increment', key, ttlSeconds);
      return Number(body.count) || 0;
    },
  };
}

/**
 * DynamoDB.
 *
 * PutItem with attribute_not_exists is an atomic claim, ADD is an atomic
 * counter, and a TTL attribute lets DynamoDB clear the records itself so
 * nothing has to sweep them.
 */
export function createDynamoStore(config, env) {
  const { table, region } = config.stateStore;
  if (!table) throw new Error('The state store backend is dynamodb but no table name is set');
  if (!region) throw new Error('The state store backend is dynamodb but no region is set');
  // A region still has to be set even when the endpoint is overridden: it is
  // part of the signature's scope, so the emulator has to agree about it too.
  const endpoint = config.stateStore.endpoint || 'https://dynamodb.' + region + '.amazonaws.com/';

  const send = async (target, body) => {
    const payload = JSON.stringify(body);
    const headers = await signRequest({
      method: 'POST',
      url: endpoint,
      body: payload,
      service: 'dynamodb',
      region,
      credentials: credentialsFromEnv(env ?? {}),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.' + target,
      },
    });
    return { res: await fetchWithTimeout(endpoint, { method: 'POST', headers, body: payload }, 4000), payload };
  };

  return {
    backend: 'dynamodb',
    atomic: true,
    async claim(id, ttlSeconds) {
      const now = nowSeconds();
      const { res } = await send('PutItem', {
        TableName: table,
        Item: {
          jti: { S: id },
          // The attribute DynamoDB's TTL is configured against. It has to be
          // seconds since the epoch as a number, not a string.
          expires_at: { N: String(now + Math.max(60, ttlSeconds)) },
        },
        // The whole point: the write fails if the key has been seen. The
        // second half matters as much as the first, because DynamoDB deletes
        // expired items on its own schedule - documented as within 48 hours -
        // so an expired record is still sitting there. Without it a ten minute
        // send limit would lock an address out for two days.
        ConditionExpression: 'attribute_not_exists(jti) OR #expires < :now',
        ExpressionAttributeNames: { '#expires': 'expires_at' },
        ExpressionAttributeValues: { ':now': { N: String(now) } },
      });
      if (res.ok) return true;

      const detail = await res.text().catch(() => '');
      if (res.status === 400 && detail.includes('ConditionalCheckFailedException')) {
        return false; // Already claimed. This is the expected refusal.
      }
      // Any other failure is a store problem, not a replay. Refusing the
      // exchange is the safe answer: a person can start again, whereas letting
      // it through would quietly disable the control whenever the table is
      // unreachable.
      throw new Error('state store write failed (HTTP ' + res.status + '): ' + detail.slice(0, 200));
    },
    async has(id) {
      const now = nowSeconds();
      const { res } = await send('GetItem', {
        TableName: table,
        Key: { jti: { S: id } },
        ConsistentRead: true,
        ProjectionExpression: 'expires_at',
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error('state store read failed (HTTP ' + res.status + '): ' + detail.slice(0, 200));
      }
      const body = await res.json();
      return Number(body?.Item?.expires_at?.N) >= now;
    },
    async increment(key, ttlSeconds) {
      const { res } = await send('UpdateItem', {
        TableName: table,
        Key: { jti: { S: key } },
        // if_not_exists keeps a window a window: counting again must not push
        // the deadline forward, or a daily limit becomes a rolling one.
        UpdateExpression: 'SET #expires = if_not_exists(#expires, :exp) ADD #hits :one',
        ExpressionAttributeNames: { '#expires': 'expires_at', '#hits': 'hits' },
        ExpressionAttributeValues: {
          ':one': { N: '1' },
          ':exp': { N: String(nowSeconds() + Math.max(60, ttlSeconds)) },
        },
        ReturnValues: 'ALL_NEW',
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error('state store counter failed (HTTP ' + res.status + '): ' + detail.slice(0, 200));
      }
      const body = await res.json();
      return Number(body?.Attributes?.hits?.N) || 0;
    },
  };
}

/**
 * @returns {Promise<object|undefined>} undefined when no store is configured,
 *   which leaves codes and client assertions single-use by convention only,
 *   and OTP send limits unenforced. See docs/state-and-limits.md.
 */
export async function createStateStore(config, env) {
  switch (config.stateStore.backend) {
    case 'none':
      return undefined;
    case 'memory':
      return createMemoryStore({ maxEntries: config.stateStore.maxEntries });
    case 'cf-durable-object':
      return createDurableObjectStore(config, env);
    case 'dynamodb':
      return createDynamoStore(config, env);
    default:
      throw new Error('unknown state store backend: ' + config.stateStore.backend);
  }
}
