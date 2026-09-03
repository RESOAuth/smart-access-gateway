// Peer deployments of the same issuer, and the public keys they hold.
//
// A multi-region or multi-cloud deployment can run one issuer as several
// independent instances, each signing with its own locally-held key rather
// than a private key copied between clouds - see docs/multi-region.md. For a
// relying party to treat every instance's tokens interchangeably, every
// instance's JWKS has to describe every other instance's keys as well as its
// own, so each instance fetches its peers' JWKS, merges the public keys into
// its own, and caches what it found for long enough that a peer going away
// does not make the tokens it already issued suddenly unverifiable.
//
// Failures are remembered too, briefly. Caching only successes would mean a
// peer that has never answered is re-fetched on every single request, so an
// unreachable peer would cost the whole fetch timeout on the request path of
// /jwks.json - the one endpoint every relying party calls to verify a token.
//
// Listing a URL in PEER_JWKS_URLS is not "share a public key for
// convenience": whatever keys it returns are trusted for this issuer as
// fully as this instance's own signer set, because that is exactly what
// letting relying parties treat every instance interchangeably requires.
// Only ever list a deployment's own peers.

import { fetchWithTimeout, readTextLimited } from '../util/http.js';
import { signRequest, credentialsFromEnv } from '../crypto/sigv4.js';
import { nowSeconds } from '../util/bytes.js';

/**
 * The query parameter a peer fetch carries, which /jwks.json answers with this
 * instance's own keys only.
 *
 * Peers are configured to point at each other's /.well-known/jwks.json, which
 * is the *merged* document - so fetching a peer is itself a request that
 * fetches every one of that peer's peers, and in a complete mesh of n
 * instances all cold at once, which is what a coordinated deployment produces,
 * that fans out exponentially. The requests that lose the race time out, and a
 * timed-out peer publishes a JWKS missing an instance's keys. Asking for the
 * local-only document makes one peer fetch cost exactly one peer's response.
 *
 * Nothing is lost by not being told a peer's peers: the mesh has to be complete
 * anyway (docs/multi-region.md), so this instance already asks each of them
 * itself, and it no longer trusts a key transitively via a peer that it did not
 * list. A distinct query string also keeps the two documents apart in any cache
 * in front of the peer, and a peer running an older release ignores the
 * parameter and answers with the merged document, which is a superset.
 */
export const PEER_FETCH_PARAM = 'sag_peer_fetch';

function peerFetchUrl(url) {
  const u = new URL(url);
  u.searchParams.set(PEER_FETCH_PARAM, '1');
  return u.href;
}

/** True when this request is another instance of this issuer fetching keys. */
export function isPeerFetch(url) {
  return url.searchParams.get(PEER_FETCH_PARAM) === '1';
}

/**
 * Fetch and validate one peer's JWKS. Never trusted blindly: capped in size,
 * parsed defensively, and stripped of anything that is not a bare public key
 * - a peer that ever answered with a private component by mistake must not
 * have it amplified into every other instance's published JWKS.
 */
async function fetchPeerJwks(url, { timeoutMs, maxBytes }, log) {
  const res = await fetchWithTimeout(peerFetchUrl(url), { headers: { accept: 'application/json' } }, timeoutMs);
  if (!res.ok) throw new Error('HTTP ' + res.status);
  // Counted while the body streams in, rather than after res.text() has
  // already allocated all of it - the reason readTextLimited exists.
  const raw = await readTextLimited(res, maxBytes);
  let body;
  try {
    body = JSON.parse(raw);
  } catch (cause) {
    throw new Error('response is not valid JSON', { cause });
  }
  if (!Array.isArray(body?.keys)) throw new Error('response has no "keys" array');

  const keys = [];
  for (const key of body.keys) {
    if (!key || typeof key !== 'object' || typeof key.kty !== 'string') continue;
    // "d" (EC/RSA/OKP) and "k" (symmetric) are the private/secret components
    // of a JWK. A genuine JWKS never carries either; a peer that did is
    // reporting a bug or a compromise, and republishing it would spread
    // whichever one it is to every relying party that fetches ours.
    if ('d' in key || 'k' in key) {
      log?.warn('peer jwks entry carried a private component and was dropped', { url, kid: key.kid });
      continue;
    }
    keys.push(key);
  }
  // A healthy instance always publishes at least one key: createSignerSet
  // refuses to start without a usable signer. So an empty answer is a peer
  // that is reachable but not serving - a signing backend that has just
  // started failing, an edge error page that happens to parse as JSON - and
  // caching it as a success would swap known-good keys for nothing for a
  // whole PEER_JWKS_CACHE_TTL, and on a shared cache backend would publish
  // that emptiness to every other instance too.
  if (keys.length === 0) throw new Error('response carried no usable public key');
  return keys;
}

// ---------------------------------------------------------------------------
// Cache backends
//
// Unlike src/store/index.js, eventual consistency here is fine - this is a
// resilience cache with a single writer path (this instance refreshing its
// own read), not a security control needing compare-and-set. That is exactly
// why Cloudflare KV, deliberately refused for state store, is the natural
// Cloudflare backend for this.
// ---------------------------------------------------------------------------

function createMemoryCache() {
  const entries = new Map();
  return {
    async get(url) {
      return entries.get(url);
    },
    async put(url, entry) {
      entries.set(url, entry);
    },
  };
}

function createKvCache(config, env) {
  const name = config.peerJwks.cacheKvBindingName;
  const binding = env?.[name];
  if (!binding || typeof binding.get !== 'function' || typeof binding.put !== 'function') {
    throw new Error('PEER_JWKS_CACHE_BACKEND is cf-kv but no KV namespace is bound as ' + name);
  }
  const keyFor = (url) => 'peer-jwks:' + url;
  return {
    async get(url) {
      return (await binding.get(keyFor(url), { type: 'json' })) ?? undefined;
    },
    async put(url, entry) {
      // KV wants a TTL of at least 60 seconds. It is set to the stale grace
      // period rather than the refresh interval, so a read is still there for
      // the whole time this instance is willing to trust it, even if nothing
      // ever refreshes the entry again.
      await binding.put(keyFor(url), JSON.stringify(entry), {
        expirationTtl: Math.max(60, config.peerJwks.staleTtlSeconds),
      });
    },
  };
}

/** DynamoDB, signed the same way src/store/index.js signs its own requests. */
function createDynamoCache(config, env) {
  const { cacheTable: table, cacheRegion: region } = config.peerJwks;
  if (!table) throw new Error('PEER_JWKS_CACHE_BACKEND is dynamodb but PEER_JWKS_CACHE_TABLE is not set');
  if (!region) throw new Error('PEER_JWKS_CACHE_BACKEND is dynamodb but neither PEER_JWKS_CACHE_REGION nor AWS_REGION is set');
  const endpoint = config.peerJwks.cacheEndpoint || 'https://dynamodb.' + region + '.amazonaws.com/';

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
    return fetchWithTimeout(endpoint, { method: 'POST', headers, body: payload }, 4000);
  };

  return {
    async get(url) {
      const res = await send('GetItem', { TableName: table, Key: { peer_url: { S: url } } });
      if (!res.ok) throw new Error('peer jwks cache read failed: HTTP ' + res.status);
      const body = await res.json();
      if (!body.Item) return undefined;
      return { keys: JSON.parse(body.Item.keys_json.S), fetchedAt: Number(body.Item.fetched_at.N) };
    },
    async put(url, entry) {
      const res = await send('PutItem', {
        TableName: table,
        Item: {
          peer_url: { S: url },
          keys_json: { S: JSON.stringify(entry.keys) },
          fetched_at: { N: String(entry.fetchedAt) },
          // The table's own TTL sweeps what this instance would have expired
          // anyway; the read path still checks fetchedAt itself, the same
          // belt-and-braces reason src/store/index.js checks expires_at.
          expires_at: { N: String(entry.fetchedAt + config.peerJwks.staleTtlSeconds) },
        },
      });
      if (!res.ok) throw new Error('peer jwks cache write failed: HTTP ' + res.status);
    },
  };
}

function createCache(config, env) {
  switch (config.peerJwks.cacheBackend) {
    case 'cf-kv':
      return createKvCache(config, env);
    case 'dynamodb':
      return createDynamoCache(config, env);
    default:
      return createMemoryCache();
  }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * @returns {object|undefined} undefined when no peers are configured, which
 *   leaves /jwks.json exactly as it was: this instance's own keys only.
 */
export function createPeerJwks(config, env) {
  if (config.peerJwks.urls.length === 0) return undefined;
  const { urls, cacheTtlSeconds, staleTtlSeconds, retryAfterSeconds, timeoutMs, maxDocumentBytes, cacheBackend } =
    config.peerJwks;
  const cache = createCache(config, env);
  // When a peer may next be tried again, per URL. In this process only, and
  // never in the shared cache: a peer being unreachable from here says nothing
  // about whether it is reachable from another instance. Bounded by the
  // configured URL list, so there is nothing to evict.
  const retryAfter = new Map();
  // One resolution in flight per peer, shared by every request that arrives
  // while it runs. A cold isolate takes /jwks.json in bursts rather than one
  // at a time - a deployment, or a fleet of relying parties whose own caches
  // expired together - and without this each request would open its own
  // connection to every peer and make its own cache read, which on Workers
  // also counts against the subrequest limit.
  const inFlight = new Map();

  return {
    backend: cacheBackend,
    urls,

    /**
     * Merged public keys from every peer that is either reachable now or was
     * reachable within its stale grace period, and whether that is all of
     * them.
     */
    async collect({ log } = {}) {
      const perPeer = await Promise.all(urls.map((url) => keysFor(url, log)));
      return {
        keys: perPeer.flatMap((peer) => peer.keys),
        // A configured peer contributing nothing means the published JWKS is a
        // subset of what this issuer is actually signing with, which is a
        // different thing from merely being a few minutes old. What to do
        // about it is the caller's decision - see handleJwks.
        incomplete: perPeer.some((peer) => peer.keys.length === 0),
      };
    },

    /** Just the merged keys, for a caller with nothing to do about a gap. */
    async keys(opts) {
      return (await this.collect(opts)).keys;
    },

    /** Cache state for one peer, without a network fetch. For /healthz. */
    async peek(url) {
      try {
        return await cache.get(url);
      } catch {
        return undefined;
      }
    },

    async describe() {
      const now = nowSeconds();
      return Promise.all(
        urls.map(async (url) => {
          const cached = await this.peek(url);
          if (!cached) return { url, key_count: 0, last_fetched_seconds_ago: null, within_cache_ttl: false, within_grace_period: false };
          const age = now - cached.fetchedAt;
          return {
            url,
            // How many of the keys in /jwks.json came from this peer, so an
            // operator asking why a key is missing can see which peer is the
            // one not contributing it.
            key_count: cached.keys.length,
            last_fetched_seconds_ago: age,
            within_cache_ttl: age < cacheTtlSeconds,
            within_grace_period: age < staleTtlSeconds,
          };
        }),
      );
    },
  };

  /** One peer's keys, coalescing everything that asks while a fetch is open. */
  function keysFor(url, log) {
    const pending = inFlight.get(url);
    if (pending) return pending;
    const promise = resolveKeys(url, log).finally(() => inFlight.delete(url));
    inFlight.set(url, promise);
    return promise;
  }

  /** One peer's keys: fresh from cache, freshly fetched, or stale-but-graced. */
  async function resolveKeys(url, log) {
    let cached;
    try {
      cached = await cache.get(url);
    } catch (err) {
      log?.warn('peer jwks cache read failed', { url, error: err.message });
    }
    const now = nowSeconds();
    if (cached && now - cached.fetchedAt < cacheTtlSeconds) return { url, keys: cached.keys };

    // A peer that has just failed is not tried again for a moment. Only
    // successes are cached, so without this a peer that has never answered -
    // a wrong URL, a region still coming up, an outage - costs a full
    // PEER_JWKS_TIMEOUT_MS on the request path of every /jwks.json, which is
    // the request every relying party makes to verify a token.
    if (now < (retryAfter.get(url) ?? 0)) return { url, keys: graceKeys(cached, now) };

    try {
      const keys = await fetchPeerJwks(url, { timeoutMs, maxBytes: maxDocumentBytes }, log);
      retryAfter.delete(url);
      try {
        // Awaited rather than fired-and-forgotten: on Workers, a promise that
        // outlives the response is not guaranteed to finish without
        // waitUntil, which this platform-agnostic core has no access to.
        await cache.put(url, { keys, fetchedAt: now });
      } catch (err) {
        log?.warn('peer jwks cache write failed', { url, error: err.message });
      }
      return { url, keys };
    } catch (err) {
      if (retryAfterSeconds > 0) retryAfter.set(url, now + retryAfterSeconds);
      if (cached && now - cached.fetchedAt < staleTtlSeconds) {
        log?.warn('peer unreachable, serving its last known keys', { url, ageSeconds: now - cached.fetchedAt, error: err.message });
        return { url, keys: cached.keys };
      }
      log?.warn('peer unreachable and no usable cached keys remain', { url, error: err.message });
      return { url, keys: [] };
    }
  }

  /** What a peer still contributes while no fetch is being attempted for it. */
  function graceKeys(cached, now) {
    return cached && now - cached.fetchedAt < staleTtlSeconds ? cached.keys : [];
  }
}

/**
 * Merge this instance's own keys with its peers'. Own keys win on a `kid`
 * collision, the same precedence src/keys/registry.js already gives the
 * primary algorithm among this instance's own signers.
 */
export function mergeJwks(localKeys, peerKeys) {
  const keys = [...localKeys];
  const seen = new Set(localKeys.map((k) => k.kid || JSON.stringify(k)));
  for (const key of peerKeys) {
    const id = key.kid || JSON.stringify(key);
    if (seen.has(id)) continue;
    seen.add(id);
    keys.push(key);
  }
  return keys;
}
