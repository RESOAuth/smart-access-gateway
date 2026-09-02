// Cloudflare Workers entry point.
//
// Workers already speak the Fetch API, so there is nothing to translate. The
// environment bag arrives as the second argument and carries both plain
// variables and bindings - a KV namespace for clients, a service binding for
// the HSM Worker - which is exactly the shape src/config.js expects.

import { handleRequest } from '../../src/index.js';
import { createDnsResolver } from './dns.js';

// Re-exported so wrangler can find the class for the SAG_STATE binding. It is
// only used when STATE_STORE_BACKEND is cf-durable-object.
export { StateGuard } from './state-do.js';

/**
 * The env bag with the platform resolver added, so the core resolves names
 * through `node:dns` rather than falling back to DNS-over-HTTPS - which does
 * not work from a Worker.
 *
 * Memoised against the bag Workers hands in, rather than rebuilt per request,
 * because the request context caches against that object's identity and a
 * fresh copy each time would throw the config away on every request. The
 * bindings object itself is left alone: it may be frozen, and it is shared.
 */
const wrapped = new WeakMap();

export function envWithResolver(env) {
  if (!env || typeof env !== 'object') return env;
  const cached = wrapped.get(env);
  if (cached) return cached;

  const binding = env.DNS_BINDING || 'SAG_DNS';
  // A real binding wins, and so does an explicitly configured DNS-over-HTTPS
  // endpoint: an operator who set one asked for it.
  const bag =
    env[binding] || env.DNS_RESOLVER_URL
      ? env
      : { ...env, [binding]: createDnsResolver({ timeoutMs: Number(env.DNS_TIMEOUT_MS) || 1500 }) };

  wrapped.set(env, bag);
  return bag;
}

export default {
  /**
   * @param {Request} request
   * @param {object} env    Variables, secrets and bindings
   * @param {object} ctx    Execution context
   */
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, envWithResolver(env));
    } catch (err) {
      // A throw here means the router itself failed, which is a bug. Log it
      // where wrangler tail will show it and answer with nothing useful.
      console.error('[sag] unhandled: ' + (err?.stack || err) + ' ' + JSON.stringify(ctx));
      return new Response('Internal error', {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
  },
};
