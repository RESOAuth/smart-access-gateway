// Cloudflare Workers entry point.
//
// Workers already speak the Fetch API, so there is nothing to translate. The
// environment bag arrives as the second argument and carries both plain
// variables and bindings - a KV namespace for clients, a service binding for
// the HSM Worker - which is exactly the shape src/config.js expects.

import { handleRequest } from '../../src/index.js';

// Re-exported so wrangler can find the class for the SAG_STATE binding. It is
// only used when STATE_STORE_BACKEND is cf-durable-object.
export { StateGuard } from './state-do.js';

export default {
  /**
   * @param {Request} request
   * @param {object} env    Variables, secrets and bindings
   * @param {object} ctx    Execution context
   */
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
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
