// SAG - Smart Access Gateway.
//
// The core is one function: a standard Request in, a standard Response out.
// Every platform adapter is therefore a thin shim, and the same code runs
// unchanged on Cloudflare Workers, AWS Lambda and a local Node process.

export { handleRequest, ROUTES } from './router.js';
export { createContext, resetContextCache } from './context.js';
export { loadConfig, assertUsable, ConfigError } from './config.js';
export { createSignerSet } from './keys/registry.js';
export { cryptoReport, supportsAlg } from './crypto/capabilities.js';
export { ACR, AMR, satisfies as acrSatisfies } from './acr.js';

import { handleRequest } from './router.js';

/**
 * Build a fetch handler bound to one environment.
 *
 * @param {object} env    Environment bag
 * @param {object} [opts]
 * @returns {(request: Request) => Promise<Response>}
 */
export function createApp(env, opts = {}) {
  return (request) => handleRequest(request, env, opts);
}
