// Per-request context.
//
// Building a signer means generating or importing key material, and on the KMS
// and HSM backends it means a network call, so it must not happen per request.
// The expensive parts are therefore cached against the environment bag that
// produced them, which is exactly the lifetime a Worker isolate or a warm
// Lambda container has.

import { loadConfig, assertUsable } from './config.js';
import { createSignerSet } from './keys/registry.js';
import { createEmailSender } from './email/index.js';
import { resolveClient } from './clients/index.js';
import { createClientStore } from './clients/store.js';
import { createStateStore } from './store/index.js';
import { createPeerJwks } from './keys/peers.js';
import { CSS_VERSION, assetVersion } from './ui/css.js';
import { JS_VERSION } from './ui/js.js';
import { contentSecurityPolicy } from './ui/csp.js';

const cache = new WeakMap();
// A plain object env (process.env, or a test bag) is not always the same
// reference, so fall back to a single slot keyed by the resolved issuer.
const fallbackCache = new Map();

function cacheFor(env) {
  if (env && typeof env === 'object') {
    let slot = cache.get(env);
    if (!slot) {
      slot = {};
      cache.set(env, slot);
    }
    return slot;
  }
  return fallbackCache;
}

/**
 * Resolve configuration and shared services for a request.
 *
 * @param {object} env      Environment bag
 * @param {Request} request
 * @param {object} [opts]   { requestUrl } to override issuer derivation
 */
export async function createContext(env, request, opts = {}) {
  const url = new URL(request.url);
  const slot = cacheFor(env);

  if (!slot.config) {
    slot.config = loadConfig(env, { requestUrl: opts.requestUrl ?? request.url });
    assertUsable(slot.config);
    // A Worker or a Lambda has no start-up banner, and /healthz no longer
    // publishes the warnings that name an absent defence, so the log stream is
    // the only place left to say them. Once per isolate, not per request.
    const startup = makeLogger(slot.config);
    for (const warning of [...slot.config.warnings, ...slot.config.internalWarnings]) {
      startup.warn('configuration warning', { detail: warning });
    }
  }
  const config = slot.config;

  if (!slot.signerSet) slot.signerSet = createSignerSet(config, env);
  if (!slot.emailSender) slot.emailSender = createEmailSender(config, env);
  if (!slot.store) slot.store = createClientStore(config, env);
  if (!slot.stateStore) slot.stateStore = createStateStore(config, env);

  const [signerSet, emailSender, store, stateStore] = await Promise.all([
    slot.signerSet,
    slot.emailSender,
    slot.store,
    slot.stateStore,
  ]);
  // Synchronous - it only picks a cache backend, it never fetches a peer
  // itself - so it stays outside the Promise.all above.
  if (!slot.peerJwks) slot.peerJwks = createPeerJwks(config, env);
  const peerJwks = slot.peerJwks;

  const basePath = config.basePath;
  const path = url.pathname.startsWith(basePath) ? url.pathname.slice(basePath.length) || '/' : url.pathname;

  // Both are derived from configuration alone, so they are worked out once per
  // isolate rather than per request. The version query is what lets the static
  // assets be cached for a year and still change with a deployment.
  if (!slot.csp) slot.csp = contentSecurityPolicy(config);
  if (!slot.assets) {
    slot.assets = {
      css: basePath + '/static/sag.css?v=' + CSS_VERSION,
      js: basePath + '/static/sag.js?v=' + JS_VERSION,
      custom: config.ui.customCssSnippet
        ? basePath + '/static/custom.css?v=' + assetVersion(config.ui.customCssSnippet)
        : undefined,
    };
  }

  return {
    env,
    request,
    url,
    path,
    config,
    issuer: config.issuer,
    basePath,
    ui: config.ui,
    assets: slot.assets,
    csp: slot.csp,
    signerSet,
    emailSender,
    store,
    stateStore,
    peerJwks,
    /** Absolute URL for one of our own endpoints. */
    absolute: (p) => config.issuer + p,
    /** Path for a form action, kept relative so a proxy prefix survives. */
    route: (p) => (basePath || '') + p,
    resolveClient: (clientId) => resolveClient(config, clientId, { store }),
    log: makeLogger(config),
  };
}

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

/**
 * Structured logging.
 *
 * Nothing that identifies a person goes in unless the caller says so
 * explicitly, and an email address never does: the OTP path logs a hashed tag
 * instead, so a log file cannot be turned into a mailing list.
 */
function makeLogger(config) {
  const threshold = LEVELS[config.logLevel] ?? LEVELS.info;
  const emit = (level, message, fields) => {
    if (LEVELS[level] < threshold) return;
    const line = { level, msg: message, ...fields };
    const text = config.devMode ? formatDev(level, message, fields) : JSON.stringify(line);
    if (level === 'error') console.error(text);
    else if (level === 'warn') console.warn(text);
    else console.log(text);
  };
  return {
    debug: (m, f) => emit('debug', m, f),
    info: (m, f) => emit('info', m, f),
    warn: (m, f) => emit('warn', m, f),
    error: (m, f) => emit('error', m, f),
  };
}

function formatDev(level, message, fields) {
  const tail = fields && Object.keys(fields).length
    ? ' ' + Object.entries(fields).map(([k, v]) => k + '=' + JSON.stringify(v)).join(' ')
    : '';
  return level.toUpperCase().padEnd(5) + ' ' + message + tail;
}

export function resetContextCache() {
  fallbackCache.clear();
}
