#!/usr/bin/env node
// The local development server.
//
// Node's http module is not the Fetch API, so this adapter's whole job is
// translating between the two. It also prints a start-up report, because the
// most common local problem is not knowing which optional pieces are active.

import { createServer } from 'node:http';
import { join } from 'node:path';
import { handleRequest } from '../../src/index.js';
import { loadConfig } from '../../src/config.js';
import { cryptoReport } from '../../src/crypto/capabilities.js';
import { createSignerSet } from '../../src/keys/registry.js';
import { createFileClientStore } from './client-files.js';
import { createDnsResolver } from './dns.js';
import { SECURITY_HEADERS } from '../../src/util/http.js';

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || '127.0.0.1';
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

class RequestBodyTooLargeError extends Error {}

/**
 * The environment bag the core sees.
 *
 * Everything in it is a string except the bindings, which is how the core
 * takes a KV namespace on Workers. A directory of relying party records is
 * the same idea with a filesystem behind it, built here because the core has
 * to bundle for a runtime that has none. Built once, because the request
 * context caches against this object.
 */
function buildEnv() {
  const bag = { ...process.env };
  // The platform resolver, so the DNS provider hint asks the host's own
  // resolver rather than a public DNS-over-HTTPS service.
  bag[process.env.DNS_BINDING || 'SAG_DNS'] = createDnsResolver({
    timeoutMs: Number(process.env.DNS_TIMEOUT_MS || 1500),
  });
  if (process.env.CLIENTS_STORE_BACKEND === 'file') {
    const dir =
      process.env.CLIENTS_STORE_DIR || join(process.env.SAG_DATA_DIR || './data', 'clients');
    bag[process.env.CLIENTS_STORE_KV_BINDING || 'SAG_CLIENTS'] = createFileClientStore(dir);
  }
  return bag;
}

const env = buildEnv();

/** Node request -> Fetch Request. */
async function toFetchRequest(req, origin) {
  const url = origin + req.url;
  const headers = new Headers();
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    // eslint-disable-next-line security/detect-object-injection -- integer index into rawHeaders array
    headers.append(req.rawHeaders[i], req.rawHeaders[i + 1]);
  }
  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      // The core caps bodies too, but stopping here avoids buffering a large
      // upload only to reject it afterwards.
      if (total > MAX_REQUEST_BODY_BYTES) throw new RequestBodyTooLargeError('request body too large');
      chunks.push(chunk);
    }
    body = Buffer.concat(chunks);
  }
  return new Request(url, { method: req.method, headers, body, duplex: body ? 'half' : undefined });
}

/**
 * Set-Cookie is the one header that legitimately repeats, and reading it with
 * headers.get() would join the values with a comma and corrupt them. undici
 * exposes them separately through getSetCookie.
 */
function collectCookies(response) {
  return typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
}

const server = createServer(async (req, res) => {
  const origin = 'http://' + (req.headers.host || host + ':' + port);
  const started = Date.now();
  try {
    const request = await toFetchRequest(req, origin);
    const response = await handleRequest(request, env, { requestUrl: request.url });

    const headers = {};
    response.headers.forEach((value, key) => {
      // eslint-disable-next-line security/detect-object-injection -- copying standard HTTP response header keys
      if (key.toLowerCase() !== 'set-cookie') headers[key] = value;
    });
    const cookies = collectCookies(response);
    res.writeHead(response.status, cookies.length ? { ...headers, 'set-cookie': cookies } : headers);
    if (response.body) res.end(Buffer.from(await response.arrayBuffer()));
    else res.end();

    if ((process.env.LOG_LEVEL || 'debug') === 'debug') {
      console.log(
        '      ' + req.method.padEnd(4) + ' ' + response.status + ' ' + req.url.split('?')[0] + ' (' + (Date.now() - started) + 'ms)',
      );
    }
  } catch (err) {
    console.error('[sag] request failed:', err);
    const tooLarge = err instanceof RequestBodyTooLargeError;
    if (!res.headersSent) {
      res.writeHead(tooLarge ? 413 : 500, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        ...SECURITY_HEADERS,
      });
    }
    res.end(tooLarge ? 'Request body too large' : 'Internal error');
  }
});

async function banner() {
  const origin = 'http://' + (host === '0.0.0.0' ? 'localhost' : host) + ':' + port;
  let config;
  try {
    config = loadConfig(env, { requestUrl: origin + '/' });
  } catch (err) {
    console.error('\n  Configuration error:\n  ' + err.message + '\n');
    process.exit(1);
  }

  const lines = [
    '',
    '  SAG - Smart Access Gateway',
    '  ' + '-'.repeat(46),
    '  Issuer      ' + config.issuer,
    '  Discovery   ' + config.issuer + '/.well-known/openid-configuration',
    '  Mode        ' + (config.devMode ? 'development' : 'production'),
    '  Signing     ' + config.signing.backend + ' / ' + [config.signing.alg, ...config.signing.additionalAlgs].join(', '),
    '  Sessions    ' + config.session.scope + ', idle ' + config.session.idleTtlSeconds + 's',
    '  Upstreams   ' +
      (config.upstreams.length
        ? config.upstreams.map((u) => u.provider + ':' + u.domain).join(', ')
        : 'none configured'),
    '  Email OTP   ' +
      (config.otp.enabled
        ? config.email.provider + ', ' + config.otp.codeLength + ' character codes'
        : 'disabled'),
    '  State store ' +
      (config.stateStore.backend === 'none'
        ? 'none (codes and assertions are replayable, copied sessions survive logout, and OTP sends are not rate limited)'
        : config.stateStore.backend +
          ' (single-use codes and client assertions, session revocation; ' +
          config.otp.sendBurst +
          ' codes per ' +
          config.otp.sendWindowSeconds +
          's and ' +
          config.otp.sendDailyLimit +
          ' a day per address)'),
    '  Clients     ' +
      (config.clients.static.length
        ? config.clients.static.map((c) => c.clientId).join(', ')
        : 'none static') +
      (config.clients.cimd.enabled ? ' (+ CIMD)' : ''),
  ];

  const report = await cryptoReport();
  lines.push('  Signatures  ' + report.supported.join(', ') + (report.unsupported.length ? '  (unavailable: ' + report.unsupported.join(', ') + ')' : ''));
  if (!report.postQuantumSignatures) {
    lines.push('              No post-quantum signature algorithm is available on this runtime.');
  }

  if (config.problems.length) {
    lines.push('', '  Problems:');
    for (const p of config.problems) lines.push('   !  ' + p);
  }
  const warnings = [...config.warnings, ...config.internalWarnings];
  if (warnings.length) {
    lines.push('', '  Warnings:');
    for (const w of warnings) lines.push('   -  ' + w);
  }

  // Fail fast rather than serve something insecure.
  if (config.problems.length) {
    console.log(lines.join('\n') + '\n');
    console.error('  Refusing to start. Fix the problems above.\n');
    process.exit(1);
  }

  try {
    const signerSet = await createSignerSet(config, env);
    for (const skip of signerSet.skipped) {
      lines.push('   -  Skipped ' + skip.alg + ': ' + skip.reason);
    }
  } catch (err) {
    console.log(lines.join('\n') + '\n');
    console.error('  Could not initialise a signing key: ' + err.message + '\n');
    process.exit(1);
  }

  // A directory of relying parties is easy to get wrong quietly - a typo in
  // the path reads as "no clients configured" - so say what is actually there.
  const clientFiles = env[process.env.CLIENTS_STORE_KV_BINDING || 'SAG_CLIENTS'];
  if (clientFiles?.list) {
    const files = await clientFiles.list();
    lines.push(
      '  Client files ' + files.length + ' in ' + clientFiles.dir + (files.length ? ': ' + files.join(', ') : ''),
    );
  }

  lines.push('', '  Listening on ' + origin, '');
  console.log(lines.join('\n'));
}

server.listen(port, host, banner);

for (const signal of ['SIGINT', 'SIGTERM']) {
  // SIGINT is Ctrl-C; SIGTERM is what a container runtime sends. Handling only
  // the first means every `docker compose restart` waits ten seconds for the
  // grace period to expire and then kills the process instead.
  process.on(signal, () => {
    console.log('\n  Stopping.');
    server.close(() => process.exit(0));
    // Nothing here is worth waiting on: a request in flight is a sign-in
    // somebody can start again, so a stop that hangs is worse than a stop that
    // drops it.
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
