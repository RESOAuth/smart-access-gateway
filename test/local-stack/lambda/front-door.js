#!/usr/bin/env node
// API Gateway, roughly, in front of the Lambda runtime interface emulator.
//
// The emulator in the AWS base image does not speak HTTP the way a browser
// does: it takes an invocation - a JSON event - on
// /2015-03-31/functions/function/invocations and hands back a JSON result. So
// something has to turn a real request into an HTTP API v2 event and the
// result back into a response, which is precisely the job API Gateway or a
// Lambda function URL does in a deployment.
//
// That makes this the only way to exercise adapters/lambda/handler.js for
// real: the base64 body handling, the separate `cookies` array that exists
// because several Set-Cookie headers would otherwise be joined with a comma,
// the stage prefix, the lowercased and comma-joined headers. Those are the
// parts that break, and none of them are visible when the handler is called
// directly from a test.
//
// It is deliberately thin and deliberately not a general API Gateway: one
// route, $default, proxying everything.

import { createServer } from 'node:http';

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || '0.0.0.0';
const runtime = process.env.LAMBDA_RUNTIME_URL || 'http://sag-lambda:8080';
const stage = process.env.LAMBDA_STAGE || '$default';
const invoke = runtime.replace(/\/+$/, '') + '/2015-03-31/functions/function/invocations';
const quiet = process.env.LOG_LEVEL === 'silent';

// Which bodies travel as text and which as base64. API Gateway decides this
// from the content type, and getting it wrong is how a JSON body arrives as
// gibberish, so the handler has to cope with both.
const TEXT_TYPES = /^(text\/|application\/(json|javascript|xml|x-www-form-urlencoded)|.*\+json)/;

function eventFor(req, url, body) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    // API Gateway lowercases names, joins repeats with a comma, and takes the
    // cookie header out into its own array.
    if (name === 'cookie') continue;
    headers[name] = Array.isArray(value) ? value.join(',') : String(value);
  }
  const cookies = (req.headers.cookie || '')
    .split(';')
    .map((c) => c.trim())
    .filter(Boolean);

  const isText = TEXT_TYPES.test(req.headers['content-type'] || 'text/plain');
  const now = new Date();

  return {
    version: '2.0',
    routeKey: '$default',
    rawPath: url.pathname,
    rawQueryString: url.search.replace(/^\?/, ''),
    ...(cookies.length ? { cookies } : {}),
    headers,
    requestContext: {
      accountId: '000000000000',
      apiId: 'sag-local-stack',
      domainName: req.headers.host || 'localhost',
      domainPrefix: 'sag-local-stack',
      http: {
        method: req.method,
        path: url.pathname,
        protocol: 'HTTP/1.1',
        sourceIp: req.socket.remoteAddress || '127.0.0.1',
        userAgent: req.headers['user-agent'] || '',
      },
      requestId: crypto.randomUUID(),
      routeKey: '$default',
      stage,
      time: now.toUTCString(),
      timeEpoch: now.getTime(),
    },
    ...(body.length
      ? { body: isText ? body.toString('utf8') : body.toString('base64'), isBase64Encoded: !isText }
      : { isBase64Encoded: false }),
  };
}

// One invocation at a time.
//
// The emulator is one execution environment, and a real Lambda's is too: a
// second concurrent request is what makes AWS start a second container. There
// is no second container here, so the emulator drops the overlapping invoke and
// the caller sees a connection failure rather than a queue. Serialising here is
// therefore the honest emulation of concurrency one - and without it the
// container healthcheck, which fires every ten seconds, intermittently knocks
// over whatever request it lands on top of.
let queue = Promise.resolve();

/**
 * Post one invocation, once the one before it has finished.
 *
 * The connection is not kept alive: the emulator closes idle sockets on its own
 * schedule, and a pooled socket closed at the far end fails the *next* request
 * rather than the one that went idle, which looks like a Lambda that
 * intermittently does not answer. A connection-level failure is retried once
 * as well, because a socket refused or reset before the body went out never
 * reached the handler.
 */
function invokeFunction(body) {
  const attempt = () =>
    fetch(invoke, {
      method: 'POST',
      headers: { 'content-type': 'application/json', connection: 'close' },
      body,
      // A cold start under load can be slow, and a function that times out
      // should look like a gateway timeout rather than a hang.
      signal: AbortSignal.timeout(30_000),
    });

  const run = queue.then(
    () => attempt(),
    () => attempt(),
  ).catch((err) => {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') throw err;
    return attempt();
  });
  // The queue must survive a failed invocation, or one error would wedge every
  // request after it.
  queue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const started = Date.now();

  let result;
  try {
    const response = await invokeFunction(JSON.stringify(eventFor(req, url, Buffer.concat(chunks))));
    // The emulator reports an unhandled exception with this header, and the
    // body is the stack trace. Losing it would make every failure a blank 502.
    if (response.headers.get('x-amz-function-error')) {
      const detail = await response.text();
      console.error('  the function raised: ' + detail);
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('The Lambda function raised an error. The trace is in this container\'s log.\n');
    }
    result = await response.json();
  } catch (err) {
    console.error('  could not invoke ' + invoke + ': ' + err.message);
    res.writeHead(504, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('The Lambda runtime did not answer.\n');
  }

  if (typeof result?.statusCode !== 'number') {
    // A handler that returns something else is a bug worth naming: API Gateway
    // answers 502 and logs "malformed Lambda proxy response".
    console.error('  malformed proxy response: ' + JSON.stringify(result).slice(0, 300));
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('Malformed Lambda proxy response.\n');
  }

  const headers = { ...(result.headers || {}) };
  const body = result.isBase64Encoded ? Buffer.from(result.body || '', 'base64') : Buffer.from(result.body || '', 'utf8');
  res.writeHead(result.statusCode, {
    ...headers,
    ...(Array.isArray(result.cookies) && result.cookies.length ? { 'set-cookie': result.cookies } : {}),
    'content-length': body.length,
  });
  res.end(req.method === 'HEAD' ? undefined : body);

  if (!quiet) {
    console.log('  ' + req.method.padEnd(4) + ' ' + result.statusCode + ' ' + url.pathname + ' (' + (Date.now() - started) + 'ms)');
  }
});

server.listen(port, host, () => {
  console.log(
    ['', '  API Gateway (local stack)', '  ' + '-'.repeat(46), '  Invoking    ' + invoke, '  Stage       ' + stage, '  Listening   http://' + host + ':' + port, ''].join('\n'),
  );
});

process.on('SIGINT', () => server.close(() => process.exit(0)));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
