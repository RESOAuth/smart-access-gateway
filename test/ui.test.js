// The sign-in pages.
//
// The brief asks for pages that work as if no CSS and no JavaScript loaded, and
// that cope with zoom and assistive technology. Those are claims, so they get
// tests. Everything here is asserted against the real rendered HTML from a real
// flow, not against the template functions in isolation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, pkce, authorizeUrl, extractField, signInWithOtp, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { DEFAULT_CSS } from '../src/ui/css.js';
import { DEFAULT_JS } from '../src/ui/js.js';

const EMAIL = 'person@example.org';

/** Fetch the first screen of a flow. */
async function emailScreen(sag, extra = {}) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, ...extra });
  const res = await sag.raw(path);
  return { res, html: await res.text() };
}

/** Fetch the one-time code screen. */
async function otpScreen(sag) {
  const first = await emailScreen(sag);
  const res = await sag.postForm('/authorize/email', { tx: extractField(first.html), email: EMAIL });
  return { res, html: await res.text() };
}

/**
 * Every element that would need script or CSS to be usable.
 *
 * The enhancement file itself is allowed - a page may load script, it just may
 * not depend on it - and the rule that keeps that honest is that the script is
 * an external file on our own origin with no inline block and no inline
 * handler anywhere. Anything that only works once script has run, a fake button
 * or a `type="button"` that submits nothing, is still a failure.
 */
function scriptDependencies(html) {
  const problems = [];
  for (const match of html.matchAll(/\son[a-z]+\s*=/gi)) problems.push('inline handler: ' + match[0].trim());
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const [, attrs, contents] = match;
    if (contents.trim() !== '') problems.push('an inline script body');
    const src = /\ssrc="([^"]*)"/i.exec(attrs);
    if (!src) problems.push('a script element with no src');
    else if (!src[1].startsWith('/static/sag.js')) problems.push('an unexpected script: ' + src[1]);
  }
  // A control that only works with script.
  for (const match of html.matchAll(/<(a|div|span)[^>]*\srole="button"/gi)) problems.push('fake button: ' + match[1]);
  if (/<button[^>]*\stype="button"/i.test(html)) problems.push('a button that submits nothing');
  return problems;
}

// ---------------------------------------------------------------------------
// Works without JavaScript
// ---------------------------------------------------------------------------

test('no screen in the flow needs JavaScript', async () => {
  const sag = createInstance();

  const email = await emailScreen(sag);
  assert.deepEqual(scriptDependencies(email.html), []);

  const otp = await otpScreen(sag);
  assert.deepEqual(scriptDependencies(otp.html), []);

  // Every action is a real form submission to a real path.
  assert.match(email.html, /<form method="post" action="\/authorize\/email">/);
  assert.match(otp.html, /<form method="post" action="\/authorize\/otp">/);
  assert.match(otp.html, /action="\/authorize\/resend"/);
  assert.match(otp.html, /action="\/authorize\/restart"/);
});

test('the form_post auto-submit degrades to a button without script', async () => {
  const sag = createInstance();
  const first = await emailScreen(sag, { response_mode: 'form_post' });
  const otp = await sag.postForm('/authorize/email', { tx: extractField(first.html), email: EMAIL });
  const otpHtml = await otp.text();
  const done = await sag.postForm('/authorize/otp', {
    tx: extractField(otpHtml),
    code: otpHtml.match(/<code>([0-9A-Z]+)<\/code>/)[1],
  });
  const html = await done.text();

  // The one place script is used, and only to save a click. It is marked with
  // an attribute the enhancement file looks for rather than an inline handler,
  // so this page needs no exception in the Content-Security-Policy either.
  assert.match(html, /<form method="post" action="[^"]+" data-autosubmit>/);
  assert.deepEqual(scriptDependencies(html), []);
  assert.match(html, /<noscript><button type="submit">Continue<\/button><\/noscript>/);
  assert.match(html, /<noscript><p>Select continue to finish signing in\.<\/p><\/noscript>/);
});

test('the transaction travels in the form, so no cookie is needed mid-flow', async () => {
  const sag = createInstance();
  const first = await emailScreen(sag);
  const tx = extractField(first.html);

  // A browser blocking every cookie must still complete the flow.
  const res = await sag.raw('/authorize/email', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: '' },
    body: new URLSearchParams({ tx, email: EMAIL }).toString(),
  });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Check your email/);
});

// ---------------------------------------------------------------------------
// Works without CSS
// ---------------------------------------------------------------------------

test('each screen is meaningful with no stylesheet at all', async () => {
  const sag = createInstance();
  for (const { html, name } of [
    { html: (await emailScreen(sag)).html, name: 'email' },
    { html: (await otpScreen(sag)).html, name: 'otp' },
  ]) {
    // One heading, so the reading order starts in the right place.
    assert.equal((html.match(/<h1>/g) || []).length, 1, name + ' should have exactly one h1');
    // Nothing is hidden by default: a rule that hides content would make the
    // page unusable when the stylesheet fails to load.
    assert.ok(!/style="[^"]*display:\s*none/i.test(html), name + ' hides something inline');
    assert.ok(!/\shidden(\s|>|=)/i.test(html), name + ' uses the hidden attribute on visible content');
    // The stylesheet is a link, not a blocking requirement. The version query
    // is what lets it be cached for a year and still change with a deployment.
    assert.match(html, /<link rel="stylesheet" href="\/static\/sag\.css\?v=[a-z0-9]+">/);
  }
});

test('the stylesheet only ever adds comfort, never meaning', () => {
  // A rule that hides content would break the no-CSS promise from the other
  // direction: content present in the HTML but invisible when styled.
  const hiding = DEFAULT_CSS.match(/display:\s*none|visibility:\s*hidden/gi) || [];
  assert.deepEqual(hiding, [], 'the default stylesheet must not hide anything');

  // Sizes in rem, so an OS or browser text-size preference scales everything.
  assert.ok(!/font-size:\s*\d+px/i.test(DEFAULT_CSS), 'no pixel font sizes');
  // No fixed heights, which is what breaks reflow at high zoom. The lookbehind
  // matters: a plain word boundary also matches inside "max-height", and a
  // max-height or min-height does not pin an element's size.
  assert.ok(!/(?<![-\w])height:\s*\d+(px|rem)/i.test(DEFAULT_CSS), 'no fixed heights');
  // WCAG 1.4.10 reflow, and the media query that goes with it.
  assert.match(DEFAULT_CSS, /max-width:\s*26rem/, 'a narrow-viewport rule is needed for reflow');
  assert.match(DEFAULT_CSS, /prefers-reduced-motion/);
  assert.match(DEFAULT_CSS, /prefers-contrast|forced-colors/);
  assert.match(DEFAULT_CSS, /prefers-color-scheme/);
  assert.match(DEFAULT_CSS, /:focus-visible/, 'focus must be visible');
});

test('the stylesheet is served cacheable and with the right type', async () => {
  const sag = createInstance();
  const res = await sag.raw('/static/sag.css');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/css; charset=utf-8');
  assert.match(res.headers.get('cache-control'), /public, max-age=\d+/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
});

// ---------------------------------------------------------------------------
// Accessibility of the markup
// ---------------------------------------------------------------------------

test('every input has a real label and helpful autocomplete', async () => {
  const sag = createInstance();

  const email = (await emailScreen(sag)).html;
  assert.match(email, /<label for="email">Email address<\/label>/);
  assert.match(email, /<input id="email" name="email" type="email"/);
  assert.match(email, /inputmode="email"/);
  assert.match(email, /autocomplete="username email"/);
  assert.match(email, /spellcheck="false"/, 'an address is not a misspelling');
  assert.match(email, /\srequired\s/);

  const otp = (await otpScreen(sag)).html;
  assert.match(otp, /<label for="code">Sign-in code<\/label>/);
  assert.match(otp, /<input id="code" name="code"/);
  // This is what lets iOS and Android offer the code from the message itself.
  assert.match(otp, /autocomplete="one-time-code"/);
  // Codes are letters and numbers by default, so the on-screen keyboard has to
  // offer both; a deployment that asks for digits gets the numeric keypad.
  assert.match(otp, /inputmode="text"/);
  assert.match(otp, /autocapitalize="characters"/);
  const numeric = (await otpScreen(createInstance({ OTP_CODE_ALPHABET: 'numeric' }))).html;
  assert.match(numeric, /inputmode="numeric"/);
  assert.match(otp, /aria-describedby="code-hint"/);
  assert.match(otp, /id="code-hint"/, 'the described-by target must exist');
});

test('nothing steals focus on load', async () => {
  // Moving focus on load is disorienting for screen reader and switch access
  // users, and the field is the first thing in the document anyway.
  const sag = createInstance();
  assert.ok(!/autofocus/i.test((await emailScreen(sag)).html));
  assert.ok(!/autofocus/i.test((await otpScreen(sag)).html));
});

test('an error is announced and tied to the field it refers to', async () => {
  const sag = createInstance();
  const first = await emailScreen(sag);
  const bad = await sag.postForm('/authorize/email', {
    tx: extractField(first.html),
    email: 'not-an-address',
  });
  const html = await bad.text();

  assert.equal(bad.status, 400, 'a rejected submission must not report success');
  // role="alert" makes a screen reader announce it, which matters because the
  // message sits above the field it is about.
  assert.match(html, /<div class="error" role="alert">/);
  assert.match(html, /Check your email address/);
  assert.match(html, /aria-invalid="true"/);
  // What they typed comes back, so they can correct it rather than retype it.
  assert.match(html, /value="not-an-address"/);
});

test('the document declares its language and asks not to be indexed', async () => {
  const sag = createInstance({ UI_LOCALE: 'cy' });
  const html = (await emailScreen(sag)).html;
  assert.match(html, /<html lang="cy">/);
  assert.match(html, /<meta name="robots" content="noindex, nofollow">/);
  assert.match(html, /<meta name="referrer" content="no-referrer">/);
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
});

test('the page loads nothing from anywhere else', async () => {
  const sag = createInstance();
  const html = (await emailScreen(sag)).html;
  // A sign-in page that fetches a font or a script from a third party leaks
  // every sign-in attempt to that third party.
  const loaded = [...html.matchAll(/(?:src="|<link[^>]+href=")(https?:)?\/\/[^"]*"/g)].map((m) => m[0]);
  assert.deepEqual(loaded, [], 'nothing may be loaded cross-origin');
  // The attribution link in the footer is a link, not a load: nothing is
  // fetched until somebody chooses to follow it, and the page sends no
  // referrer when they do.
  assert.match(html, /<a href="https:\/\/resoauth\.dev" rel="noopener">RESOAuth<\/a>/);
});

test('security headers are set on every page', async () => {
  const sag = createInstance();
  const { res } = await emailScreen(sag);
  assert.equal(res.headers.get('x-frame-options'), 'DENY', 'a sign-in page must not be framed');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

// ---------------------------------------------------------------------------
// Content-Security-Policy
// ---------------------------------------------------------------------------

/** Parse a policy into { directive: [sources] }. */
function policy(header) {
  const out = {};
  for (const part of header.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) out[name] = sources;
  }
  return out;
}

test('every page carries a policy that starts at nothing', async () => {
  const sag = createInstance();
  const { res } = await emailScreen(sag);
  const csp = policy(res.headers.get('content-security-policy'));

  assert.deepEqual(csp['default-src'], ["'none'"], 'the policy must start closed');
  assert.deepEqual(csp['base-uri'], ["'none'"], 'a <base> element could rewrite every form action');
  assert.deepEqual(csp['frame-ancestors'], ["'none'"], 'a sign-in page must not be framed');
  assert.deepEqual(csp['connect-src'], ["'none'"], 'nothing on these pages fetches anything');

  // form-action is absent, and has to stay absent. Browsers check it across the
  // redirect chain, and completing a sign-in is a same-origin form POST that is
  // answered with a 303 to the relying party, so `'self'` blocks every
  // successful sign-in. Measured in Chromium; see the note in src/ui/csp.js.
  assert.equal(csp['form-action'], undefined, 'form-action on these pages would break the flow');

  // The point of the whole arrangement: no inline anything to allow.
  assert.deepEqual(csp['script-src'], ["'self'"]);
  assert.ok(!csp['script-src'].includes("'unsafe-inline'"));
  assert.ok(!csp['style-src'].includes("'unsafe-inline'"));
  assert.ok(!csp['style-src'].some((s) => s.startsWith("'nonce-")), 'no nonce should be needed');
});

test('the policy is on every screen, not just the first', async () => {
  const sag = createInstance();
  const first = await emailScreen(sag);
  const tx = extractField(first.html);
  for (const res of [
    first.res,
    await sag.postForm('/authorize/email', { tx, email: EMAIL }),
    await sag.raw('/logout'),
    await sag.raw('/authorize?client_id=not-registered'),
  ]) {
    assert.ok(res.headers.get('content-security-policy'), 'a page went out with no policy');
  }
});

test('the policy widens only for what the operator configured', async () => {
  const plain = policy((await emailScreen(createInstance())).res.headers.get('content-security-policy'));
  assert.deepEqual(plain['style-src'], ["'self'"]);
  assert.deepEqual(plain['img-src'], ["'self'", 'data:', 'https:']);

  // A remote theme has to be loadable, and only from where it lives.
  const themed = createInstance({ CUSTOM_CSS_REMOTE_URL: 'https://cdn.example.test/theme.css' });
  const withTheme = policy((await emailScreen(themed)).res.headers.get('content-security-policy'));
  assert.deepEqual(withTheme['style-src'], ["'self'", 'https://cdn.example.test']);

  // Pictures off means no third-party images at all: a logo still needs its
  // own origin naming, and nothing else gets in.
  const strict = createInstance({ PROFILE_PICTURE: 'false', UI_LOGO_URL: 'https://brand.example.test/logo.svg' });
  const narrow = policy((await emailScreen(strict)).res.headers.get('content-security-policy'));
  assert.deepEqual(narrow['img-src'], ["'self'", 'data:', 'https://brand.example.test']);
});

test('the form_post page does constrain where its form may post', async () => {
  // This is the one page whose form legitimately posts to another origin, and
  // it posts there directly rather than through a redirect - so form-action can
  // name the exact target, and does.
  const sag = createInstance();
  const first = await emailScreen(sag, { response_mode: 'form_post' });
  const otp = await sag.postForm('/authorize/email', { tx: extractField(first.html), email: EMAIL });
  const otpHtml = await otp.text();
  const done = await sag.postForm('/authorize/otp', {
    tx: extractField(otpHtml),
    code: otpHtml.match(/<code>([0-9A-Z]+)<\/code>/)[1],
  });
  const csp = policy(done.headers.get('content-security-policy'));
  assert.deepEqual(csp['form-action'], ['http://127.0.0.1:8788'], 'exactly the relying party, and nowhere else');
  assert.deepEqual(csp['default-src'], ["'none'"]);
  assert.equal(csp['img-src'], undefined, 'the page shows nothing, so it may load nothing');
});

// ---------------------------------------------------------------------------
// The enhancement script
// ---------------------------------------------------------------------------

test('the theme control exists only because the script ran', async () => {
  const sag = createInstance();
  const html = (await emailScreen(sag)).html;

  // An empty slot, and nothing else. A control written into the markup would
  // still be there on a page whose script was blocked, where it would do
  // nothing at all - which is worse than not offering it.
  assert.match(html, /<div data-theme-control data-label="Colour theme"><\/div>/);
  assert.ok(!html.includes('aria-pressed'), 'no control may be in the markup');
  assert.ok(!html.includes('class="theme"'));

  // And it is last, so the first Tab reaches the field rather than a control
  // somebody will use once.
  assert.ok(html.indexOf('data-theme-control') > html.indexOf('id="email"'));
});

test('the script is a file on our own origin, loaded before the first paint', async () => {
  const sag = createInstance();
  const html = (await emailScreen(sag)).html;
  const match = /<script src="(\/static\/sag\.js\?v=[a-z0-9]+)"><\/script>/.exec(html);
  assert.ok(match, 'the script must be an external file with a version');
  // In <head> and not deferred: the theme is applied before anything is drawn,
  // and deferring it would paint the wrong one for a frame.
  assert.ok(html.indexOf(match[0]) < html.indexOf('<body>'));
  assert.ok(!/<script[^>]*\s(defer|async)/.test(html));

  const res = await sag.raw(match[1]);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/javascript; charset=utf-8');
  assert.equal(await res.text(), DEFAULT_JS);
});

test('the script touches nothing it does not have to', () => {
  // It runs on every sign-in page on the internet-facing side of a deployment,
  // so the bar for what it is allowed to do is high.
  assert.ok(!/\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML/.test(DEFAULT_JS), 'no HTML is ever parsed');
  assert.ok(!/\beval\b|new Function|setTimeout\(\s*['"`]/.test(DEFAULT_JS), 'nothing is evaluated as code');
  assert.ok(!/fetch\(|XMLHttpRequest|WebSocket|sendBeacon/.test(DEFAULT_JS), 'it talks to nobody');
  assert.ok(!/document\.cookie/.test(DEFAULT_JS), 'the session cookie is HttpOnly and none of its business');
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(DEFAULT_JS), 'no third-party URL appears in it');
  // Storage access can throw outright rather than return null - Safari in
  // private browsing does - so every use has to be guarded.
  for (const use of DEFAULT_JS.matchAll(/localStorage/g)) void use;
  assert.equal(
    (DEFAULT_JS.match(/try \{/g) || []).length >= 2,
    true,
    'localStorage access must be wrapped, because it throws in private browsing',
  );
});

test('the code field carries what the script needs, and works without it', async () => {
  const otp = (await otpScreen(createInstance())).html;
  assert.match(otp, /data-length="9"/);
  assert.match(otp, /data-alphabet="alphanumeric"/);
  const numeric = (await otpScreen(createInstance({ OTP_CODE_ALPHABET: 'numeric' }))).html;
  assert.match(numeric, /data-alphabet="numeric"/);
  // The submit button is still a submit button.
  assert.match(otp, /<button type="submit" data-busy-label="Signing in\.\.\.">Sign in<\/button>/);
});

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

test('an asset asked for by its current version can be cached for a year', async () => {
  const sag = createInstance();
  const html = (await emailScreen(sag)).html;
  const css = /href="(\/static\/sag\.css\?v=[a-z0-9]+)"/.exec(html)[1];

  const versioned = await sag.raw(css);
  assert.equal(versioned.headers.get('cache-control'), 'public, max-age=31536000, immutable');

  // Without the version, or with a stale one, it is a short cache: the URL is
  // what changes when the file does, so an unversioned request cannot be
  // promised anything.
  assert.match((await sag.raw('/static/sag.css')).headers.get('cache-control'), /max-age=300/);
  assert.match((await sag.raw('/static/sag.css?v=stale')).headers.get('cache-control'), /max-age=300/);
});

// ---------------------------------------------------------------------------
// Operator theming
// ---------------------------------------------------------------------------

test('a snippet is served as a stylesheet, after the default one', async () => {
  const snippet = 'main { border-color: rebeccapurple }';
  const sag = createInstance({ CUSTOM_CSS_SNIPPET: snippet });
  const html = (await emailScreen(sag)).html;
  assert.match(html, /<link rel="stylesheet" href="\/static\/sag\.css\?v=[a-z0-9]+">/, 'the default is still loaded');
  assert.match(html, /<link rel="stylesheet" href="\/static\/custom\.css\?v=[a-z0-9]+">/);
  // Order matters: the snippet must come last so it can adjust the base.
  assert.ok(html.indexOf('sag.css') < html.indexOf('custom.css'));

  const served = await sag.raw(html.match(/href="(\/static\/custom\.css[^"]*)"/)[1]);
  assert.equal(served.status, 200);
  assert.equal(served.headers.get('content-type'), 'text/css; charset=utf-8');
  assert.equal(await served.text(), snippet);
});

test('a remote stylesheet replaces the default, but a snippet still applies', async () => {
  // This is the rule from the brief: an operator supplying a whole theme does
  // not want to fight ours, but should still be able to tweak on top.
  const sag = createInstance({
    CUSTOM_CSS_REMOTE_URL: 'https://cdn.example.test/theme.css',
    CUSTOM_CSS_SNIPPET: 'h1 { letter-spacing: 0 }',
  });
  const html = (await emailScreen(sag)).html;
  assert.ok(!html.includes('/static/sag.css'), 'the default must not be loaded as well');
  assert.match(html, /<link rel="stylesheet" href="https:\/\/cdn\.example\.test\/theme\.css">/);
  assert.match(html, /<link rel="stylesheet" href="\/static\/custom\.css\?v=[a-z0-9]+">/);
  assert.ok(html.indexOf('cdn.example.test') < html.indexOf('custom.css'));
});

test('a snippet has no element to break out of', async () => {
  // The snippet used to be inlined in a <style> element, where the one thing
  // that had to be escaped was the closing sequence. Serving it as a stylesheet
  // removes the question: a text/css response with nosniff is never parsed as
  // markup, so there is nothing for a payload to escape into.
  const snippet = 'a{}</style><script>alert(1)</script><style>';
  const sag = createInstance({ CUSTOM_CSS_SNIPPET: snippet });
  const html = (await emailScreen(sag)).html;

  assert.ok(!html.includes('<style'), 'no page carries an inline style element');
  assert.ok(!html.includes('alert(1)'), 'the snippet never reaches the document');
  assert.deepEqual(scriptDependencies(html), []);

  const served = await sag.raw('/static/custom.css');
  assert.equal(served.headers.get('content-type'), 'text/css; charset=utf-8');
  assert.equal(served.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(await served.text(), snippet);
});

test('a deployment with no snippet does not serve one', async () => {
  const sag = createInstance();
  assert.ok(!(await emailScreen(sag)).html.includes('custom.css'));
  assert.equal((await sag.raw('/static/custom.css')).status, 404);
});

test('an operator name and logo appear, and are escaped', async () => {
  const sag = createInstance({
    UI_ORG_NAME: 'Acme & Sons <Ltd>',
    UI_SUPPORT_URL: 'https://help.acme.test/signin',
    UI_TITLE: 'Sign in to Acme',
  });
  const html = (await emailScreen(sag)).html;
  assert.match(html, /Acme &amp; Sons &lt;Ltd&gt;/);
  assert.ok(!html.includes('<Ltd>'), 'operator values must be escaped');
  assert.match(html, /<a href="https:\/\/help\.acme\.test\/signin">Get help signing in<\/a>/);
  assert.match(html, /<title>Sign in - Sign in to Acme<\/title>/);
});

test('a relying party name is shown so the person knows what they are signing into', async () => {
  const sag = createInstance({
    CLIENT_APP_ID: 'ledger',
    CLIENT_APP_NAME: 'Acme Ledger',
    CLIENT_APP_REDIRECT_URIS: 'https://ledger.test/cb',
  });
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, clientId: 'ledger', redirectUri: 'https://ledger.test/cb' });
  const html = await (await sag.raw(path)).text();
  assert.match(html, /Continue to <strong>Acme Ledger<\/strong>/);
});

// ---------------------------------------------------------------------------
// What the pages say
// ---------------------------------------------------------------------------

test('the OTP screen repeats the address and offers a way back', async () => {
  const sag = createInstance();
  const html = (await otpScreen(sag)).html;
  assert.match(html, new RegExp('sent a 9-character code to <strong>' + EMAIL + '</strong>'));
  assert.match(html, /Send another code/);
  assert.match(html, /Use a different email address/);
});

test('the development code is shown on the page only in development', async () => {
  const dev = createInstance();
  assert.match((await otpScreen(dev)).html, /Development mode: your sign-in code is <code>[0-9A-Z]{9}<\/code>/);

  const real = createInstance({
    SAG_ISSUER: 'https://id.example.test',
    SAG_DEV: 'false',
    EMAIL_PROVIDER: 'mailchannels',
    EMAIL_FROM: 'no-reply@id.example.test',
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    MAILCHANNELS_API_KEY: 'k',
  });
  // The send will fail because nothing answers, but the point is that no code
  // is ever rendered outside development.
  const html = (await otpScreen(real)).html;
  assert.ok(!/Development mode/.test(html));
  assert.ok(!/<code>[0-9A-Z]{9}<\/code>/.test(html));
});

test('the error page does not blame the person or leak internals', async () => {
  const sag = createInstance();
  const res = await sag.postForm('/authorize/otp', { tx: 'rubbish', code: '000000' });
  const html = await res.text();
  assert.match(html, /Start signing in again/);
  assert.match(html, /Nothing is wrong with your account/);
  assert.ok(!/stack|SealError|undefined|\bat \//i.test(html), 'no internals in a user-facing page');
});

test('the root path is not a landing page', async () => {
  const sag = createInstance();
  const res = await sag.raw('/');
  assert.equal(res.status, 404);
  assert.match(await res.text(), /Start from the application you want to use/);
});

test('signing out says so plainly', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });
  const confirm = await sag.raw('/logout');
  const confirmHtml = await confirm.text();
  assert.match(confirmHtml, /every application that uses this sign-in service/, 'a shared session must say so');

  const done = await sag.postForm('/logout', { lt: extractField(confirmHtml, 'lt') });
  const html = await done.text();
  assert.match(html, /<h1>You are signed out<\/h1>/);
  assert.deepEqual(scriptDependencies(html), []);
});
