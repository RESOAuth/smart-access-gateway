// Exercise the delivered script against browser APIs, without replacing any
// of its event handlers or waiting for real typing delays.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runInNewContext } from 'node:vm';
import { DEFAULT_JS } from '../src/ui/js.js';

function authenticator({ digits = 6, requestSubmit = true, valid = true } = {}) {
  let now = 0;
  let nextTimer = 0;
  let submissions = 0;
  let submissionRequests = 0;
  let focuses = 0;
  const timers = new Map();
  const form = new EventTarget();
  form.hasAttribute = () => false;
  form.querySelectorAll = () => [];
  form.submit = () => { submissions += 1; };
  if (requestSubmit) {
    form.requestSubmit = () => {
      submissionRequests += 1;
      if (valid && form.dispatchEvent(new Event('submit', { cancelable: true }))) submissions += 1;
    };
  }
  const input = new EventTarget();
  input.form = form;
  input.value = '';
  input.focus = () => { focuses += 1; };
  input.getAttribute = (name) => name === 'data-submit-at' ? String(digits) : null;
  const document = {
    readyState: 'complete',
    documentElement: { setAttribute() {}, removeAttribute() {} },
    querySelector: () => null,
    querySelectorAll: (selector) => {
      if (selector === 'input[data-submit-at]') return [input];
      if (selector === 'form') return [form];
      return [];
    },
  };
  runInNewContext(DEFAULT_JS, {
    document,
    localStorage: { getItem: () => null },
    setTimeout: (callback, delay) => {
      const id = ++nextTimer;
      timers.set(id, { callback, at: now + delay });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
  });
  return {
    input,
    form,
    get submissions() { return submissions; },
    get submissionRequests() { return submissionRequests; },
    get focuses() { return focuses; },
    set valid(value) { valid = value; },
    type(value, { composing = false } = {}) {
      input.value = value;
      const event = new Event('input');
      Object.defineProperty(event, 'isComposing', { value: composing });
      input.dispatchEvent(event);
    },
    tick(milliseconds) {
      now += milliseconds;
      while (true) {
        const due = [...timers].find(([, timer]) => timer.at <= now);
        if (!due) break;
        timers.delete(due[0]);
        due[1].callback();
      }
    },
  };
}

test('an authenticator code is focused and submitted once after a 500 ms pause', () => {
  const browser = authenticator();
  assert.equal(browser.focuses, 1);
  browser.type('012 345');
  browser.tick(499);
  assert.equal(browser.submissions, 0);
  browser.tick(1);
  assert.equal(browser.submissions, 1);
  browser.type('654321');
  browser.tick(500);
  assert.equal(browser.submissions, 1, 'changing a submitted input cannot spend another attempt');
});

test('continued typing restarts the pause and deleting a digit cancels it', () => {
  const browser = authenticator();
  browser.type('123456');
  browser.tick(400);
  browser.type('654321');
  browser.tick(400);
  assert.equal(browser.submissions, 0);
  browser.type('65432');
  browser.tick(500);
  assert.equal(browser.submissions, 0);
  browser.type('654321');
  browser.tick(500);
  assert.equal(browser.submissions, 1);
});

test('eight-digit and mixed authenticators do not submit a six-digit prefix', () => {
  const browser = authenticator({ digits: 8 });
  browser.type('012345');
  browser.tick(1000);
  assert.equal(browser.submissions, 0);
  browser.type('0123456');
  browser.tick(1000);
  assert.equal(browser.submissions, 0);
  browser.type('0123-4567');
  browser.tick(500);
  assert.equal(browser.submissions, 1);
});

test('the wrong digit count never schedules a submission', () => {
  for (const value of ['12345', '12345 ', '1234567', '12345678', '12345a', '------', '']) {
    const browser = authenticator();
    browser.type(value);
    browser.tick(500);
    assert.equal(browser.submissionRequests, 0, value);
    assert.equal(browser.submissions, 0, value);
  }
});

test('native validation can reject a value without preventing auto-submit after correction', () => {
  const invalid = authenticator({ valid: false });
  invalid.type('123456x');
  invalid.tick(500);
  assert.equal(invalid.submissionRequests, 1, 'the debounce only counts digits');
  assert.equal(invalid.input.value, '123456x', 'validation receives the original value');
  assert.equal(invalid.submissions, 0, 'requestSubmit delegates validation to the browser');

  invalid.valid = true;
  invalid.type('123456');
  invalid.tick(500);
  assert.equal(invalid.submissionRequests, 2);
  assert.equal(invalid.submissions, 1);
  invalid.type('654321');
  invalid.tick(500);
  assert.equal(invalid.submissionRequests, 2, 'a successful submission still prevents duplicates');
});

test('manual submission cancels delayed submission', () => {
  const manual = authenticator();
  manual.type('123456');
  manual.form.requestSubmit();
  manual.tick(500);
  assert.equal(manual.submissions, 1);
});

test('blur and composition do not change the digit-count debounce', () => {
  const blurred = authenticator();
  blurred.type('123456');
  blurred.input.dispatchEvent(new Event('blur'));
  blurred.tick(499);
  assert.equal(blurred.submissions, 0);
  blurred.tick(1);
  assert.equal(blurred.submissions, 1);

  const composing = authenticator();
  composing.type('123456', { composing: true });
  composing.tick(499);
  assert.equal(composing.submissions, 0);
  composing.tick(1);
  assert.equal(composing.submissions, 1);
});

test('the legacy submission fallback still submits once', () => {
  const fallback = authenticator({ requestSubmit: false });
  fallback.type('123456');
  fallback.tick(500);
  fallback.type('654321');
  fallback.tick(500);
  assert.equal(fallback.submissions, 1);
});

test('a pending timeout checks the current value before submitting', () => {
  const browser = authenticator();
  browser.type('123456');
  browser.input.value = '12345';
  browser.tick(500);
  assert.equal(browser.submissions, 0);
});
