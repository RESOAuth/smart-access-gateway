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
  let focuses = 0;
  const timers = new Map();
  const form = new EventTarget();
  form.hasAttribute = () => false;
  form.querySelectorAll = () => [];
  form.submit = () => { submissions += 1; };
  if (requestSubmit) {
    form.requestSubmit = () => {
      if (valid && form.dispatchEvent(new Event('submit', { cancelable: true }))) submissions += 1;
    };
  }
  const input = new EventTarget();
  input.form = form;
  input.value = '';
  input.focus = () => { focuses += 1; };
  input.getAttribute = (name) => name === 'data-submit-at' ? String(digits) : null;
  input.checkValidity = () => valid;
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
    get focuses() { return focuses; },
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

test('invalid or incomplete authenticator input never schedules a submission', () => {
  for (const value of ['12345', '12345 ', '1234567', '12345678', '12345a', '------', '']) {
    const browser = authenticator();
    browser.type(value);
    browser.tick(500);
    assert.equal(browser.submissions, 0, value);
  }
  const invalid = authenticator({ valid: false });
  invalid.type('123456');
  invalid.tick(500);
  assert.equal(invalid.submissions, 0, 'native validity is checked before fallback submission');
});

test('manual submission or leaving the code field cancels delayed submission', () => {
  const manual = authenticator();
  manual.type('123456');
  manual.form.requestSubmit();
  manual.tick(500);
  assert.equal(manual.submissions, 1);

  const blurred = authenticator();
  blurred.type('123456');
  blurred.input.dispatchEvent(new Event('blur'));
  blurred.tick(500);
  assert.equal(blurred.submissions, 0, 'opening the backup form must not submit the authenticator form');
});

test('composition is left alone and the legacy submission fallback still submits once', () => {
  const composing = authenticator();
  composing.type('123456', { composing: true });
  composing.tick(500);
  assert.equal(composing.submissions, 0);
  composing.type('123456');
  composing.tick(500);
  assert.equal(composing.submissions, 1);

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
