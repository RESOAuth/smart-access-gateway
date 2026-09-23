import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('./fixtures/local-stack-verifier.js', import.meta.url));

for (const [scenario, diagnostic] of [
  ['password-html', /password.*verification-code page/],
  ['mfa-html', /local-mfa.*HTTP 500/],
  ['token-error', /token exchange failed.*400/],
  ['invalid-json', /invalid JSON/],
  ['mfa-retry', /token exchange failed.*400/],
]) {
  test('local-stack verifier reports ' + scenario + ' without exposing authentication responses', () => {
    const result = spawnSync(process.execPath, [fixture, scenario], { encoding: 'utf8', timeout: 10000 });
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    const output = result.stdout + result.stderr;
    assert.match(output, /FAIL\s+sag-local/);
    assert.match(output, diagnostic);
    assert.equal(output.includes('private-authentication-response-marker'), false);
    assert.equal(output.includes('opaque-transaction'), false);
    assert.equal(output.includes('opaque-authorisation-code'), false);
  });
}
