// The Node-only local identity store: password defence and the filesystem
// boundary around privacy-preserving records.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nodeCrypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import {
  Argon2idError,
  LocalIdentityFileError,
  createArgon2id,
  createFileLocalIdentityStore,
  hashArgon2id,
  parseArgon2idPhc,
  verifyArgon2id,
} from '../adapters/node/local-identities.js';

const KEY = 'a'.repeat(64);
const OTHER_KEY = 'b'.repeat(64);
const run = promisify(execFile);

async function temporaryStore() {
  const dir = await mkdtemp(join(tmpdir(), 'sag-local-identities-'));
  return { dir, store: createFileLocalIdentityStore(dir) };
}

test('Argon2id PHC verifiers round-trip and reject the wrong password', async (t) => {
  if (typeof nodeCrypto.argon2 !== 'function') {
    t.skip('this Node.js runtime has no crypto.argon2');
    return;
  }
  const phc = await hashArgon2id('a correct horse battery staple');
  assert.match(phc, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
  const parsed = parseArgon2idPhc(phc);
  assert.equal(parsed.version, 19);
  assert.equal(parsed.salt.length, 16);
  assert.equal(parsed.tag.length, 32);
  assert.equal(await verifyArgon2id(phc, 'a correct horse battery staple'), true);
  assert.equal(await verifyArgon2id(phc, 'not the password'), false);
});

test('the PHC parser rejects malformed, non-canonical and dangerous parameters', () => {
  const salt = Buffer.alloc(16, 1).toString('base64').replace(/=+$/, '');
  const tag = Buffer.alloc(32, 2).toString('base64').replace(/=+$/, '');
  const invalid = [
    '',
    '$argon2i$v=19$m=65536,t=3,p=1$' + salt + '$' + tag,
    '$argon2id$v=16$m=65536,t=3,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$t=3,m=65536,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=065536,t=3,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=65537,t=3,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=65536,t=11,p=1$' + salt + '$' + tag,
    '$argon2id$v=19$m=65536,t=3,p=5$' + salt + '$' + tag,
    '$argon2id$v=19$m=65536,t=3,p=1$' + salt + '=$' + tag,
    '$argon2id$v=19$m=65536,t=3,p=1$AA$' + tag,
    '$argon2id$v=19$m=65536,t=3,p=1$' + salt + '$AA',
    'x'.repeat(513),
  ];
  for (const phc of invalid) {
    assert.throws(() => parseArgon2idPhc(phc), Argon2idError, phc.slice(0, 80));
  }
});

test('Argon2 options and password input are bounded before work starts', async () => {
  const fakeCrypto = {
    argon2() {
      assert.fail('unsafe parameters reached crypto.argon2');
    },
    randomBytes: nodeCrypto.randomBytes,
    timingSafeEqual: nodeCrypto.timingSafeEqual,
  };
  const argon = createArgon2id({ cryptoModule: fakeCrypto });
  await assert.rejects(argon.hash('password', { memory: 65537 }), Argon2idError);
  await assert.rejects(argon.hash('password', { passes: 0 }), Argon2idError);
  await assert.rejects(argon.hash('x'.repeat(64 * 1024 + 1)), /at most 65536 bytes/);
  await assert.rejects(argon.hash(123), /string or Uint8Array/);
});

test('an older Node.js runtime gets a clear Argon2 feature error at use time', async () => {
  const argon = createArgon2id({
    cryptoModule: {
      randomBytes: nodeCrypto.randomBytes,
      timingSafeEqual: nodeCrypto.timingSafeEqual,
    },
  });
  await assert.rejects(argon.hash('password'), /unavailable.*crypto\.argon2/i);
});

test('Argon2 work is concurrency-limited and its wait queue is bounded', async () => {
  let active = 0;
  let peak = 0;
  const fakeCrypto = {
    randomBytes: (size) => Buffer.alloc(size, 7),
    timingSafeEqual: nodeCrypto.timingSafeEqual,
    argon2(_algorithm, parameters, callback) {
      active += 1;
      peak = Math.max(peak, active);
      setTimeout(() => {
        active -= 1;
        callback(null, Buffer.alloc(parameters.tagLength, 9));
      }, 20);
    },
  };
  const argon = createArgon2id({ maxConcurrent: 2, maxQueue: 8, cryptoModule: fakeCrypto });
  await Promise.all(Array.from({ length: 6 }, (_, index) => argon.hash('password-' + index)));
  assert.equal(peak, 2);

  const congested = createArgon2id({ maxConcurrent: 1, maxQueue: 1, cryptoModule: fakeCrypto });
  const first = congested.hash('one');
  const second = congested.hash('two');
  await assert.rejects(congested.hash('three'), /too many password operations/);
  await Promise.all([first, second]);
});

test('records use strict keys and bounded regular files, never symlinks', async () => {
  const { dir, store } = await temporaryStore();
  await assert.rejects(store.get('../outside'), LocalIdentityFileError);
  await assert.rejects(store.get('A'.repeat(64)), LocalIdentityFileError);
  await assert.rejects(store.get('a'.repeat(63)), LocalIdentityFileError);
  assert.equal(await store.get(KEY), null);

  const outside = join(dir, '..', 'sag-local-identity-outside-' + nodeCrypto.randomBytes(6).toString('hex') + '.json');
  await writeFile(outside, JSON.stringify({ revision: 1 }));
  await symlink(outside, join(dir, KEY + '.json'));
  await assert.rejects(store.get(KEY), /symbolic link/);

  await mkdir(join(dir, OTHER_KEY + '.json'));
  await assert.rejects(store.get(OTHER_KEY), /not a regular file/);
});

test('a named pipe is rejected without waiting for a writer', async (t) => {
  if (process.platform === 'win32') {
    t.skip('POSIX named-pipe behaviour');
    return;
  }
  const { dir, store } = await temporaryStore();
  await run('mkfifo', [join(dir, KEY + '.json')]);
  await assert.rejects(store.get(KEY), /not a regular file/);
});

test('record reads stop at 64 KiB and reject malformed documents', async () => {
  const { dir, store } = await temporaryStore();
  await writeFile(join(dir, KEY + '.json'), Buffer.alloc(64 * 1024 + 1, 0x20), { mode: 0o600 });
  await assert.rejects(store.get(KEY), /exceeds 65536 bytes/);

  await writeFile(join(dir, KEY + '.json'), '{not json');
  await assert.rejects(store.get(KEY), /not valid JSON/);

  await writeFile(join(dir, KEY + '.json'), JSON.stringify({ revision: 0 }));
  await assert.rejects(store.get(KEY), /revision.*at least 1/);
});

test('compare-and-swap writes are atomic, private and revision checked', async () => {
  const { dir, store } = await temporaryStore();
  assert.equal(await store.replace(KEY, 0, { revision: 1, password: 'verifier' }), true);
  assert.deepEqual(await store.get(KEY), { revision: 1, password: 'verifier' });

  const path = join(dir, KEY + '.json');
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.match(await readFile(path, 'utf8'), /"revision": 1/);

  assert.equal(await store.replace(KEY, 0, { revision: 1, password: 'stale' }), false);
  assert.equal(await store.replace(KEY, 1, { revision: 2, password: 'new' }), true);
  assert.equal((await store.get(KEY)).password, 'new');
  await assert.rejects(
    store.replace(KEY, 2, { revision: 4, password: 'skipped' }),
    /expected revision plus one/,
  );
  await assert.rejects(store.replace(KEY, -1, { revision: 1 }), /expected revision/);

  const listed = await store.list();
  assert.deepEqual(listed, [KEY + '.json']);
  assert.equal(listed.some((name) => name.endsWith('.tmp')), false);
});

test('the per-key mutex lets only one concurrent writer win a revision', async () => {
  const { dir, store } = await temporaryStore();
  const otherBinding = createFileLocalIdentityStore(dir);
  assert.equal(await store.replace(KEY, 0, { revision: 1, value: 'initial' }), true);

  const attempts = await Promise.all([
    store.replace(KEY, 1, { revision: 2, value: 'first' }),
    otherBinding.replace(KEY, 1, { revision: 2, value: 'second' }),
  ]);
  assert.deepEqual([...attempts].sort(), [false, true]);
  assert.ok(['first', 'second'].includes((await store.get(KEY)).value));
});

test('atomic creation cannot be overwritten by a separate binding', async () => {
  const { dir, store } = await temporaryStore();
  const otherBinding = createFileLocalIdentityStore(dir);
  const attempts = await Promise.all([
    store.replace(KEY, 0, { revision: 1, value: 'first' }),
    otherBinding.replace(KEY, 0, { revision: 1, value: 'second' }),
  ]);
  assert.deepEqual([...attempts].sort(), [false, true]);
  assert.ok(['first', 'second'].includes((await store.get(KEY)).value));
});
