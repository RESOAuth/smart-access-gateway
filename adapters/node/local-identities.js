// Local identity records held as privacy-preserving files.
//
// The core cannot import node:fs because it also runs in a Cloudflare Worker.
// This adapter therefore presents the filesystem as a small binding, in the
// same way adapters/node/client-files.js presents relying-party records. A
// record key is the full lower-case HMAC-SHA-256 hex digest of its canonical
// email address; the address itself never appears in a filename.

import * as nodeCrypto from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';

const KEY_PATTERN = /^[0-9a-f]{64}$/;
const MAX_RECORD_BYTES = 64 * 1024;
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;

const ARGON2_VERSION = 19;
const ARGON2_DEFAULTS = Object.freeze({
  memory: 64 * 1024,
  passes: 3,
  parallelism: 1,
  tagLength: 32,
  saltLength: 16,
});
const ARGON2_LIMITS = Object.freeze({
  memory: { min: 8 * 1024, max: 64 * 1024 },
  passes: { min: 1, max: 10 },
  parallelism: { min: 1, max: 4 },
  tagLength: { min: 16, max: 64 },
  saltLength: { min: 16, max: 64 },
});
// Matches the core's upper configuration bound and the HTTP body cap. The
// normal policy default is much smaller, but the adapter must not quietly
// override an explicit LOCAL_PASSWORD_MAX_BYTES setting.
const MAX_PASSWORD_BYTES = 64 * 1024;
const MAX_PHC_LENGTH = 512;
// Bindings for the same directory can be constructed more than once by tests
// or tooling in one process. Share their mutexes so the advertised CAS remains
// true across adapter instances; separate processes still require the
// documented single-writer discipline.
const RECORD_LOCKS = new Map();

export class LocalIdentityFileError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'LocalIdentityFileError';
  }
}

export class Argon2idError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'Argon2idError';
  }
}

export function assertArgon2idAvailable(cryptoModule = nodeCrypto) {
  if (typeof cryptoModule?.argon2 !== 'function') {
    throw new Argon2idError(
      'Argon2id is unavailable: local identities require Node.js 24.7 or newer with crypto.argon2',
    );
  }
}

/** A small FIFO semaphore, with a bound so queued requests cannot grow forever. */
class Semaphore {
  constructor(limit, maxQueue) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new TypeError('Argon2 concurrency must be a positive integer');
    if (!Number.isSafeInteger(maxQueue) || maxQueue < 0) throw new TypeError('Argon2 queue size must be a non-negative integer');
    this.limit = limit;
    this.maxQueue = maxQueue;
    this.active = 0;
    this.queue = [];
  }

  async run(operation) {
    await this.acquire();
    try {
      return await operation();
    } finally {
      this.release();
    }
  }

  async acquire() {
    if (this.active < this.limit) {
      this.active += 1;
      return;
    }
    if (this.queue.length >= this.maxQueue) {
      throw new Argon2idError('Argon2 is busy; too many password operations are already queued');
    }
    // The active permit is transferred directly by release(), so this waiter
    // must not increment the count when it wakes.
    await new Promise((resolvePermit) => this.queue.push(resolvePermit));
  }

  release() {
    const next = this.queue.shift();
    if (next) next();
    else this.active -= 1;
  }
}

function boundedInteger(value, name, bounds) {
  if (!Number.isSafeInteger(value) || value < bounds.min || value > bounds.max) {
    throw new Argon2idError(
      name + ' must be a whole number from ' + bounds.min + ' to ' + bounds.max,
    );
  }
  return value;
}

function passwordBytes(password) {
  let bytes;
  if (typeof password === 'string') bytes = Buffer.from(password, 'utf8');
  else if (password instanceof Uint8Array) bytes = Buffer.from(password);
  else throw new TypeError('password must be a string or Uint8Array');
  if (bytes.length > MAX_PASSWORD_BYTES) {
    bytes.fill(0);
    throw new Argon2idError('password must be at most ' + MAX_PASSWORD_BYTES + ' bytes');
  }
  return bytes;
}

function unpaddedBase64(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/=+$/, '');
}

function decodePhcBase64(value, name) {
  if (!/^[A-Za-z0-9+/]+$/.test(value)) {
    throw new Argon2idError('Argon2id PHC ' + name + ' is not unpadded base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || unpaddedBase64(bytes) !== value) {
    throw new Argon2idError('Argon2id PHC ' + name + ' is not canonical base64');
  }
  return bytes;
}

/** Parse only the canonical PHC form this adapter writes. */
export function parseArgon2idPhc(phc) {
  if (typeof phc !== 'string' || phc.length === 0 || phc.length > MAX_PHC_LENGTH) {
    throw new Argon2idError('Argon2id verifier is not a bounded PHC string');
  }
  const match = phc.match(
    /^\$argon2id\$v=19\$m=([1-9][0-9]*),t=([1-9][0-9]*),p=([1-9][0-9]*)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/,
  );
  if (!match) throw new Argon2idError('Argon2id verifier is not in canonical PHC format');

  const memory = boundedInteger(Number(match[1]), 'Argon2 memory', ARGON2_LIMITS.memory);
  const passes = boundedInteger(Number(match[2]), 'Argon2 passes', ARGON2_LIMITS.passes);
  const parallelism = boundedInteger(Number(match[3]), 'Argon2 parallelism', ARGON2_LIMITS.parallelism);
  const salt = decodePhcBase64(match[4], 'salt');
  const tag = decodePhcBase64(match[5], 'tag');
  boundedInteger(salt.length, 'Argon2 salt length', ARGON2_LIMITS.saltLength);
  boundedInteger(tag.length, 'Argon2 tag length', ARGON2_LIMITS.tagLength);

  return { version: ARGON2_VERSION, memory, passes, parallelism, salt, tag };
}

function checkedHashOptions(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Argon2 options must be an object');
  }
  return {
    memory: boundedInteger(options.memory ?? ARGON2_DEFAULTS.memory, 'Argon2 memory', ARGON2_LIMITS.memory),
    passes: boundedInteger(options.passes ?? ARGON2_DEFAULTS.passes, 'Argon2 passes', ARGON2_LIMITS.passes),
    parallelism: boundedInteger(
      options.parallelism ?? ARGON2_DEFAULTS.parallelism,
      'Argon2 parallelism',
      ARGON2_LIMITS.parallelism,
    ),
    tagLength: boundedInteger(options.tagLength ?? ARGON2_DEFAULTS.tagLength, 'Argon2 tag length', ARGON2_LIMITS.tagLength),
    saltLength: boundedInteger(options.saltLength ?? ARGON2_DEFAULTS.saltLength, 'Argon2 salt length', ARGON2_LIMITS.saltLength),
  };
}

/**
 * Build an Argon2id service.
 *
 * The crypto namespace is injectable only so the concurrency and unavailable-
 * runtime paths can be tested without allocating several real 64 MiB jobs.
 * Production callers use the module-wide service below.
 */
export function createArgon2id({
  maxConcurrent = 4,
  maxQueue = 64,
  cryptoModule = nodeCrypto,
} = {}) {
  const semaphore = new Semaphore(maxConcurrent, maxQueue);

  const implementation = () => {
    assertArgon2idAvailable(cryptoModule);
    return cryptoModule.argon2;
  };

  const run = (parameters) =>
    semaphore.run(
      () =>
        new Promise((resolveResult, rejectResult) => {
          try {
            implementation()('argon2id', parameters, (error, result) => {
              if (error) rejectResult(error);
              else resolveResult(Buffer.from(result));
            });
          } catch (error) {
            rejectResult(error);
          }
        }),
    );

  return {
    async hash(password, options) {
      const settings = checkedHashOptions(options);
      const message = passwordBytes(password);
      let salt;
      try {
        if (typeof cryptoModule?.randomBytes !== 'function') {
          throw new Argon2idError('secure random-byte generation is unavailable in this Node.js runtime');
        }
        salt = Buffer.from(cryptoModule.randomBytes(settings.saltLength));
        if (salt.length !== settings.saltLength) {
          throw new Argon2idError('secure random-byte generation returned the wrong number of bytes');
        }
        const tag = await run({
          message,
          nonce: salt,
          parallelism: settings.parallelism,
          tagLength: settings.tagLength,
          memory: settings.memory,
          passes: settings.passes,
        });
        if (tag.length !== settings.tagLength) {
          throw new Argon2idError('crypto.argon2 returned an unexpected tag length');
        }
        return (
          '$argon2id$v=' +
          ARGON2_VERSION +
          '$m=' +
          settings.memory +
          ',t=' +
          settings.passes +
          ',p=' +
          settings.parallelism +
          '$' +
          unpaddedBase64(salt) +
          '$' +
          unpaddedBase64(tag)
        );
      } finally {
        message.fill(0);
      }
    },

    async verify(phc, password) {
      const parsed = parseArgon2idPhc(phc);
      const message = passwordBytes(password);
      try {
        const actual = await run({
          message,
          nonce: parsed.salt,
          parallelism: parsed.parallelism,
          tagLength: parsed.tag.length,
          memory: parsed.memory,
          passes: parsed.passes,
        });
        if (actual.length !== parsed.tag.length) return false;
        if (typeof cryptoModule?.timingSafeEqual !== 'function') {
          throw new Argon2idError('timing-safe comparison is unavailable in this Node.js runtime');
        }
        return cryptoModule.timingSafeEqual(actual, parsed.tag);
      } finally {
        message.fill(0);
      }
    },
  };
}

const argon2id = createArgon2id();

export const hashArgon2id = (password, options) => argon2id.hash(password, options);
export const verifyArgon2id = (phc, password) => argon2id.verify(phc, password);

function checkedKey(key) {
  if (typeof key !== 'string' || !KEY_PATTERN.test(key)) {
    throw new LocalIdentityFileError('local identity keys must be 64 lower-case hexadecimal characters');
  }
  return key;
}

function checkedRevision(value, name, { allowZero = false } = {}) {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new LocalIdentityFileError(name + ' must be a safe integer of at least ' + minimum);
  }
  return value;
}

function checkedDocument(doc, expectedRevision) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new LocalIdentityFileError('a local identity record must be a JSON object');
  }
  checkedRevision(doc.revision, 'record revision');
  if (doc.revision !== expectedRevision + 1) {
    throw new LocalIdentityFileError('replacement record revision must be the expected revision plus one');
  }
  let text;
  try {
    text = JSON.stringify(doc, null, 2) + '\n';
  } catch (cause) {
    throw new LocalIdentityFileError('local identity record is not serialisable JSON', { cause });
  }
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length > MAX_RECORD_BYTES) {
    throw new LocalIdentityFileError('local identity record exceeds ' + MAX_RECORD_BYTES + ' bytes');
  }
  return bytes;
}

function recordPath(root, key) {
  const path = resolve(join(root, checkedKey(key) + '.json'));
  if (!path.startsWith(root + sep)) {
    throw new LocalIdentityFileError('local identity path escaped its configured directory');
  }
  return path;
}

async function inspectRoot(root, { create = false } = {}) {
  let stat;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- root is the configured local-identity directory
    stat = await lstat(root);
  } catch (error) {
    if (error.code !== 'ENOENT' || !create) throw error;
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- root is the configured local-identity directory
    await mkdir(root, { recursive: true, mode: DIRECTORY_MODE });
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- root is the configured local-identity directory
    stat = await lstat(root);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new LocalIdentityFileError(root + ' must be a real directory, not a symlink or another file type');
  }
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    throw new LocalIdentityFileError(root + ' must not be accessible by group or other users; use mode 0700');
  }
  return stat;
}

function openReadOnlyNoFollow(path) {
  let flags = constants.O_RDONLY;
  if (Number.isInteger(constants.O_NOFOLLOW)) flags |= constants.O_NOFOLLOW;
  if (process.platform !== 'win32' && Number.isInteger(constants.O_NONBLOCK)) {
    // Opening a FIFO for reading normally waits for a writer before fstat can
    // reject it. Non-blocking open keeps a malicious special file from tying
    // up the bounded libuv worker pool.
    flags |= constants.O_NONBLOCK;
  }
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is rooted and its filename comes from checkedKey
  return open(path, flags);
}

async function readBounded(handle) {
  const bytes = Buffer.alloc(MAX_RECORD_BYTES + 1);
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (result.bytesRead === 0) break;
    offset += result.bytesRead;
  }
  if (offset > MAX_RECORD_BYTES) {
    throw new LocalIdentityFileError('local identity record exceeds ' + MAX_RECORD_BYTES + ' bytes');
  }
  return bytes.subarray(0, offset);
}

async function readRecord(root, key) {
  const path = recordPath(root, key);
  try {
    await inspectRoot(root);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }

  let handle;
  try {
    // Windows does not expose O_NOFOLLOW. This pre-check rejects a stable
    // reparse-point/symlink there; on POSIX O_NOFOLLOW also closes the race.
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is rooted and its filename comes from checkedKey
    const entry = await lstat(path);
    if (entry.isSymbolicLink()) {
      throw new LocalIdentityFileError(path + ' must not be a symbolic link');
    }
    handle = await openReadOnlyNoFollow(path);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error.code === 'ELOOP') {
      throw new LocalIdentityFileError(path + ' must not be a symbolic link', { cause: error });
    }
    throw error;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new LocalIdentityFileError(path + ' is not a regular file');
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
      throw new LocalIdentityFileError(path + ' must not be accessible by group or other users; use mode 0600');
    }
    if (stat.size > MAX_RECORD_BYTES) {
      throw new LocalIdentityFileError('local identity record exceeds ' + MAX_RECORD_BYTES + ' bytes');
    }
    const bytes = await readBounded(handle);
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (cause) {
      throw new LocalIdentityFileError(path + ' is not valid UTF-8', { cause });
    }
    let doc;
    try {
      doc = JSON.parse(text);
    } catch (cause) {
      throw new LocalIdentityFileError(path + ' is not valid JSON', { cause });
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      throw new LocalIdentityFileError(path + ' must contain a JSON object');
    }
    checkedRevision(doc.revision, 'record revision');
    return doc;
  } finally {
    await handle.close();
  }
}

async function syncDirectory(root) {
  let handle;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- root is the checked local-identity directory
    handle = await open(root, constants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    // Some filesystems do not support fsync on a directory. The record rename
    // remains atomic there; only crash durability of the directory entry is
    // unavailable.
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    await handle?.close();
  }
}

async function writeAtomic(root, key, bytes, { createOnly = false } = {}) {
  await inspectRoot(root, { create: true });
  const target = recordPath(root, key);
  const suffix = nodeCrypto.randomBytes(12).toString('hex');
  const temporary = resolve(join(root, '.' + key + '.' + process.pid + '.' + suffix + '.tmp'));
  if (!temporary.startsWith(root + sep)) throw new LocalIdentityFileError('temporary identity path escaped its directory');

  let handle;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- temporary is rooted and built from a checked key plus random hex
    handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      FILE_MODE,
    );
    await handle.chmod(FILE_MODE);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (createOnly) {
      // link(2) installs the already-flushed inode only if target does not
      // exist. Unlike rename(), it cannot let two provisioning processes both
      // report success while the last one silently overwrites the first.
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- both paths are confined to the checked store root
      await link(temporary, target);
      // Once linked, the target is complete and durable enough to expose. A
      // failed private-temp cleanup must not turn a successful creation into a
      // misleading failure which an operator might retry as a replacement.
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- temporary is confined to the checked store root
      await unlink(temporary).catch(() => {});
    } else {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- both paths are confined to the checked store root
      await rename(temporary, target);
    }
    await syncDirectory(root);
  } catch (error) {
    await handle?.close().catch(() => {});
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- temporary is confined to the checked store root
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

/**
 * @param {string} dir Directory holding <hmac-sha256(email)>.json records
 * @param {object} [options] Argon2 concurrency bound
 * @returns {{get(key: string): Promise<object|null>, replace(key: string,
 *   expectedRevision: number, doc: object): Promise<boolean>, list():
 *   Promise<string[]>, hashArgon2id: Function, verifyArgon2id: Function,
 *   dir: string}}
 */
export function createFileLocalIdentityStore(
  dir,
  { argon2Concurrency = 4 } = {},
) {
  const root = resolve(dir);
  const passwordArgon2id = createArgon2id({
    maxConcurrent: argon2Concurrency,
    maxQueue: argon2Concurrency * 32,
  });

  const withKeyLock = async (key, operation) => {
    const lockId = root + '\0' + key;
    const previous = RECORD_LOCKS.get(lockId) || Promise.resolve();
    let release;
    const current = new Promise((resolveLock) => {
      release = resolveLock;
    });
    RECORD_LOCKS.set(lockId, current);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (RECORD_LOCKS.get(lockId) === current) RECORD_LOCKS.delete(lockId);
    }
  };

  return {
    dir: root,
    assertAvailable: () => assertArgon2idAvailable(),
    async assertDirectory() {
      try {
        await inspectRoot(root);
      } catch (error) {
        if (error.code === 'ENOENT') {
          throw new LocalIdentityFileError(
            root + ' does not exist; refusing to treat a missing identity directory as an empty rekey',
            { cause: error },
          );
        }
        throw error;
      }
    },
    hashArgon2id: (password, options) => passwordArgon2id.hash(password, options),
    verifyArgon2id: (phc, password) => passwordArgon2id.verify(phc, password),

    async get(key) {
      return readRecord(root, checkedKey(key));
    },

    /**
     * Atomically replace a record when its current revision is the expected
     * value. Revision zero means the file must not exist. A mismatch returns
     * false; malformed input or an unsafe file fails loudly.
     */
    async replace(key, expectedRevision, doc) {
      key = checkedKey(key);
      expectedRevision = checkedRevision(expectedRevision, 'expected revision', { allowZero: true });
      const bytes = checkedDocument(doc, expectedRevision);
      return withKeyLock(key, async () => {
        const current = await readRecord(root, key);
        if ((current?.revision ?? 0) !== expectedRevision) return false;
        try {
          await writeAtomic(root, key, bytes, { createOnly: expectedRevision === 0 });
        } catch (error) {
          // A second adapter or provisioning process can win after our read.
          // Atomic no-clobber creation turns that race into the same ordinary
          // CAS mismatch returned by the in-process path.
          if (expectedRevision === 0 && error.code === 'EEXIST') return false;
          throw error;
        }
        return true;
      });
    },

    /** Record-shaped filenames, for diagnostics and validated offline rekey. */
    async list() {
      try {
        await inspectRoot(root);
      } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw error;
      }
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- root is the checked local-identity directory
      const entries = await readdir(root, { withFileTypes: true });
      return entries
        // Some filesystems report DT_UNKNOWN even for regular files. Match
        // only the exact record grammar here, then let get()/fstat validate
        // the file type before rekeying or otherwise trusting its contents.
        .filter((entry) => entry.name.endsWith('.json') && KEY_PATTERN.test(entry.name.slice(0, -5)))
        .map((entry) => entry.name)
        .sort();
    },
  };
}
