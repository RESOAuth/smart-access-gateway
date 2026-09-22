#!/usr/bin/env node
// Provision or rekey operator-managed local identities.
//
// Passwords are accepted only on standard input, never as an argument. Linked
// upstream refresh credentials are read from operator-named environment
// variables, so neither secret appears in the process list or the JSON source
// used to describe a link.

import { open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createFileLocalIdentityStore } from '../adapters/node/local-identities.js';
import {
  createLocalIdentityStore,
  localIdentityKey,
  newCredentialId,
  newLocalIdentityId,
  normaliseLocalUpstreamLink,
  parseLocalIdentityRecord,
  sealTotpSecret,
  sealUpstreamRefreshToken,
} from '../src/local-identities/index.js';
import { encodeBase32 } from '../src/local-identities/totp.js';
import { looksLikeEmail, normaliseEmail } from '../src/identity.js';
import { PROFILE_CLAIMS } from '../src/config.js';
import { randomBytes } from '../src/util/bytes.js';

const HELP = `
  Create a privacy-preserving local identity file.

    printf '%s\\n' "$PASSWORD" | npm run generate-local-identity -- \\
      --email jamie.taylor@example.com --password-stdin \\
      --directory /var/lib/sag/local-identities --totp --backup-codes 10

  Required environment:

    SAG_SECRET       seals TOTP seeds and retained upstream refresh tokens
    SUBJECT_SALT     keys filenames and stable subject identifiers; never rotate it

  Options:

    --email ADDRESS          address used to locate the identity; not stored in JSON
    --directory PATH         identity directory (or set LOCAL_IDENTITIES_DIR)
    --password-stdin         read one password, ending at the first newline
    --totp                   generate and seal one authenticator seed
    --backup-codes NUMBER    generate and Argon2id-hash up to 20 recovery codes
    --claims FILE            JSON object of permitted OpenID Connect profile claims
    --upstreams FILE         JSON array of exact upstream links; a link may name a
                             refresh_token_env whose value is sealed into the record
    --rekey                  reseal every durable secret after setting both
                             SAG_SECRET and SAG_SECRET_PREVIOUS
    --help                   show this help

  An upstream entry has this shape:

    {"id":"work","upstream":"microsoft/examplecom","issuer":"https://login.example/tenant/v2.0","subject":"opaque-upstream-sub","refresh_token_env":"WORK_REFRESH_TOKEN"}

  The tool refuses to overwrite an existing identity. Increase security_version
  when manually changing credentials so existing sessions and codes are revoked.
`;

const VALUE_FLAGS = new Set([
  '--email',
  '--directory',
  '--backup-codes',
  '--claims',
  '--upstreams',
]);
const BOOLEAN_FLAGS = new Set(['--password-stdin', '--totp', '--rekey', '--help', '-h']);

export function parseArguments(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- integer index walks the supplied argv array
    const arg = argv[i];
    if (BOOLEAN_FLAGS.has(arg)) {
      options[arg.replace(/^-+/, '').replaceAll('-', '_')] = true;
      continue;
    }
    if (!VALUE_FLAGS.has(arg)) throw new Error('unknown option: ' + arg);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) throw new Error(arg + ' requires a value');
    options[arg.slice(2).replaceAll('-', '_')] = value;
    i += 1;
  }
  return options;
}

function toolConfig(env) {
  // Match config.js exactly: deployment environment strings are trimmed
  // before use. Otherwise a shell-added space could create a filename or
  // ciphertext which the running instance can never find or open.
  const current = String(env.SAG_SECRET || '').trim();
  const previous = String(env.SAG_SECRET_PREVIOUS || '').trim();
  const salt = String(env.SUBJECT_SALT || '').trim();
  if (current.length < 32) throw new Error('SAG_SECRET must contain at least 32 characters');
  if (salt.length < 16) throw new Error('SUBJECT_SALT must contain at least 16 characters and must never rotate');
  if (previous && previous.length < 32) throw new Error('SAG_SECRET_PREVIOUS must contain at least 32 characters');
  return {
    secrets: [current, previous].filter(Boolean),
    subject: { salt },
    profile: { claims: PROFILE_CLAIMS, showPicture: true },
    localIdentities: {
      backend: 'file',
      bindingName: 'SAG_LOCAL_IDENTITIES',
      maxPasswordBytes: 1024,
      totpSkew: 1,
    },
  };
}

async function boundedJson(path, description) {
  const limit = 64 * 1024;
  let handle;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- operator-supplied CLI path is the purpose of this offline tool
    handle = await open(resolve(path), 'r');
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(description + ' file must be a regular file');
    if (stat.size > limit) throw new Error(description + ' file is larger than 64 KiB');

    // Read at most one byte beyond the limit. This also catches a file which
    // grows after fstat without allocating memory in proportion to its size.
    const buffer = Buffer.alloc(limit + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > limit) throw new Error(description + ' file is larger than 64 KiB');
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, offset)));
    } catch (cause) {
      throw new Error(description + ' file is not valid UTF-8 JSON: ' + cause.message, { cause });
    }
  } finally {
    await handle?.close();
  }
}

async function passwordFromStdin(input) {
  const chunks = [];
  let length = 0;
  for await (const chunk of input) {
    const bytes = Buffer.from(chunk);
    const newline = bytes.indexOf(0x0a);
    const part = newline === -1 ? bytes : bytes.subarray(0, newline);
    length += part.length;
    if (length > 1024) throw new Error('password must contain at most 1024 UTF-8 bytes');
    chunks.push(part);
    if (newline !== -1) break;
  }
  let line = Buffer.concat(chunks);
  if (line.at(-1) === 0x0d) line = line.subarray(0, -1);
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(line);
  } catch {
    throw new Error('password must be valid UTF-8');
  }
  const bytes = Buffer.byteLength(value, 'utf8');
  if (bytes < 12) throw new Error('password must contain at least 12 UTF-8 bytes');
  if (bytes > 1024) throw new Error('password must contain at most 1024 UTF-8 bytes');
  return value;
}

function checkedClaims(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('claims must be a JSON object');
  }
  for (const [claim, held] of Object.entries(value)) {
    if (!PROFILE_CLAIMS.includes(claim)) throw new Error('claims contains unsupported field: ' + claim);
    if (typeof held !== 'string' || !held) throw new Error('claim ' + claim + ' must be a non-empty string');
    if (held.length > 512) throw new Error('claim ' + claim + ' must contain at most 512 characters');
    if (claim === 'picture' && !/^https:\/\//i.test(held)) throw new Error('claim picture must be an HTTPS URL');
  }
  return value;
}

async function upstreamLinks(config, source, env, identityId) {
  if (source === undefined) return [];
  if (!Array.isArray(source) || source.length > 20) throw new Error('upstreams must be an array of at most 20 links');
  const links = [];
  for (const raw of source) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('each upstream link must be an object');
    const allowed = new Set(['id', 'upstream', 'issuer', 'subject', 'sub', 'refresh_token_env', 'refresh_token']);
    const unknown = Object.keys(raw).find((field) => !allowed.has(field));
    if (unknown) throw new Error('an upstream link contains unsupported field: ' + unknown);
    if ('refresh_token' in raw) {
      throw new Error('put a refresh token in an environment variable named by refresh_token_env, not in JSON');
    }
    if (raw.id !== undefined && typeof raw.id !== 'string') throw new Error('upstream link id must be a string');
    if (typeof raw.upstream !== 'string') throw new Error('upstream link upstream must be a string');
    if (typeof raw.issuer !== 'string') throw new Error('upstream link issuer must be a string');
    if (raw.subject !== undefined && raw.sub !== undefined) {
      throw new Error('an upstream link must use subject or sub, not both');
    }
    const subject = raw.subject ?? raw.sub;
    if (typeof subject !== 'string') throw new Error('upstream link subject must be a string');
    if (raw.refresh_token_env !== undefined && typeof raw.refresh_token_env !== 'string') {
      throw new Error('upstream link refresh_token_env must be a string');
    }
    const candidate = {
      id: raw.id ?? newCredentialId(),
      upstream: raw.upstream,
      issuer: raw.issuer,
      subject,
    };
    const link = normaliseLocalUpstreamLink(candidate, links.length);
    if (!link) throw new Error('an upstream link is malformed or contains an unsupported value');
    if (raw.refresh_token_env) {
      const variable = String(raw.refresh_token_env);
      if (!/^[A-Z_][A-Z0-9_]*$/.test(variable)) throw new Error('refresh_token_env is not a valid environment variable name');
      // eslint-disable-next-line security/detect-object-injection -- the operator deliberately names the source environment variable
      const token = env[variable];
      if (!token) throw new Error(variable + ' is empty or unset');
      if (String(token).length > 16384) throw new Error(variable + ' is too large to store');
      link.refresh_token = await sealUpstreamRefreshToken(config, identityId, link, String(token));
    }
    links.push(link);
  }
  return links;
}

function recoveryCode() {
  const id = encodeBase32(randomBytes(5));
  const body = encodeBase32(randomBytes(10)).match(/.{1,4}/g).join('-');
  return { id, code: id + '-' + body };
}

export async function provision(options, { env = process.env, input = process.stdin, output = console.log } = {}) {
  const config = toolConfig(env);
  const directory = resolve(options.directory || env.LOCAL_IDENTITIES_DIR || '');
  if (!options.directory && !env.LOCAL_IDENTITIES_DIR) throw new Error('--directory or LOCAL_IDENTITIES_DIR is required');
  if (!options.password_stdin) throw new Error('--password-stdin is required; passwords are never accepted in arguments');
  const email = normaliseEmail(options.email);
  if (!email || !looksLikeEmail(email)) throw new Error('--email must be an address such as name@example.com');
  const count = Number(options.backup_codes || 0);
  if (!Number.isSafeInteger(count) || count < 0 || count > 20) throw new Error('--backup-codes must be a whole number from 0 to 20');

  const binding = createFileLocalIdentityStore(directory);
  const password = await passwordFromStdin(input);
  const identityId = newLocalIdentityId();
  const key = await localIdentityKey(config, email);
  const claims = options.claims ? checkedClaims(await boundedJson(options.claims, 'claims')) : undefined;
  const upstreamSource = options.upstreams ? await boundedJson(options.upstreams, 'upstreams') : undefined;
  const upstreams = await upstreamLinks(config, upstreamSource, env, identityId);
  const totp = [];
  let totpSecret;
  if (options.totp) {
    const id = newCredentialId();
    totpSecret = encodeBase32(randomBytes(20));
    totp.push({
      id,
      label: 'Authenticator',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: await sealTotpSecret(config, identityId, id, totpSecret),
    });
  }

  const codes = [];
  const backupCodes = [];
  for (let i = 0; i < count; i += 1) {
    const recovery = recoveryCode();
    codes.push(recovery.code);
    backupCodes.push({ id: recovery.id, hash: await binding.hashArgon2id(recovery.code) });
  }
  const record = {
    v: 1,
    id: identityId,
    revision: 1,
    security_version: 1,
    password: await binding.hashArgon2id(password),
    ...(claims ? { claims } : {}),
    ...(totp.length || backupCodes.length ? { mfa_required: true } : {}),
    totp,
    backup_codes: backupCodes,
    upstreams,
  };
  if (!parseLocalIdentityRecord(config, record, key)) throw new Error('the generated identity did not pass schema validation');
  if (!(await binding.replace(key, 0, record))) throw new Error('an identity already exists for that address; nothing was changed');

  output('Created ' + join(directory, key + '.json'));
  output('Identity id: ' + identityId);
  if (totpSecret) {
    output('TOTP secret: ' + totpSecret);
    output(
      'TOTP URI: ' +
        'otpauth://totp/' +
        encodeURIComponent('SAG:' + email) +
        '?secret=' +
        totpSecret +
        '&issuer=SAG&algorithm=SHA1&digits=6&period=30',
    );
  }
  if (codes.length) {
    output('Backup codes (shown once):');
    for (const code of codes) output('  ' + code);
  }
  return { directory, key, identityId, totpSecret, backupCodes: codes };
}

export async function rekey(options, { env = process.env, output = console.log } = {}) {
  const config = toolConfig(env);
  if (config.secrets.length < 2) throw new Error('--rekey requires SAG_SECRET_PREVIOUS');
  const directory = resolve(options.directory || env.LOCAL_IDENTITIES_DIR || '');
  if (!options.directory && !env.LOCAL_IDENTITIES_DIR) throw new Error('--directory or LOCAL_IDENTITIES_DIR is required');
  const binding = createFileLocalIdentityStore(directory);
  await binding.assertDirectory();
  const service = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: binding });
  const result = await service.rekeyAll();
  output('Rekeyed ' + result.changed + ' record(s); ' + result.unchanged + ' already used the current secret.');
  return result;
}

export async function main(argv = process.argv.slice(2), io = {}) {
  const options = parseArguments(argv);
  if (options.help || options.h) {
    (io.output || console.log)(HELP);
    return;
  }
  if (options.rekey) {
    if (options.email || options.password_stdin || options.totp || options.backup_codes || options.claims || options.upstreams) {
      throw new Error('--rekey cannot be combined with identity-creation options');
    }
    return rekey(options, io);
  }
  return provision(options, io);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    console.error('Could not update local identities: ' + error.message);
    process.exitCode = 1;
  });
}
