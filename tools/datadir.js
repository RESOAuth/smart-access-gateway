// Key material that lives in a directory.
//
// A Worker or a Lambda takes its secrets from the platform. A container has to
// be handed them, and `docker compose up` with nothing configured has to work,
// so on first start SAG generates them into the data volume and reads them
// back on every start after that. An instance that generated a fresh signing
// key on every start would invalidate every session and every token it had
// issued the moment it restarted, which is the failure this file exists to
// prevent.
//
// Two files, deliberately separate:
//
//   sag.env     generated secrets. Written once, never edited by hand.
//   config.env  the operator's settings. Never generated, never rewritten.

import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { generateSigningKey, randomSecret } from '../src/keys/generate.js';

export const SECRETS_FILE = 'sag.env';
export const SETTINGS_FILE = 'config.env';

/** KEY=value or KEY='value' lines, with # comments. */
export function parseEnvFile(text) {
  const out = {};
  for (const line of String(text).split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

/**
 * Single quotes, because a signing key is JSON and JSON is full of double
 * quotes. A value containing a single quote could not have come from here, so
 * refusing one is better than writing a file that cannot be read back.
 */
export function formatEnvFile(values, header = []) {
  const lines = header.map((h) => (h ? '# ' + h : '#'));
  for (const [key, value] of Object.entries(values)) {
    const text = String(value);
    if (text.includes("'") || text.includes('\n')) throw new Error(key + ' cannot be written to an env file');
    lines.push(key + "='" + text + "'");
  }
  return lines.join('\n') + '\n';
}

/**
 * Make sure the directory holds everything this instance needs to keep its
 * identity across a restart.
 *
 * @param {string} dir
 * @param {object} [opts] { alg, backend } - the signing algorithm and backend
 * @returns {Promise<{values: object, settings: object, generated: string[]}>}
 */
export async function ensureKeyMaterial(dir, { alg, backend, now = () => new Date() } = {}) {
  const secretsPath = join(dir, SECRETS_FILE);
  const settingsPath = join(dir, SETTINGS_FILE);
  const settings = existsSync(settingsPath) ? parseEnvFile(readFileSync(settingsPath, 'utf8')) : {};
  const values = existsSync(secretsPath) ? parseEnvFile(readFileSync(secretsPath, 'utf8')) : {};
  const generated = [];

  // The settings file has a say in what to generate, because an operator who
  // wrote SIGNING_ALG=ES384 there and then found an ES256 key in the volume
  // would have an instance that cannot sign anything.
  const wantAlg = alg || settings.SIGNING_ALG || 'ES256';
  const wantBackend = backend || settings.SIGNING_BACKEND || 'local';

  if (!values.SAG_SECRET) {
    values.SAG_SECRET = randomSecret();
    generated.push('SAG_SECRET');
  }
  if (!values.SUBJECT_SALT) {
    // Generated even though it is only used with SUBJECT_TYPE=pairwise,
    // because it must never change once it has been used and generating it
    // later would be one more chance to get that wrong.
    values.SUBJECT_SALT = randomSecret();
    generated.push('SUBJECT_SALT');
  }
  // A KMS or HSM backend keeps the key elsewhere, so there is nothing to make.
  if (wantBackend === 'local' && !values.SIGNING_PRIVATE_JWK) {
    const key = await generateSigningKey(wantAlg);
    values.SIGNING_ALG = key.alg;
    values.SIGNING_PRIVATE_JWK = JSON.stringify(key.privateJwk);
    generated.push('SIGNING_PRIVATE_JWK');
  }

  if (generated.length) {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      probeWritable(dir);
    } catch (cause) {
      throw new Error(explainUnwritable(dir, cause), { cause });
    }
    writeFileSync(
      secretsPath,
      formatEnvFile(values, [
        'SAG instance key material, generated ' + now().toISOString() + '.',
        '',
        'This file is the identity of this deployment: anyone holding it can',
        'impersonate it. It lives in the data volume and never in an image.',
        'Deleting it starts a new identity, which signs everybody out and',
        'invalidates every token this instance has issued.',
        '',
        'Settings belong in ' + SETTINGS_FILE + ' next to this file, not here.',
      ]),
      { mode: 0o600 },
    );
    chmodSync(secretsPath, 0o600);
  }

  return { values, settings, generated };
}

/** Fail before writing rather than half way through it. */
function probeWritable(dir) {
  const probe = join(dir, '.sag-write-test');
  writeFileSync(probe, '');
  rmSync(probe, { force: true });
}

/**
 * The one error worth explaining properly.
 *
 * A container that cannot write its data directory is nearly always a
 * bind-mounted host directory under rootless Podman, where the host user maps
 * to root inside the container and the image's own user therefore owns
 * nothing. The stack trace for that is unhelpful; the fix is one line.
 */
function explainUnwritable(dir, cause) {
  if (cause?.code !== 'EACCES' && cause?.code !== 'EPERM') return cause?.message || String(cause);
  return [
    'Cannot write key material to ' + dir + ': ' + cause.code + '.',
    '',
    'This is almost always a bind-mounted directory whose owner is not the user',
    'inside the container. Either use a named volume, which is what',
    'docker-compose.yml does, or fix the ownership:',
    '',
    '  Docker:           chown 1000:1000 ' + dir + ' on the host',
    '  Rootless Podman:  add :U to the volume, for example ./data:/data:U,',
    '                    or run with --userns=keep-id',
    '',
    'See docs/docker.md.',
  ].join('\n');
}
