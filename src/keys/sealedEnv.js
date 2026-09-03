// Sealed environment variables.
//
// A deployment account sometimes cannot avoid putting a secret in plain
// environment variables - Lambda console, an ECS task definition, a plain
// EC2 instance's systemd unit. Any value can be pasted instead as a
// reference into one of three AWS secret stores, and is resolved
// transparently before configuration is parsed:
//
//   aws:kms:<ciphertext>                the base64 output of `aws kms encrypt`
//   aws:secretsmanager:<secret id>      a Secrets Manager secret, by name or ARN
//   aws:ssm:<name>                      a SecureString (or plain) SSM parameter
//
// Each is a signed HTTPS call like the rest of src/keys/, not a platform API,
// so this works identically on Lambda, ECS, EC2 or a bare Node process -
// whichever one hands SAG ambient AWS credentials.

import { signRequest, credentialsFromEnv } from '../crypto/sigv4.js';
import { unb64 } from '../util/bytes.js';
import { fetchWithTimeout } from '../util/http.js';

const SERVICES = {
  kms: {
    endpointEnv: 'AWS_ENDPOINT_URL_KMS',
    target: 'TrentService.Decrypt',
    payload: (id) => ({ CiphertextBlob: id }),
    extractValue: (out) => new TextDecoder().decode(unb64(out.Plaintext)),
  },
  secretsmanager: {
    endpointEnv: 'AWS_ENDPOINT_URL_SECRETS_MANAGER',
    target: 'secretsmanager.GetSecretValue',
    payload: (id) => ({ SecretId: id }),
    extractValue: (out) =>
      out.SecretString !== undefined ? out.SecretString : new TextDecoder().decode(unb64(out.SecretBinary)),
  },
  ssm: {
    endpointEnv: 'AWS_ENDPOINT_URL_SSM',
    target: 'AmazonSSM.GetParameter',
    payload: (id) => ({ Name: id, WithDecryption: true }),
    extractValue: (out) => out.Parameter.Value,
  },
};

// None of these may be a prefix of another, so an id containing a colon (an
// ARN, an SSM path) is never split on the wrong one.
const MARKERS = [
  { marker: 'aws:kms:', service: 'kms' },
  { marker: 'aws:secretsmanager:', service: 'secretsmanager' },
  { marker: 'aws:ssm:', service: 'ssm' },
];

/** Every marker a sealed value can start with, for callers that only need to detect one. */
export const SEALED_MARKERS = MARKERS.map((m) => m.marker);

function matchSealed(value) {
  if (typeof value !== 'string') return undefined;
  return MARKERS.find(({ marker }) => value.startsWith(marker));
}

function str(env, key) {
  // eslint-disable-next-line security/detect-object-injection -- key is an environment variable name
  const v = env[key];
  return v === undefined || v === null || String(v).trim() === '' ? undefined : String(v).trim();
}

async function resolve(service, id, { region, credentials, endpoint, timeoutMs = 5000 }) {
  // eslint-disable-next-line security/detect-object-injection -- service is matched from MARKERS table
  const { target, payload, extractValue } = SERVICES[service];
  const url = endpoint || 'https://' + service + '.' + region + '.amazonaws.com/';
  const body = JSON.stringify(payload(id));
  const headers = await signRequest({
    method: 'POST',
    url,
    body,
    service,
    region,
    credentials,
    headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': target },
  });
  const res = await fetchWithTimeout(url, { method: 'POST', headers, body }, timeoutMs);
  const outText = await res.text();
  if (!res.ok) throw new Error(service + ' ' + target + ' failed with HTTP ' + res.status + ' ' + outText.slice(0, 300));
  return extractValue(JSON.parse(outText));
}

/**
 * Resolve every sealed value in an environment bag.
 *
 * Returns the same object, untouched, when nothing is sealed - an unsealed
 * deployment makes no AWS call and needs no AWS credentials at all.
 */
export async function unsealEnv(env) {
  const sealed = Object.entries(env ?? {})
    .map(([key, value]) => ({ key, value, match: matchSealed(value) }))
    .filter((entry) => entry.match);
  if (sealed.length === 0) return env;

  const region = str(env, 'AWS_REGION');
  if (!region) throw new Error('AWS_REGION must be set to unseal a sealed environment variable');
  const credentials = credentialsFromEnv(env);
  const globalEndpoint = str(env, 'AWS_ENDPOINT_URL');

  const unsealed = { ...env };
  await Promise.all(
    sealed.map(async ({ key, value, match }) => {
      const endpoint = str(env, SERVICES[match.service].endpointEnv) || globalEndpoint;
      // eslint-disable-next-line security/detect-object-injection -- key is from Object.entries(env)
      unsealed[key] = await resolve(match.service, value.slice(match.marker.length), { region, credentials, endpoint });
    }),
  );
  return unsealed;
}
