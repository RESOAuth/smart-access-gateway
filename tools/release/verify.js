import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  expected, fileBytes, validateManifest, validateFiles, provenanceEnvelopes,
  validateExport, REPOSITORY, ISSUER,
} from './policy.js';

export function command(program, args, options = {}) {
  // Arguments are passed without a shell; release metadata is never code.
  return execFileSync(program, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'], ...options });
}

export function checkToolVersions() {
  const cosign = JSON.parse(command('cosign', ['version', '--json'])).gitVersion;
  const gh = /^gh version (\d+\.\d+\.\d+)/.exec(command('gh', ['--version']))?.[1];
  for (const [name, actual, minimum] of [['cosign', cosign?.replace(/^v/, ''), '3.1.3'], ['gh', gh, '2.101.0']]) {
    const parts = actual?.split('.').map(Number);
    const floor = minimum.split('.').map(Number);
    assert(parts && parts.length === 3 && parts.every(Number.isInteger) && parts[0] === floor[0] &&
      (parts[1] > floor[1] || (parts[1] === floor[1] && parts[2] >= floor[2])), `${name} requires >= ${minimum} within the same major version`);
  }
}

export function verifyRelease(directory, tag, commit, runId) {
  const policy = { ...expected(tag, commit), runId };
  checkToolVersions();
  const signaturePolicy = ['--certificate-identity', policy.identity, '--certificate-oidc-issuer', ISSUER];
  // Authenticate before using any field from the manifest as a path or target.
  command('cosign', ['verify-blob', resolve(directory, 'release-manifest.json'), '--bundle',
    resolve(directory, 'release-manifest.sigstore.json'), ...signaturePolicy]);
  const manifest = validateManifest(JSON.parse(fileBytes(directory, 'release-manifest.json')), policy);
  validateFiles(directory, manifest);
  const attestationPolicy = ['--repo', REPOSITORY, '--cert-identity', policy.identity,
    '--cert-oidc-issuer', ISSUER, '--source-ref', `refs/tags/${tag}`, '--source-digest', commit,
    '--signer-digest', commit, '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1'];
  const image = manifest.images[0].reference;
  command('cosign', ['verify', image, ...signaturePolicy]);
  command('gh', ['attestation', 'verify', `oci://${image}`, '--bundle',
    resolve(directory, 'container.provenance.sigstore.json'), ...attestationPolicy]);
  for (const name of ['release-manifest.json', ...manifest.files.map(file => file.name)]) {
    command('gh', ['attestation', 'verify', resolve(directory, name), '--bundle',
      resolve(directory, 'files.provenance.sigstore.json'), ...attestationPolicy]);
  }
  validateExport(directory, provenanceEnvelopes(directory, manifest));
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [directory, tag, commit, runId, ...extra] = process.argv.slice(2);
  assert(directory && tag && commit && extra.length === 0, 'Usage: node tools/release/verify.js DIRECTORY TAG COMMIT [RUN_ID]');
  const manifest = verifyRelease(directory, tag, commit, runId);
  console.log(`Verified ${tag} (${commit}): ${manifest.images[0].reference}`);
}
