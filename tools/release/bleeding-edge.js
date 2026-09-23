import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { command, checkToolVersions } from './verify.js';
import { IMAGE, ISSUER, REPOSITORY, REPOSITORY_URL } from './policy.js';

const identity = `${REPOSITORY_URL}/.github/workflows/bleeding-edge.yml@refs/heads/main`;

export function verifyBleedingEdge(digest, commit) {
  assert(/^sha256:[a-f0-9]{64}$/.test(digest), 'Expected an exact image digest');
  assert(/^[a-f0-9]{40}$/.test(commit), 'Expected full source commit');
  checkToolVersions();
  const image = `${IMAGE}@${digest}`;
  command('cosign', ['verify', image, '--certificate-identity', identity,
    '--certificate-oidc-issuer', ISSUER, '--certificate-github-workflow-sha', commit,
    '--certificate-github-workflow-trigger', 'push']);
  command('gh', ['attestation', 'verify', `oci://${image}`, '--bundle-from-oci',
    '--repo', REPOSITORY, '--cert-identity', identity, '--cert-oidc-issuer', ISSUER,
    '--source-ref', 'refs/heads/main', '--source-digest', commit, '--signer-digest', commit,
    '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1']);
  return image;
}

function publish(digest, commit) {
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY, 'Unexpected repository');
  assert.equal(process.env.GITHUB_EVENT_NAME, 'push', 'Only main pushes publish development images');
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main', 'Expected main');
  assert.equal(process.env.GITHUB_SHA, commit, 'Source must match the triggering commit');
  const image = verifyBleedingEdge(digest, commit);
  // Candidates may be unsigned while building. Consumer tags move only after
  // both the registry signature and provenance have passed verification.
  for (const tag of [`bleeding-edge-${commit.slice(0, 7)}`, 'bleeding-edge']) {
    const target = `${IMAGE}:${tag}`;
    command('docker', ['buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', target, image]);
    const promoted = command('docker', ['buildx', 'imagetools', 'inspect', target, '--format', '{{.Manifest.Digest}}']).trim();
    assert.equal(promoted, digest, 'Promotion changed digest');
  }
  console.log(`Published signed bleeding-edge (${commit}): ${image}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [operation, digest, commit, ...extra] = process.argv.slice(2);
  assert(['verify', 'publish'].includes(operation) && digest && commit && extra.length === 0,
    'Usage: node tools/release/bleeding-edge.js verify|publish DIGEST COMMIT');
  if (operation === 'publish') publish(digest, commit);
  else console.log(`Verified main (${commit}): ${verifyBleedingEdge(digest, commit)}`);
}
