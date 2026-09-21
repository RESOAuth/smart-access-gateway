import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const REPOSITORY = 'RESOAuth/smart-access-gateway';
export const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
export const WORKFLOW = '.github/workflows/release.yml';
export const IMAGE = 'ghcr.io/resoauth/sag';
export const ISSUER = 'https://token.actions.githubusercontent.com';
export const COMPANIONS = [
  'release-manifest.json', 'release-manifest.sigstore.json',
  'files.provenance.sigstore.json', 'container.provenance.sigstore.json',
  'release.intoto.jsonl',
];
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;

export function version(tag) {
  // Build metadata is deliberately excluded: OCI tags cannot contain '+'.
  assert(typeof tag === 'string' && tag.length <= 120, 'Invalid release tag');
  // The tag length bounds work for the semantic-version expression.
  // eslint-disable-next-line security/detect-unsafe-regex
  const match = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(tag);
  assert(match && tag.length <= 120, 'Expected vMAJOR.MINOR.PATCH[-PRERELEASE]');
  assert(!match[4]?.split('.').some(id => /^\d+$/.test(id) && id.length > 1 && id.startsWith('0')), 'Invalid numeric prerelease identifier');
  return { version: tag.slice(1), major: match[1], minor: match[2], patch: match[3], prerelease: !!match[4] };
}

export function expected(tag, commit) {
  version(tag);
  assert(COMMIT.test(commit), 'Expected full source commit');
  return { tag, commit, identity: `${REPOSITORY_URL}/${WORKFLOW}@refs/tags/${tag}` };
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function fileBytes(directory, name) {
  assert(/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) && name !== '..', 'Unsafe asset name');
  const path = join(directory, name);
  // Never follow a symlink supplied as a release asset.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  assert(lstatSync(path).isFile(), `Not a regular file: ${name}`);
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  return readFileSync(path);
}

export function assetNames(tag) {
  version(tag);
  return [`sag-${tag}-source.tar.gz`, ...COMPANIONS].sort();
}

export function validateManifest(manifest, policy) {
  assert.equal(manifest.schemaVersion, 1, 'Unsupported manifest schema');
  assert.equal(manifest.repository, REPOSITORY_URL, 'Wrong repository');
  assert.equal(manifest.tag, policy.tag, 'Wrong tag');
  assert.equal(manifest.commit, policy.commit, 'Wrong source commit');
  assert.equal(manifest.workflow, WORKFLOW, 'Wrong workflow');
  assert(/^[1-9]\d*$/.test(manifest.run?.id), 'Invalid run ID');
  assert(Number.isSafeInteger(manifest.run.attempt) && manifest.run.attempt > 0, 'Invalid run attempt');
  assert.equal(manifest.run.url, `${REPOSITORY_URL}/actions/runs/${manifest.run.id}/attempts/${manifest.run.attempt}`, 'Wrong run URL');
  if (policy.runId) assert.equal(manifest.run.id, policy.runId, 'Different workflow run');
  assert(Array.isArray(manifest.files) && manifest.files.length === 1, 'Incomplete or unexpected payload set');
  assert.equal(manifest.files[0].name, `sag-${policy.tag}-source.tar.gz`, 'Wrong source archive name');
  assert(SHA256.test(manifest.files[0].sha256), 'Malformed file digest');
  assert(Array.isArray(manifest.images) && manifest.images.length === 1, 'Expected one container');
  const image = manifest.images[0];
  assert.equal(image.name, IMAGE, 'Wrong image repository');
  assert(/^sha256:[a-f0-9]{64}$/.test(image.digest), 'Malformed image digest');
  assert.equal(image.reference, `${IMAGE}@${image.digest}`, 'Wrong image reference');
  // This release contract follows the existing amd64 image, including its
  // BuildKit provenance/SBOM index. Child manifests are not deployment targets.
  assert.deepEqual(image.platforms, ['linux/amd64'], 'Unexpected image platforms');
  return manifest;
}

export function validateFiles(directory, manifest) {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  assert.deepEqual(readdirSync(directory).sort(), assetNames(manifest.tag), 'Incomplete or unexpected release assets');
  for (const name of assetNames(manifest.tag)) fileBytes(directory, name);
  for (const file of manifest.files) {
    assert.equal(sha256(fileBytes(directory, file.name)), file.sha256, `Hash mismatch: ${file.name}`);
  }
}

export function envelopeFromBundle(bundle, subjects, manifest) {
  const envelope = bundle.dsseEnvelope;
  assert(envelope && envelope.payloadType === 'application/vnd.in-toto+json', 'Missing in-toto envelope');
  assert(typeof envelope.payload === 'string' && envelope.payload.length > 0, 'Empty provenance payload');
  assert(Array.isArray(envelope.signatures) && envelope.signatures.length > 0 &&
    envelope.signatures.every(signature => typeof signature.sig === 'string' && signature.sig.length > 0), 'Missing provenance signature');
  const bytes = Buffer.from(envelope.payload, 'base64');
  assert.equal(bytes.toString('base64'), envelope.payload, 'Malformed provenance encoding');
  const statement = JSON.parse(bytes.toString('utf8'));
  assert.equal(statement._type, 'https://in-toto.io/Statement/v1', 'Wrong statement type');
  assert.equal(statement.predicateType, 'https://slsa.dev/provenance/v1', 'Wrong provenance type');
  assert(Array.isArray(statement.subject), 'Missing provenance subjects');
  const sorted = values => [...values].sort((a, b) => a.name.localeCompare(b.name));
  assert.deepEqual(sorted(statement.subject), sorted(subjects), 'Unexpected provenance subjects or digests');
  const definition = statement.predicate?.buildDefinition;
  assert.equal(definition?.buildType, 'https://actions.github.io/buildtypes/workflow/v1', 'Wrong build type');
  assert.deepEqual(definition.externalParameters.workflow, {
    repository: REPOSITORY_URL, path: WORKFLOW, ref: `refs/tags/${manifest.tag}`,
  }, 'Wrong provenance workflow');
  assert.equal(definition.internalParameters.github.event_name, 'push', 'Wrong workflow event');
  assert.equal(definition.internalParameters.github.runner_environment, 'github-hosted', 'Untrusted runner');
  assert.deepEqual(definition.resolvedDependencies, [{
    uri: `git+${REPOSITORY_URL}@refs/tags/${manifest.tag}`, digest: { gitCommit: manifest.commit },
  }], 'Wrong provenance source');
  assert.equal(statement.predicate.runDetails.builder.id, expected(manifest.tag, manifest.commit).identity, 'Wrong builder');
  assert.equal(statement.predicate.runDetails.metadata.invocationId, manifest.run.url, 'Wrong provenance run');
  return envelope;
}

export function provenanceEnvelopes(directory, manifest) {
  const fileSubjects = [...manifest.files, {
    name: 'release-manifest.json', sha256: sha256(fileBytes(directory, 'release-manifest.json')),
  }].map(file => ({ name: file.name, digest: { sha256: file.sha256 } }));
  const image = manifest.images[0];
  return [
    envelopeFromBundle(JSON.parse(fileBytes(directory, 'files.provenance.sigstore.json')), fileSubjects, manifest),
    envelopeFromBundle(JSON.parse(fileBytes(directory, 'container.provenance.sigstore.json')),
      [{ name: IMAGE, digest: { sha256: image.digest.slice(7) } }], manifest),
  ];
}

export function validateExport(directory, envelopes) {
  const lines = fileBytes(directory, 'release.intoto.jsonl').toString('utf8').trim().split('\n');
  assert.equal(lines.length, 2, 'Expected one envelope per bundle');
  assert.deepEqual(lines.map(line => JSON.parse(line)), envelopes, 'Export differs from verified bundles');
}

export function stableAliases(tag, publishedTags) {
  const current = version(tag);
  if (current.prerelease) return [];
  const newer = publishedTags.map(tag => version(tag)).filter(other => !other.prerelease).filter(other =>
    BigInt(other.major) > BigInt(current.major) ||
    (other.major === current.major && BigInt(other.minor) > BigInt(current.minor)) ||
    (other.major === current.major && other.minor === current.minor && BigInt(other.patch) > BigInt(current.patch)));
  return [
    ...(!newer.length ? ['latest'] : []),
    ...(!newer.some(other => other.major === current.major) ? [current.major] : []),
    ...(!newer.some(other => other.major === current.major && other.minor === current.minor) ? [`${current.major}.${current.minor}`] : []),
  ];
}
