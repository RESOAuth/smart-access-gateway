import assert from 'node:assert/strict';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  REPOSITORY, REPOSITORY_URL, IMAGE, WORKFLOW, assetNames, expected, version,
  sha256, fileBytes, validateManifest, provenanceEnvelopes, stableAliases,
} from './policy.js';
import { command, verifyRelease } from './verify.js';

const tag = process.env.RELEASE_TAG;
const commit = process.env.RELEASE_COMMIT;
const runId = process.env.GITHUB_RUN_ID;
const directory = resolve('release-assets');
const output = (name, value) => {
  assert(!String(value).includes('\n'), 'Multiline workflow output');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
};
const api = (path, ...args) => JSON.parse(command('gh', ['api', `repos/${REPOSITORY}/${path}`, ...args]));
const releases = () => JSON.parse(command('gh', ['api', '--paginate', '--slurp', `repos/${REPOSITORY}/releases?per_page=100`])).flat();
const releaseForTag = () => {
  const matches = releases().filter(release => release.tag_name === tag);
  assert(matches.length <= 1, 'Multiple releases for tag');
  return matches[0];
};

function validateSource(source) {
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY, 'Unexpected repository');
  const parsed = version(tag);
  expected(tag, source);
  command('git', ['merge-base', '--is-ancestor', source, 'refs/remotes/origin/main']);
  assert.equal(api('branches/main').protected, true, 'main must be protected');
  command('git', ['checkout', '--detach', source]);
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  assert.equal(pkg.version, parsed.version, 'package.json does not match tag');
  const runtime = /export const VERSION = '([^']+)';/.exec(readFileSync('src/version.js', 'utf8'))?.[1];
  assert.equal(runtime, parsed.version, 'src/version.js does not match tag');
  const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  assert.equal(lock.version, parsed.version, 'Lockfile does not match tag');
  assert.equal(lock.packages?.['']?.version, parsed.version, 'Lockfile root package does not match tag');
  releaseNotes(parsed.version);

  // A green rerun is required after any failed or cancelled run for this commit.
  for (const workflow of ['ci.yml', 'codeql.yml', 'scorecard.yml']) {
    const runs = api(`actions/workflows/${workflow}/runs?head_sha=${source}&branch=main&event=push&per_page=1`).workflow_runs;
    assert(runs.length === 1 && runs[0].status === 'completed' && runs[0].conclusion === 'success', `${workflow} must pass on this main commit before tagging`);
  }
}

function validateTag() {
  assert.equal(process.env.GITHUB_EVENT_NAME, 'workflow_dispatch', 'Only a dispatched tag can release');
  assert.equal(process.env.GITHUB_REF, `refs/tags/${tag}`, 'Release must run at the requested tag');
  version(tag);
  const peeled = command('git', ['rev-parse', `refs/tags/${tag}^{commit}`]).trim();
  assert.equal(peeled, process.env.GITHUB_SHA, 'Tag moved from the triggering commit');
  validateSource(peeled);
  output('commit', peeled);
  const release = releaseForTag();
  output('published', !!release && !release.draft);
  const artifacts = JSON.parse(command('gh', ['api', '--paginate', '--slurp', `repos/${REPOSITORY}/actions/runs/${runId}/artifacts?per_page=100`])).flatMap(page => page.artifacts);
  const checkpoints = artifacts.filter(artifact => artifact.name === 'signed-release');
  assert(checkpoints.length <= 1 && !checkpoints.some(artifact => artifact.expired), 'Signing checkpoint missing or expired; do not rebuild this release');
  if (release?.draft) assert(checkpoints.length === 1, 'Existing draft requires this run\'s signing checkpoint');
  output('checkpoint', checkpoints[0]?.id || '');
}

function prepare(checkOnly = false) {
  assert.equal(process.env.GITHUB_EVENT_NAME, 'workflow_dispatch', 'Preparation must be manually dispatched');
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main', 'Prepare release must run from main');
  const source = process.env.GITHUB_SHA;
  validateSource(source);
  if (checkOnly) return;

  const ref = `refs/tags/${tag}`;
  const matching = api(`git/matching-refs/tags/${tag}`).filter(item => item.ref === ref);
  assert(matching.length <= 1, 'Multiple matching release refs');
  if (matching.length) {
    assert.equal(matching[0].object.type, 'commit', 'Expected a workflow-created lightweight tag');
    assert.equal(matching[0].object.sha, source, 'Existing tag points to a different commit');
  } else {
    api('git/refs', '--method', 'POST', '-f', `ref=${ref}`, '-f', `sha=${source}`);
  }

  // Tag writes with GITHUB_TOKEN do not trigger push workflows. Explicit
  // dispatch does; keep the signer running at the tag for its OIDC identity.
  const runs = JSON.parse(command('gh', ['api', '--paginate', '--slurp',
    `repos/${REPOSITORY}/actions/workflows/release.yml/runs?event=workflow_dispatch&head_sha=${source}&per_page=100`,
  ])).flatMap(page => page.workflow_runs);
  const existing = runs.find(run => run.head_branch === tag && run.head_sha === source);
  if (existing) {
    console.log(`Release run already exists: ${REPOSITORY_URL}/actions/runs/${existing.id}. Rerun that run if it failed.`);
    return;
  }
  command('gh', ['workflow', 'run', 'release.yml', '--repo', REPOSITORY, '--ref', tag]);
  console.log(`Started Signed release for ${tag} at ${source}. Follow it in the repository's Actions tab.`);
}

function releaseNotes(releaseVersion) {
  const lines = readFileSync('CHANGELOG.md', 'utf8').split('\n');
  const start = lines.findIndex(line => line.startsWith(`## ${releaseVersion} - `));
  assert(start >= 0, `Missing dated changelog entry for ${releaseVersion}`);
  const end = lines.findIndex((line, index) => index > start && line.startsWith('## '));
  const notes = lines.slice(start + 1, end < 0 ? undefined : end).join('\n').trim();
  assert(notes.includes('### Security'), 'Release notes require Security section');
  return `${notes}\n`;
}

function imageDigest(reference, allowMissing = false) {
  try {
    const digest = command('docker', ['buildx', 'imagetools', 'inspect', reference, '--format', '{{.Manifest.Digest}}'], { stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    assert(/^sha256:[a-f0-9]{64}$/.test(digest), 'Registry returned malformed digest');
    return digest;
  } catch (error) {
    // Authentication errors and outages must never be interpreted as permission
    // to replace an image. Only the registry's explicit absence is acceptable.
    if (allowMissing && /not found|manifest unknown|MANIFEST_UNKNOWN/.test(String(error.stderr))) return null;
    throw error;
  }
}

function candidate() {
  expected(tag, commit);
  const reference = `${IMAGE}:candidate-${runId}`;
  output('reference', reference);
  const existing = imageDigest(reference, true);
  output('digest', existing || '');
  // Refuse to rebuild after publication even if the run checkpoint has expired.
  const release = releaseForTag();
  assert(!release, 'Existing release must be resumed from its checkpoint');
}

function manifest() {
  expected(tag, commit);
  const digest = process.env.IMAGE_DIGEST;
  mkdirSync(directory, { recursive: true });
  const name = `sag-${tag}-source.tar.gz`;
  command('git', ['archive', '--format=tar.gz', `--prefix=sag-${tag}/`, `--output=${join(directory, name)}`, commit]);
  const data = {
    schemaVersion: 1, repository: REPOSITORY_URL, tag, commit, workflow: WORKFLOW,
    run: { id: runId, attempt: Number(process.env.GITHUB_RUN_ATTEMPT),
      url: `${REPOSITORY_URL}/actions/runs/${runId}/attempts/${process.env.GITHUB_RUN_ATTEMPT}` },
    files: [{ name, sha256: sha256(fileBytes(directory, name)) }],
    images: [{ name: IMAGE, digest, reference: `${IMAGE}@${digest}`, platforms: ['linux/amd64'] }],
  };
  validateManifest(data, { ...expected(tag, commit), runId });
  writeFileSync(join(directory, 'release-manifest.json'), `${JSON.stringify(data, null, 2)}\n`);
}

function exportProvenance() {
  const manifest = validateManifest(JSON.parse(fileBytes(directory, 'release-manifest.json')), { ...expected(tag, commit), runId });
  // Validate each bundle before writing anything: a good second bundle cannot
  // mask an absent envelope in the first.
  const envelopes = provenanceEnvelopes(directory, manifest);
  writeFileSync(join(directory, 'release.intoto.jsonl'), `${envelopes.map(envelope => JSON.stringify(envelope)).join('\n')}\n`);
}

function download(release, target) {
  const names = release.assets.map(asset => asset.name).sort();
  assert.deepEqual(names, assetNames(tag), 'Incomplete or unexpected uploaded assets');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(target, { recursive: true });
  command('gh', ['release', 'download', tag, '--repo', REPOSITORY, '--dir', target]);
}

function stage() {
  const manifest = verifyRelease(directory, tag, commit, runId);
  let release = releaseForTag();
  if (!release) {
    const notes = join(tmpdir(), `sag-release-${runId}.md`);
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(notes, releaseNotes(version(tag).version));
    command('gh', ['release', 'create', tag, '--repo', REPOSITORY, '--verify-tag', '--draft',
      '--title', tag, '--notes-file', notes, ...(version(tag).prerelease ? ['--prerelease'] : [])]);
    release = releaseForTag();
  }
  assert(release?.draft, 'Never change a published release');
  assert.equal(release.prerelease, version(tag).prerelease, 'Conflicting prerelease status');
  const existingNames = release.assets.map(asset => asset.name);
  assert.equal(new Set(existingNames).size, existingNames.length, 'Duplicate uploaded assets');
  for (const asset of release.assets) {
    assert(assetNames(tag).includes(asset.name), 'Unexpected existing asset');
    const existing = command('gh', ['api', `repos/${REPOSITORY}/releases/assets/${asset.id}`, '-H', 'Accept: application/octet-stream'], { encoding: 'buffer' });
    assert.equal(sha256(existing), sha256(fileBytes(directory, asset.name)), `Conflicting uploaded bytes: ${asset.name}`);
  }
  for (const name of assetNames(tag).filter(name => !existingNames.includes(name))) {
    command('gh', ['release', 'upload', tag, join(directory, name), '--repo', REPOSITORY]);
  }
  const staged = resolve('downloaded-release');
  download(releaseForTag(), staged);
  verifyRelease(staged, tag, commit, runId);
  assert.equal(JSON.parse(fileBytes(staged, 'release-manifest.json')).images[0].digest, manifest.images[0].digest);
}

function publish() {
  const manifest = verifyRelease(resolve('downloaded-release'), tag, commit, runId);
  const release = releaseForTag();
  assert(release?.draft, 'Never change a published release');
  const source = manifest.images[0].reference;
  const versionTag = version(tag).version;
  const target = `${IMAGE}:${versionTag}`;
  const existing = imageDigest(target, true);
  assert(!existing || existing === manifest.images[0].digest, 'Conflicting immutable version image');
  const publishedTags = releases().filter(release => !release.draft).map(release => release.tag_name);
  const aliases = stableAliases(tag, publishedTags);
  for (const name of [versionTag, ...aliases]) {
    const reference = `${IMAGE}:${name}`;
    // --prefer-index=false preserves a single manifest too; an existing index
    // is copied unchanged, including BuildKit provenance and SBOM descriptors.
    command('docker', ['buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', reference, source]);
    assert.equal(imageDigest(reference), manifest.images[0].digest, 'Promotion changed digest');
  }
  // Publication is last: signing, download verification, or promotion failure
  // leaves a draft and a reusable checkpoint, never a complete public release.
  command('gh', ['release', 'edit', tag, '--repo', REPOSITORY, '--draft=false',
    `--latest=${aliases.includes('latest') ? 'true' : 'false'}`]);
}

const [operation, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0, 'Unexpected arguments');
switch (operation) {
  case 'prepare-check': prepare(true); break;
  case 'prepare': prepare(); break;
  case 'validate': validateTag(); break;
  case 'candidate': candidate(); break;
  case 'manifest': manifest(); break;
  case 'export': exportProvenance(); break;
  case 'stage': stage(); break;
  case 'publish': publish(); break;
  case 'published': {
    const release = releaseForTag();
    assert(release && !release.draft, 'Expected a published release');
    download(release, directory);
    verifyRelease(directory, tag, commit);
    break;
  }
  default: throw new Error('Expected prepare-check, prepare, validate, candidate, manifest, export, stage, publish, or published');
}
