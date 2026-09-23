import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, copyFileSync, chmodSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  REPOSITORY, REPOSITORY_URL, WORKFLOW, IMAGE, assetNames, expected, version, sha256,
  validateManifest, validateFiles, envelopeFromBundle, provenanceEnvelopes, validateExport, stableAliases,
} from '../tools/release/policy.js';

const TAG = 'v0.3.0';
const COMMIT = 'a'.repeat(40);
const DIGEST = `sha256:${'b'.repeat(64)}`;
const workflowScript = resolve('tools/release/workflow.js');
const verifyScript = resolve('tools/release/verify.js');
const cliFixture = resolve('test/fixtures/release-cli.js');
const policy = expected(TAG, COMMIT);

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'sag-release-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const directory = join(root, 'release-assets');
  mkdirSync(directory);
  writeFileSync(join(root, 'CHANGELOG.md'), '## 0.3.0 - 2026-09-21\n\n### Security\n\nNone.\n');
  const source = `sag-${TAG}-source.tar.gz`;
  writeFileSync(join(directory, source), 'source archive fixture');
  const manifest = {
    schemaVersion: 1, repository: REPOSITORY_URL, tag: TAG, commit: COMMIT, workflow: WORKFLOW,
    run: { id: '12', attempt: 1, url: `${REPOSITORY_URL}/actions/runs/12/attempts/1` },
    files: [{ name: source, sha256: sha256('source archive fixture') }],
    images: [{ name: IMAGE, digest: DIGEST, reference: `${IMAGE}@${DIGEST}`, platforms: ['linux/amd64'] }],
  };
  writeFileSync(join(directory, 'release-manifest.json'), JSON.stringify(manifest));
  writeFileSync(join(directory, 'release-manifest.sigstore.json'), '{}');
  const subjects = [...manifest.files.map(file => ({ name: file.name, digest: { sha256: file.sha256 } })),
    { name: 'release-manifest.json', digest: { sha256: sha256(readFileSync(join(directory, 'release-manifest.json'))) } }];
  const statement = {
    _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1', subject: subjects,
    predicate: {
      buildDefinition: {
        buildType: 'https://actions.github.io/buildtypes/workflow/v1',
        externalParameters: { workflow: { repository: REPOSITORY_URL, path: WORKFLOW, ref: `refs/tags/${TAG}` } },
        internalParameters: { github: { event_name: 'workflow_dispatch', runner_environment: 'github-hosted' } },
        resolvedDependencies: [{ uri: `git+${REPOSITORY_URL}@refs/tags/${TAG}`, digest: { gitCommit: COMMIT } }],
      },
      runDetails: { builder: { id: policy.identity }, metadata: { invocationId: manifest.run.url } },
    },
  };
  const bundle = statement => ({ dsseEnvelope: {
    payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
    signatures: [{ keyid: '', sig: 'c2lnbmF0dXJl' }],
  } });
  const filesBundle = bundle(statement);
  const containerBundle = bundle({ ...statement, subject: [{ name: IMAGE, digest: { sha256: DIGEST.slice(7) } }] });
  writeFileSync(join(directory, 'files.provenance.sigstore.json'), JSON.stringify(filesBundle));
  writeFileSync(join(directory, 'container.provenance.sigstore.json'), JSON.stringify(containerBundle));
  writeFileSync(join(directory, 'release.intoto.jsonl'), [filesBundle, containerBundle].map(bundle => JSON.stringify(bundle.dsseEnvelope)).join('\n') + '\n');
  const bin = join(root, 'bin');
  mkdirSync(bin);
  for (const program of ['gh', 'cosign', 'docker']) {
    copyFileSync(cliFixture, join(bin, program));
    chmodSync(join(bin, program), 0o755);
  }
  const remote = join(root, 'remote');
  mkdirSync(remote);
  const statePath = join(root, 'state.json');
  writeFileSync(statePath, JSON.stringify({ calls: [], images: {}, remote, identity: policy.identity, commit: COMMIT }));
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, RELEASE_TEST_STATE: statePath,
    RELEASE_TAG: TAG, RELEASE_COMMIT: COMMIT, GITHUB_RUN_ID: '12', GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REPOSITORY: REPOSITORY, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: `refs/tags/${TAG}`,
    GITHUB_SHA: COMMIT, GITHUB_OUTPUT: join(root, 'output') };
  const state = () => JSON.parse(readFileSync(statePath));
  const update = change => { const data = state(); change(data); writeFileSync(statePath, JSON.stringify(data)); };
  const run = operation => spawnSync(process.execPath, [workflowScript, operation], { cwd: root, env, encoding: 'utf8' });
  return { root, directory, manifest, subjects, statement, bundle, filesBundle, containerBundle, env, state, update, run };
}

function passes(result) { assert.equal(result.status, 0, result.stderr); }
function fails(result, pattern) { assert.notEqual(result.status, 0); if (pattern) assert.match(result.stderr, pattern); }

test('release versions reject unsafe names and invalid semantic versions', () => {
  for (const tag of ['v0.3.0', 'v1.2.3-rc.1', 'v1.0.0-alpha-beta']) assert(version(tag));
  for (const tag of ['v01.2.3', 'v1.2', 'v1.2.3-01', 'v1.2.3+build', '../v1.2.3', 'v1.2.3\n', 'v1.2.3;true']) {
    assert.throws(() => version(tag), undefined, tag);
  }
});

test('manifest enforces the complete release contract and independent expected identity', t => {
  const f = fixture(t);
  assert.equal(validateManifest(f.manifest, policy), f.manifest);
  const changes = [
    m => m.schemaVersion++, m => m.repository = 'https://github.com/example/other',
    m => m.workflow = '.github/workflows/bleeding-edge.yml', m => m.tag = 'v0.4.0', m => m.commit = 'c'.repeat(40),
    m => m.run.url += '/other', m => m.run.attempt = 0,
    m => m.files.push(m.files[0]), m => m.files = [], m => m.files[0].name = '../archive',
    m => m.files[0].sha256 = 'invalid', m => m.images[0].digest = 'sha256:abcd',
    m => m.images[0].reference = `${IMAGE}@sha256:${'c'.repeat(64)}`,
    m => m.images[0].name = 'ghcr.io/example/sag', m => m.images[0].platforms.push('linux/arm64'),
  ];
  for (const change of changes) { const m = structuredClone(f.manifest); change(m); assert.throws(() => validateManifest(m, policy)); }
  assert.throws(() => validateManifest(f.manifest, { ...policy, runId: '13' }), /Different workflow run/);
});

test('release assets reject missing companions, modified payloads, extra files, and symlinks', t => {
  const f = fixture(t);
  validateFiles(f.directory, f.manifest);
  for (const name of assetNames(TAG)) {
    const path = join(f.directory, name), original = readFileSync(path);
    rmSync(path);
    assert.throws(() => validateFiles(f.directory, f.manifest));
    writeFileSync(path, original);
  }
  writeFileSync(join(f.directory, 'unexpected'), 'extra');
  assert.throws(() => validateFiles(f.directory, f.manifest), /unexpected release assets/);
  rmSync(join(f.directory, 'unexpected'));
  const source = join(f.directory, f.manifest.files[0].name);
  writeFileSync(source, 'tampered');
  assert.throws(() => validateFiles(f.directory, f.manifest), /Hash mismatch/);
  rmSync(source); symlinkSync(join(f.directory, 'release-manifest.json'), source);
  assert.throws(() => validateFiles(f.directory, f.manifest), /regular file/);
});

test('provenance validates each bundle, exact subjects, source, runner, and run metadata', t => {
  const f = fixture(t);
  const envelopes = provenanceEnvelopes(f.directory, f.manifest);
  validateExport(f.directory, envelopes);
  for (const mutate of [e => e.signatures = [], e => e.payload = '', e => e.payload = '!!!', e => e.payloadType = 'wrong']) {
    const bundle = structuredClone(f.filesBundle); mutate(bundle.dsseEnvelope);
    assert.throws(() => envelopeFromBundle(bundle, f.subjects, f.manifest));
  }
  const mutations = [
    s => s.subject.pop(), s => s.subject.push(s.subject[0]), s => s.subject[0].digest.sha256 = 'c'.repeat(64),
    s => s.predicateType = 'https://example.invalid', s => s._type = 'other',
    s => s.predicate.buildDefinition.externalParameters.workflow.ref = 'refs/heads/main',
    s => s.predicate.buildDefinition.externalParameters.workflow.repository = 'https://github.com/other/repo',
    s => s.predicate.buildDefinition.externalParameters.workflow.path = '.github/workflows/bleeding-edge.yml',
    s => s.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 'c'.repeat(40),
    s => s.predicate.buildDefinition.internalParameters.github.runner_environment = 'self-hosted',
    s => s.predicate.buildDefinition.internalParameters.github.event_name = 'pull_request_target',
    s => s.predicate.runDetails.metadata.invocationId += '2', s => s.predicate.runDetails.builder.id = 'other',
  ];
  for (const mutate of mutations) {
    const statement = structuredClone(f.statement); mutate(statement);
    assert.throws(() => envelopeFromBundle(f.bundle(statement), f.subjects, f.manifest));
  }
  for (const name of ['files.provenance.sigstore.json', 'container.provenance.sigstore.json']) {
    const path = join(f.directory, name), original = readFileSync(path);
    writeFileSync(path, '{}');
    assert.throws(() => provenanceEnvelopes(f.directory, f.manifest), /Missing in-toto envelope/);
    fails(f.run('export'), /Missing in-toto envelope/);
    writeFileSync(path, original);
  }
  writeFileSync(join(f.directory, 'release.intoto.jsonl'), JSON.stringify(envelopes[0]));
  assert.throws(() => validateExport(f.directory, envelopes), /one envelope per bundle/);
  const changed = structuredClone(envelopes); changed[0].signatures[0].sig = 'different';
  writeFileSync(join(f.directory, 'release.intoto.jsonl'), changed.map(e => JSON.stringify(e)).join('\n'));
  assert.throws(() => validateExport(f.directory, envelopes), /differs/);
});

test('stable aliases never advance for prereleases or move backwards across supported release lines', () => {
  assert.deepEqual(stableAliases('v0.3.0-rc.1', []), []);
  assert.deepEqual(stableAliases(TAG, ['v0.2.1']), ['latest', '0', '0.3']);
  assert.deepEqual(stableAliases(TAG, ['v0.4.0']), ['0.3']);
  assert.deepEqual(stableAliases(TAG, ['v1.0.0']), ['0', '0.3']);
  assert.deepEqual(stableAliases(TAG, ['v0.3.1']), []);
});

test('consumer verifier passes exact policy to both cryptographic tools', t => {
  const f = fixture(t);
  passes(spawnSync(process.execPath, [verifyScript, f.directory, TAG, COMMIT, '12'], { env: f.env, encoding: 'utf8' }));
  assert.equal(f.state().calls.filter(call => call[0] === 'gh' && call[1] === 'attestation').length, 3);
  f.update(s => s.identity = policy.identity.replace('release.yml', 'bleeding-edge.yml'));
  fails(spawnSync(process.execPath, [verifyScript, f.directory, TAG, COMMIT], { env: f.env, encoding: 'utf8' }), /Wrong certificate identity/);
});

test('failed signature verification prevents draft creation and uploads', t => {
  const f = fixture(t); f.update(s => s.fail = 'cosign verify-blob');
  fails(f.run('stage'));
  assert.equal(f.state().release, undefined);
});

test('an upload failure leaves a draft and a retry fills only missing identical assets', t => {
  const f = fixture(t); f.update(s => s.fail = 'release upload v0.3.0 ' + join(f.directory, 'release-manifest.json'));
  fails(f.run('stage'));
  assert.equal(f.state().release.draft, true);
  assert(f.state().release.assets.length > 0);
  f.update(s => delete s.fail);
  passes(f.run('stage'));
  assert.deepEqual(f.state().release.assets.map(a => a.name).sort(), assetNames(TAG));
  assert.equal(f.state().release.draft, true);
});

test('conflicting existing draft bytes are never replaced', t => {
  const f = fixture(t); passes(f.run('stage'));
  writeFileSync(join(f.state().remote, 'release-manifest.json'), 'conflict');
  fails(f.run('stage'), /Conflicting uploaded bytes/);
  assert.equal(f.state().release.draft, true);
});

test('promotion failure leaves the verified draft resumable with exactly the same digest', t => {
  const f = fixture(t); passes(f.run('stage'));
  f.update(s => s.fail = '--tag ' + IMAGE + ':latest');
  fails(f.run('publish'));
  assert.equal(f.state().release.draft, true);
  assert.equal(f.state().images[`${IMAGE}:0.3.0`], DIGEST);
  f.update(s => delete s.fail);
  passes(f.run('publish'));
  assert.equal(f.state().release.draft, false);
  assert.equal(f.state().images[`${IMAGE}:latest`], DIGEST);
  fails(f.run('stage'), /Never change a published release/);
});

test('an existing different version digest blocks promotion and publication', t => {
  const f = fixture(t); passes(f.run('stage'));
  f.update(s => s.images[`${IMAGE}:0.3.0`] = `sha256:${'c'.repeat(64)}`);
  fails(f.run('publish'), /Conflicting immutable version image/);
  assert.equal(f.state().release.draft, true);
  assert.equal(f.state().images[`${IMAGE}:latest`], undefined);
});

test('candidate lookup distinguishes an absent image from a registry outage', t => {
  const f = fixture(t);
  passes(f.run('candidate'));
  assert.match(readFileSync(f.env.GITHUB_OUTPUT, 'utf8'), /digest=\n/);
  f.update(s => s.images[`${IMAGE}:candidate-12`] = DIGEST);
  passes(f.run('candidate'));
  assert.match(readFileSync(f.env.GITHUB_OUTPUT, 'utf8'), new RegExp(DIGEST));
  f.update(s => s.fail = 'docker buildx imagetools inspect');
  fails(f.run('candidate'));
});

function sourceFixture(t) {
  const f = fixture(t);
  const git = (...args) => execFileSync('git', args, { cwd: f.root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-b', 'main');
  git('config', 'user.name', 'SAG test'); git('config', 'user.email', 'test@example.invalid');
  mkdirSync(join(f.root, 'src'));
  writeFileSync(join(f.root, 'package.json'), JSON.stringify({ version: '0.3.0' }));
  writeFileSync(join(f.root, 'package-lock.json'), JSON.stringify({ version: '0.3.0', packages: { '': { version: '0.3.0' } } }));
  writeFileSync(join(f.root, 'src/version.js'), "export const VERSION = '0.3.0';\n");
  git('add', 'package.json', 'package-lock.json', 'src/version.js', 'CHANGELOG.md'); git('commit', '-m', 'Release fixture');
  const commit = git('rev-parse', 'HEAD');
  git('update-ref', 'refs/remotes/origin/main', commit);
  f.env.GITHUB_SHA = commit;
  return { ...f, git, commit };
}

test('the release gate accepts a main commit at the dispatched tag and rejects other sources', t => {
  const f = sourceFixture(t);
  f.git('tag', TAG);
  passes(f.run('validate'));
  f.env.GITHUB_EVENT_NAME = 'push';
  fails(f.run('validate'), /Only a dispatched tag/);
  f.env.GITHUB_EVENT_NAME = 'workflow_dispatch';
  f.env.GITHUB_REF = 'refs/heads/main';
  fails(f.run('validate'), /requested tag/);
  f.env.GITHUB_REF = `refs/tags/${TAG}`;
  f.env.GITHUB_SHA = COMMIT;
  fails(f.run('validate'), /Tag moved/);
  f.env.GITHUB_SHA = f.commit;
  f.update(s => s.checkConclusion = 'failure');
  fails(f.run('validate'), /must pass/);
  f.update(s => { delete s.checkConclusion; s.protected = false; });
  fails(f.run('validate'), /main must be protected/);
  f.update(s => delete s.protected);
  f.git('commit', '--allow-empty', '-m', 'Outside main');
  f.env.GITHUB_SHA = f.git('rev-parse', 'HEAD');
  f.git('tag', '-f', TAG);
  fails(f.run('validate'));
});

test('preparation creates the version tag and dispatches the tag workflow without signing keys', t => {
  const f = sourceFixture(t);
  f.env.GITHUB_REF = 'refs/heads/main';
  passes(f.run('prepare-check'));
  assert.equal(f.state().refs, undefined);
  passes(f.run('prepare'));
  assert.deepEqual(f.state().refs, [{ ref: `refs/tags/${TAG}`, object: { type: 'commit', sha: f.commit } }]);
  assert.deepEqual(f.state().dispatchedRuns, [{ id: 34, head_sha: f.commit, head_branch: TAG }]);
  passes(f.run('prepare'));
  assert.equal(f.state().calls.filter(call => call[1] === 'workflow').length, 1, 'a retry points to the existing release run');
  assert.equal(f.state().calls.filter(call => call.includes('POST')).length, 1, 'a retry never recreates the tag');
});

test('preparation retries a failed dispatch using the same tag and source', t => {
  const f = sourceFixture(t);
  f.env.GITHUB_REF = 'refs/heads/main';
  f.update(s => s.fail = 'gh workflow run');
  fails(f.run('prepare'));
  assert.equal(f.state().refs[0].object.sha, f.commit);
  f.update(s => delete s.fail);
  passes(f.run('prepare'));
  assert.equal(f.state().calls.filter(call => call.includes('POST')).length, 1);
  assert.equal(f.state().dispatchedRuns[0].head_sha, f.commit);
});

test('preparation refuses a different branch, version, failing checks, and conflicting tag', t => {
  const f = sourceFixture(t);
  f.env.GITHUB_REF = 'refs/heads/feature';
  fails(f.run('prepare'), /must run from main/);
  assert.equal(f.state().refs, undefined);
  f.env.GITHUB_REF = 'refs/heads/main';
  f.env.RELEASE_TAG = 'v0.4.0';
  fails(f.run('prepare'), /package.json does not match/);
  assert.equal(f.state().refs, undefined);
  f.env.RELEASE_TAG = TAG;
  f.update(s => s.checkConclusion = 'failure');
  fails(f.run('prepare'), /must pass/);
  assert.equal(f.state().refs, undefined);
  f.update(s => {
    delete s.checkConclusion;
    s.refs = [{ ref: `refs/tags/${TAG}`, object: { type: 'commit', sha: COMMIT } }];
  });
  fails(f.run('prepare'), /different commit/);
  assert.equal(f.state().dispatchedRuns, undefined);
});

test('source packaging uses the Git object and never archives the populated working tree', t => {
  const f = fixture(t);
  const git = (...args) => execFileSync('git', args, { cwd: f.root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-b', 'main'); git('config', 'user.name', 'SAG test'); git('config', 'user.email', 'test@example.invalid');
  writeFileSync(join(f.root, 'source.txt'), 'committed source');
  git('add', 'source.txt'); git('commit', '-m', 'Archive fixture');
  f.env.RELEASE_COMMIT = git('rev-parse', 'HEAD'); f.env.IMAGE_DIGEST = DIGEST;
  writeFileSync(join(f.root, 'source.txt'), 'uncommitted change');
  writeFileSync(join(f.root, 'private-config'), 'must not ship');
  passes(f.run('manifest'));
  const archive = join(f.directory, `sag-${TAG}-source.tar.gz`);
  const names = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' });
  assert.equal(names, `sag-${TAG}/\nsag-${TAG}/source.txt\n`);
  assert.equal(execFileSync('tar', ['-xOzf', archive, `sag-${TAG}/source.txt`], { encoding: 'utf8' }), 'committed source');
  assert(existsSync(join(f.directory, 'release-manifest.json')));
});

test('completed release reruns only verify and never upload or promote', t => {
  const f = fixture(t); passes(f.run('stage')); passes(f.run('publish'));
  f.update(s => s.calls = []);
  rmSync(f.directory, { recursive: true });
  passes(f.run('published'));
  assert(!f.state().calls.some(call => call[0] === 'docker' || (call[0] === 'gh' && call[1] === 'release' && ['create', 'upload', 'edit'].includes(call[2]))));
});
