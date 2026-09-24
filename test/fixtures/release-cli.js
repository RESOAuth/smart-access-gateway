#!/usr/bin/env node
// External CLI doubles exercise failure ordering without publishing anything.
// Synthetic DSSE fixtures do not constitute a cryptographic acceptance test.
import { readFileSync, writeFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { basename, join } from 'node:path';
const statePath = process.env.RELEASE_TEST_STATE;
const state = JSON.parse(readFileSync(statePath));
const program = basename(process.argv[1]);
const args = process.argv.slice(2);
state.calls.push([program, ...args]);
const save = () => writeFileSync(statePath, JSON.stringify(state));
const result = value => { save(); process.stdout.write(typeof value === 'string' ? value : JSON.stringify(value)); };
const fail = message => { save(); console.error(message); process.exit(1); };
const flag = name => args[args.indexOf(name) + 1];
const field = name => args.find((arg, index) => ['-f', '-F'].includes(args[index - 1]) && arg.startsWith(`${name}=`))?.slice(name.length + 1);
if (state.fail && [program, ...args].join(' ').includes(state.fail)) fail('Injected external service failure');
if (program === 'cosign') {
  if (args[0] === 'version') result({ gitVersion: 'v3.1.3' });
  else {
    if (!args.includes('--certificate-identity') || !args.includes('--certificate-oidc-issuer')) fail('Missing signature policy');
    if (flag('--certificate-identity') !== state.identity) fail('Wrong certificate identity');
    if (args.includes('--certificate-github-workflow-sha') && flag('--certificate-github-workflow-sha') !== state.commit) fail('Wrong signature source');
    result('{}');
  }
} else if (program === 'gh') {
  if (args[0] === '--version') result('gh version 2.101.0 (test)\n');
  else if (args[0] === 'attestation') {
    for (const required of ['--source-ref', '--source-digest', '--cert-identity', '--cert-oidc-issuer', '--signer-digest', '--deny-self-hosted-runners']) {
      if (!args.includes(required)) fail(`Missing policy: ${required}`);
    }
    if (flag('--cert-identity') !== state.identity || flag('--source-digest') !== state.commit) fail('Wrong attestation policy');
    if (state.sourceRef && flag('--source-ref') !== state.sourceRef) fail('Wrong source ref');
    result('{}');
  } else if (args[0] === 'api') {
    const endpoint = args.find(arg => arg.startsWith('repos/'));
    if (endpoint.includes('/releases/assets/')) {
      const asset = state.release.assets.find(asset => String(asset.id) === endpoint.split('/').at(-1));
      save(); process.stdout.write(readFileSync(join(state.remote, asset.name)));
    } else if (endpoint.includes('/git/ref/tags/')) {
      if (!state.releaseRef) fail('Tag not found (HTTP 404)');
      result(state.releaseRef);
    } else if (endpoint.includes('/git/matching-refs/tags/')) result(state.refs || []);
    else if (endpoint.endsWith('/git/refs') && flag('--method') === 'POST') {
      const fields = Object.fromEntries(args.filter((_, index) => args[index - 1] === '-f').map(field => field.split('=')));
      const ref = { ref: fields.ref, object: { type: 'commit', sha: fields.sha } };
      if (state.refs?.some(existing => existing.ref === ref.ref)) fail('Ref already exists');
      state.refs = [...(state.refs || []), ref];
      result(ref);
    } else if (endpoint.includes('event=workflow_dispatch')) result([{ workflow_runs: state.dispatchedRuns || [] }]);
    else if (endpoint.endsWith('/releases') && flag('--method') === 'POST') {
      if (state.release) fail('Release exists');
      state.release = { id: 45, tag_name: field('tag_name'), draft: field('draft') === 'true',
        prerelease: field('prerelease') === 'true', assets: [] };
      result(state.release);
    } else if (endpoint.includes('/releases?')) result([state.release && !state.staleReleaseList ? [state.release] : []]);
    else if (/\/releases\/\d+$/.test(endpoint)) {
      if (endpoint.split('/').at(-1) !== String(state.release?.id)) fail('Release not found (HTTP 404)');
      if (flag('--method') === 'PATCH') {
        state.release.draft = field('draft') === 'true';
        state.release.make_latest = field('make_latest');
      }
      result(state.release);
    }
    else if (endpoint.endsWith('/branches/main')) result({ protected: state.protected !== false });
    else if (endpoint.includes('/actions/workflows/')) result({ workflow_runs: [{ status: 'completed', conclusion: state.checkConclusion || 'success' }] });
    else if (endpoint.includes('/artifacts?')) result([{ artifacts: state.artifacts || [] }]);
    else fail(`Unhandled API ${endpoint}`);
  } else if (args[0] === 'workflow' && args[1] === 'run') {
    const tag = flag('--ref');
    const ref = state.refs.find(ref => ref.ref === `refs/tags/${tag}`);
    state.dispatchedRuns = [...(state.dispatchedRuns || []), { id: 34, head_sha: ref.object.sha, head_branch: tag }];
    result('');
  } else if (args[0] === 'release') {
    switch (args[1]) {
      case 'upload': {
        const name = basename(args[3]);
        if (state.release.assets.some(asset => asset.name === name)) fail('Asset exists');
        copyFileSync(args[3], join(state.remote, name));
        state.release.assets.push({ id: state.release.assets.length + 1, name });
        result(''); break;
      }
      case 'download':
        mkdirSync(flag('--dir'), { recursive: true });
        for (const asset of state.release.assets) copyFileSync(join(state.remote, asset.name), join(flag('--dir'), asset.name));
        result(''); break;
      default: fail('Unhandled release command');
    }
  } else fail('Unhandled gh command');
} else if (program === 'docker') {
  if (args[2] === 'inspect') {
    const digest = state.images[args[3]];
    if (!digest) fail('manifest unknown');
    result(digest);
  } else if (args[2] === 'create') {
    state.images[flag('--tag')] = state.promotedDigest || args.at(-1).split('@')[1];
    result('');
  } else fail('Unhandled docker command');
} else fail('Unhandled program');
