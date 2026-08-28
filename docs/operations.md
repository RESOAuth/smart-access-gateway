# Operating a SAG deployment

Runbooks for the things an operator has to do occasionally and must not get
wrong. Each one states what breaks if it is done in the wrong order.

## Rotating the master secret

`SAG_SECRET` protects sessions, in-flight transactions, authorisation codes and
access tokens. Rotating it is routine and does not have to sign anybody out.
Never reuse it for a different issuer: sealed values are purpose-bound, but are
not bound to an issuer name. This is an explicit decision rather than a pending
migration - see
[ADR 0014](adr/0014-sealed-values-remain-independent-of-the-issuer.md).

The rule: **the current secret seals, every configured secret opens.** So a
rotation is done in two deployments, not one.

1. **Deploy with both.** Set `SAG_SECRET` to the new value and
   `SAG_SECRET_PREVIOUS` to the old one.

   ```sh
   SAG_SECRET=<new>
   SAG_SECRET_PREVIOUS=<old>
   ```

   From this moment everything new is sealed under the new secret, and anything
   sealed under the old one still opens. Nobody is signed out, and anybody
   halfway through typing a code can still finish.

2. **Wait.** Long enough for every existing session to have been used at least
   once, because using a session rewrites its cookie under the new secret. One
   `SESSION_TTL` is the safe answer - by then every session has either been
   re-sealed or expired on its own.

3. **Deploy without the old one.** Remove `SAG_SECRET_PREVIOUS`. Any session
   that was never used during the window is now invalid, and those people sign
   in again.

Doing step 3 immediately signs everybody out. That is a legitimate thing to
want after a suspected compromise - it is the revocation mechanism - but it is
not a rotation.

Generate a new secret with:

```sh
npm run keygen -- --secret-only
```

## Rotating the signing key

Different from the master secret, and slower, because relying parties cache the
JWKS.

1. **Publish both.** Add the new key as an additional algorithm, or configure a
   second key of the same algorithm. Both appear in `/jwks.json`, and the old
   one stays primary. Relying parties pick keys by `kid`, so nothing breaks.
2. **Wait for the JWKS cache to turn over.** SAG serves it with a five minute
   cache, but a relying party's own library may cache for much longer. An hour
   is comfortable; a day is safe.
3. **Make the new key primary.** New `id_token`s are signed with it. Anything
   already issued still verifies, because the old key is still published.
4. **Retire the old key** once nothing signed by it can still be within its
   lifetime - `ID_TOKEN_TTL` plus a margin.

Never do steps 1 and 3 in one deployment: a relying party with a cached JWKS
that does not yet contain the new key will reject every token until it refetches.

## Warning with SUBJECT_SALT

Values shorter than 16 characters produce a start-up warning but are not
rejected, because changing one is the more damaging automatic action. Changing
it gives every person a new
`sub` at every relying party, which orphans their accounts - the relying party
sees a brand new user and the old records become unreachable. There is no
migration path short of every relying party re-linking accounts by email.

If it has to change, treat it as a migration project, not an operational task.
`SAG_ISSUER` is deliberately not part of the derivation, so renaming a
deployment is not this - see
[ADR 0011](adr/0011-subject-derived-from-the-verified-address.md). Turning
`SANITISE_PLUS_EMAILS` on or off after people have signed in is: it merges or
splits every account whose owner uses a plus tag.

## Suspected compromise

- **Master secret leaked.** Deploy a new `SAG_SECRET` with no
  `SAG_SECRET_PREVIOUS`. Every session, transaction and code is invalidated at
  once. Everybody signs in again.
- **Signing key leaked.** Configure the new key and make it primary in one
  deployment, and remove the old key at the same time. This will break relying
  parties with a stale JWKS for as long as their cache lasts, which is the
  correct trade: a leaked signing key means anybody can mint an `id_token` for
  anybody.
- **A client secret leaked.** Change that client's secret. Nothing else is
  affected, because a code is bound to its client.

## Reading `/alive`

Nothing to read: a `200` with the body `ok` means a process is listening,
and that is the entire question it answers. It is deliberately independent
of configuration, so it stays `200` even when this instance would refuse to
start - see `/healthz` below for the question that actually depends on being
configured correctly. Point a container orchestrator's liveness probe or a
load balancer's own target-health check at it; do not point a multi-region
failover check at it - see [multi-region.md](multi-region.md).

## Reading `/healthz`

It answers one question - can this instance sign somebody in? - and is
deliberately terse, because it is unauthenticated. What to look for:

- `version` - the deployed SAG release, so a fleet behind a load balancer can
  be checked for a stale instance after a rollout.
- `signing.primary.ephemeral: true` - the instance generated its own key at
  start-up and will invalidate every token it has issued when it restarts. Only
  ever acceptable in development.
- `warnings` - anything in here was tolerated at start-up rather than fatal, so
  it is worth reading after every deployment.
- `routes.upstreams` - a count per provider, so `{"microsoft": 3}` means three
  upstream registrations. Which domains they serve is not published.
- `peer_jwks` - only present with `PEER_JWKS_URLS` set. A peer with
  `within_grace_period: false` has had its keys dropped from `/jwks.json`
  entirely, which means it has been unreachable for a very long time by
  design - see [multi-region.md](multi-region.md).

### What it deliberately will not tell you

Whether a state store is configured, and therefore whether authorisation codes
are single-use and OTP sends are limited, is not published, and neither is
anything that names an upstream domain or a relying party. A map of which
defences are on and who is behind this deployment is more useful to somebody
deciding what to try than it is to you.

Those warnings still exist. They are in the start-up banner on Node, and on
every platform they are written to the log once per isolate as
`configuration warning` with the text in `detail`:

```sh
node adapters/node/server.js               # banner, under "Warnings:"
wrangler tail | grep 'configuration warning'
aws logs tail /aws/lambda/sag --follow | grep 'configuration warning'
```

If you need a machine-readable answer to "is the state store there?", the
honest test is behavioural: redeem an authorisation code twice and check the
second attempt is refused. That is what
[test/local-stack/verify.js](../test/local-stack/verify.js) does.

## Checking a deployment refuses to be insecure

The design principle is that development defaults become hard errors as soon as
a real hostname is in play. It is worth confirming that on a new deployment
rather than trusting it:

```sh
SAG_ISSUER=https://id.example.com node adapters/node/server.js
```

With nothing else set, that must refuse to start and list the reasons - no
master secret, no signing key, no subject salt, and a console email provider.
If it starts, something is wrong with the configuration being passed in.
