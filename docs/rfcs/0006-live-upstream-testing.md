# 0006. Live upstream testing against Microsoft and Google

Status: Proposed

## Context

Federation is tested against a stub provider with real discovery and signed
ID tokens. That cannot establish real tenant, consent, account-selection,
address-verification, or authentication-context behaviour for Microsoft and
Google. A successful sign-in alone is insufficient evidence.

## Proposal

Maintain one real test registration per provider and a documented set of
synthetic test accounts. Keep credentials outside the repository. Record the
provider, tenant policy, SAG revision, test date, expected outcome, and
redacted result in the upstream test guide. Do not retain live tokens or
identifying screenshots in public evidence.

Exercise this acceptance matrix for each provider:

- Normal sign-in, consent refusal, account selection, missing consent, and
  upstream errors, including safe return to the relying party.
- Allowed and disallowed tenants, organisational guests, consumer accounts,
  and addresses outside the authority of the selected upstream. An email
  claim alone must not establish control of a domain.
- Verified, absent, and unsuitable address claims; stable subject derivation;
  and repeated sign-in with changed optional profile data.
- Password-only and supported MFA results, with recorded issuer-specific
  evidence for the ACR SAG emits. Unsupported contexts must fail a required
  floor rather than become MFA by inference.
- `prompt=none`, `prompt=login`, `max_age`, stale sessions, and configured
  upstream prompts. Failure to meet a requirement must not obtain a weaker
  result through email OTP.
- Expired or reused codes, key rotation and unknown `kid`, bounded discovery
  failures, and upstream token/UserInfo failure where applicable.

Some negative responses cannot safely be induced at a live provider. Mark
these cases explicitly as covered by signed adversarial fixtures, alongside
the live evidence that informs them. Do not label an unexercised case passed.
Fold real behavioural differences into the stub provider and reproducible
regression tests; fold registration requirements into `docs/upstreams.md`.

## Cost

Manual execution and maintained registrations, credentials, consent settings,
and test accounts. Repeat affected cases after upstream-contract changes and
before releasing changes to federation or assurance. Acceptance requires
recorded outcomes and resolved failures, not merely two working login demos.
