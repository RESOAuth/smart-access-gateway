# 0004. Per-relying-party OTP policy

Status: Proposed

## Context

OTP send limits and code length are deployment-wide today. Some relying
parties need stricter limits. A shorter code also changes online guessing
risk: a sealed browser transaction's attempt count can be rolled back by
replaying an earlier value, so it cannot enforce a verification budget.

## Proposal

### Policy ownership

Define operator-owned bounds for minimum code entropy, maximum lifetime,
maximum failed verification attempts, and aggregate send ceilings. A client
may request a stricter policy through its existing registration mechanism.
Self-published CIMD cannot relax those bounds or opt out of enforcement.
Resolve unset values from deployment policy, validate the effective policy,
and bind it to the client and OTP transaction at issuance. Reject invalid
combinations rather than silently using a weaker value.

Code length must imply at least the operator's minimum entropy under the
chosen alphabet. A longer lifetime or extra attempts cannot compensate for a
shorter code without an explicit operator policy change. At verification,
apply any newly tightened deployment policy as well; incompatible in-flight
transactions restart sign-in. Pre-release deployments need no legacy grace.

Keep one aggregate send ceiling per canonical mailbox across clients and
instances; a per-client ceiling is an additional restriction. Derive opaque
counter keys from the same canonical mailbox rules as existing OTP delivery,
not client-specific subject or plus-address sanitisation. Never collapse
provider-specific mailbox aliases without a verified routing rule. The
existing send-limit fail-open policy remains separate from verification.

### Verification state

Require a qualifying shared atomic verification store for this feature.
Create an expiring record keyed by random OTP transaction id, containing the
client binding, effective policy, attempt budget, verifier, and lifecycle
state. Use a keyed verifier with a secret outside the store for low-entropy
codes. No plaintext code or address is required in the record. The existing
sealed transaction still carries browser context; it is not the counter.

One atomic operation checks expiry and client binding, compares the submitted
code, and either increments failed attempts or consumes the successful code.
Exactly one success is possible, including simultaneous submissions to
different instances. A spent or exhausted record cannot be reset by replaying
a cookie. A resend supersedes the previous code and retains the transaction's
failed-attempt budget. New transactions remain subject to aggregate mailbox
and network verification throttles, so restarting cannot evade the budget.

Bound unauthenticated traffic before expensive work. Verification-store
timeouts and indeterminate outcomes fail closed; there is no stateless
fallback. Preserve the generic errors and enumeration defence in [ADR
0003](../adr/0003-silent-enumeration-and-rate-limit-defence.md). All instances
accepting a transaction must use the same atomic authority; asynchronous
replicas do not suffice. The replay store's existing separate claim and
increment operations do not supply this combined verification transition.

## Cost

This needs policy parsing, a new atomic verification-store operation and
production backend support, aggregate throttles, expiry cleanup, and all
adapter tests. It is larger than a code-length override in `src/otp.js`.
Document proposed per-client fields with relying-party configuration when
implemented. Verification becomes unavailable during a store outage.

Acceptance requires tests for untrusted CIMD weakening, client-id quota
sharding, changed policy, fixed-window boundaries, replayed attempt counters,
simultaneous correct and incorrect submissions, resend and restart abuse,
single-use success, expiry, and store failure. Demonstrate the configured
entropy and aggregate online-guess budget together, rather than describing
code length alone as the security guarantee.
