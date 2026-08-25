# 0010. Relaying authentication events to a SIEM, one destination per instance

Status: Proposed

## Context

An operator wants sign-in, sign-out and abuse-relevant events visible in
their own security tooling, not only in SAG's own log stream. SAG already
emits structured, one-line-per-event JSON logs for exactly this kind of
thing - sign-in succeeded, an upstream error, an OTP sent, an OTP send
refused by rate limit, an authorisation code issued, tokens issued, a
session ended, a start-up configuration warning - see the `log.*` calls
throughout `src/`. On most platforms an operator already wires the
platform's log pipeline (CloudWatch, Cloudflare Logpush, whatever a plain
`node` process writes to stdout) into a SIEM, and that is often enough. It
falls short in two ways: a log line is whatever shape the code that wrote
it happened to choose, with no shared vocabulary across deployments or
versions, so a detection rule written against today's wording breaks
quietly the next time that message changes; and it carries no signature,
so once it leaves SAG's process it is only as trustworthy as every hop the
log pipeline takes on the way to the SIEM.

CAEP (the Continuous Access Evaluation Profile, part of the OpenID Shared
Signals Framework, SSF) solves a related but narrower problem: an identity
provider telling one specific relying party that one specific subject's
session or credential state changed, over a stream that relying party
registered and can manage. That machinery - stream registration, per-
subject delivery, poll or push chosen per receiver - is built for a
multi-tenant fan-out SAG does not have here. A SIEM is not a relying
party: it does not care about one subject's stream, and it wants
everything a deployment sees, not a filtered slice of it. Building the
full SSF stream-management API to serve one operator-configured
destination would be solving a shape of problem SAG does not actually
have.

## Proposal

Borrow the one part of SSF/CAEP worth keeping - the Security Event Token
(SET, RFC 8417: a signed JWT with a fixed event envelope and a
URN-namespaced event type) - without the streaming and subscription
protocol built around it. Emit a SET, signed by the same signer set that
already signs `id_token`
([ADR 0006](../adr/0006-algorithm-agile-signing.md)), for a fixed
catalogue of security-relevant events: sign-in succeeded, sign-in failed
(an upstream error or a refused code), an OTP sent, an OTP send refused by
rate limit, an authorisation code issued, tokens issued, a session ended
(scoped or global, mirroring
[ADR 0004](../adr/0004-session-scope-and-sign-out-confirmation.md)), and a
start-up configuration warning. Where an event maps directly onto a CAEP
type - a session ending onto `session-revoked` - use CAEP's URN, so a SIEM
already parsing CAEP from another vendor recognises it without a
SAG-specific rule; where nothing in CAEP fits (an OTP send, a rate limit),
define a SAG-specific event type in the same envelope shape rather than
force a mismatch onto a CAEP type that does not really mean that.

Configure one export destination per running instance -
`SIEM_WEBHOOK_URL`, plus which event types to include - not one per
relying party. Delivery is push only: SAG POSTs each SET as it happens,
signed as an outbound request the same way any other SAG-initiated call to
a third party already is
([ADR 0010](../adr/0010-signed-outbound-requests.md)), so the SIEM
authenticates the request without a shared secret beyond SAG's own
published keys. No stream registry, no subscription API, no per-subject
authorisation to get wrong: one instance, one destination, every event
above a configured severity.

## Cost

Push-only and fire-and-forget from a stateless instance means an export
that fails - the SIEM endpoint is down, DNS is broken, whatever the
reason - has nowhere durable to retry from without the same optional
state store the rest of SAG depends on for anything that outlives a
single request
([ADR 0001](../adr/0001-stateless-with-optional-state-store.md)); without
it, a failed export is simply lost and logged as a warning, and that has
to be an honest, visible limitation rather than a silent gap in an
operator's audit trail. Every event now costs an outbound HTTP call on a
path that is otherwise pure compute, so it must never be allowed to block
or fail the request that triggered it - fire-and-forget, never
fire-and-await. A fixed event catalogue is also an ongoing maintenance
surface: every new security-relevant `log.*` call added to `src/` in
future is a decision about whether it belongs in the export catalogue
too, and nothing today would enforce that the two stay in step with each
other.
