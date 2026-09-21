# 0010. Relaying authentication events to a SIEM, one destination per instance

Status: Proposed

## Context

SAG emits structured security logs, but event fields are not a stable public
contract. Operators need detections that survive message wording changes and,
optionally, signed events delivered to one configured SIEM. Platform log
forwarding already handles many deployments and remains a supported transport.

Unawaited network work is not reliable after a serverless response. Lambda can
freeze the execution environment, and Cloudflare's `waitUntil` has a bounded
lifetime. A discarded promise may produce neither delivery nor a failure log.
See the [Lambda runtime lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html)
and [Worker execution context](https://developers.cloudflare.com/workers/runtime-apis/context/#waituntil).

## Proposal

### Event contract

Define a versioned catalogue for sign-in success and failure, OTP send and
send refusal, code issuance, token issuance, session ending, and configuration
warnings. Each event has a stable type, timestamp, random event id, outcome,
and an allow-list of bounded fields. Log this structured event before any
export attempt. Changing prose must not change event identity or semantics.

Exclude credentials, codes, assertions, raw tokens, raw addresses, and arbitrary
upstream response bodies. Where correlation is needed, use a deployment-scoped
pseudonymous identifier with documented retention. Do not turn public client
metadata into trusted operator or severity fields.

For direct delivery, wrap each event in a signed [Security Event Token, RFC
8417](https://www.rfc-editor.org/rfc/rfc8417.html). Use `typ: secevent+jwt`,
SAG's `iss`, an explicit receiver `aud`, `iat`, a unique `jti`, and an `events`
object keyed by a documented SAG-controlled event URI. Keep the same event id
in the log and SET. Publish payload schemas and representative synthetic
fixtures, including session scope from [ADR
0004](../adr/0004-session-scope-and-sign-out-confirmation.md).

Use SAG event types initially. A familiar event name is insufficient to claim
CAEP semantics: any later CAEP mapping must implement its subject and event
contract completely. This proposal does not implement SSF stream registration,
subscriptions, acknowledgement, or a session-revocation protocol.

### Configuration and delivery

Configure one `SIEM_WEBHOOK_URL`, explicit `SIEM_AUDIENCE`, and a bounded
`SIEM_EVENT_TYPES` allow-list per deployment. The operator sets these values;
client metadata and browser requests cannot choose a destination. Require
HTTPS, normal certificate validation, bounded response bodies, no redirects,
and an explicit egress policy. A private SIEM endpoint requires a deliberate
operator-approved network destination, not arbitrary URL fetching.

Sign using an explicitly selected algorithm from the existing signer set
([ADR 0006](../adr/0006-algorithm-agile-signing.md)) that the receiver supports.
Retain public verification keys for the documented event acceptance window.
The receiver validates signature, issuer, audience, type, freshness, and event
schema, and deduplicates by issuer and `jti`. Outbound request signatures follow
[ADR 0010](../adr/0010-signed-outbound-requests.md); that signature alone does
not guarantee the SIEM implements the event-verification contract.

Direct export is best effort with a bounded awaited flush before returning the
authentication response on every adapter. Start one total two-second deadline
for the flush, including signing and delivery of the bounded event batch. Send
each event at most once, cap concurrency, and stop or cancel work at the
deadline. Export failure must not change the authentication result. This can
add up to two seconds of response latency; it is an explicit tradeoff, not
fire-and-forget work that is assumed to survive the response.

Record a bounded local delivery outcome or timeout before returning. Runtime
termination can still prevent that record, so platform logs and delivery
metrics must not be presented as a lossless audit guarantee. Do not wait on
one timeout per event or let an unavailable SIEM exhaust unbounded memory.

There is no durable retry queue in this phase. Operators requiring retained
retries use their platform's supported log-forwarding pipeline and its own
retention and failure monitoring. The current replay store's claims and
counters must not be presented as an export queue. Direct delivery failures
remain visible through local outcomes and aggregate metrics where execution
continues, but are not automatically redelivered.

## Cost

Stable schemas, signing and verification fixtures, bounded delivery, adapter
lifecycle tests, configuration documentation, and an operator runbook. Direct
export adds signing and network work to authentication latency and load.

Acceptance requires tests for a slow or unavailable receiver, signing timeout,
redirect refusal, malformed response, event bursts, and every adapter's
response lifecycle. Verify the total deadline, unchanged authentication
result, bounded queue and concurrency, redaction, receiver deduplication,
audience and type rejection, and key rotation. Record actual delivery limits
without claiming exactly-once or durable delivery.
