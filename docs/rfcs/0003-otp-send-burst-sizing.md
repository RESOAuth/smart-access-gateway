# 0003. Whether the OTP send-burst size is right

Status: Proposed

## Context

The default email OTP send limit is two codes per ten-minute window per
address, with a separate daily ceiling. Enforcement depends on the configured
store; without it there is no shared send limit. Fixed windows can permit four
sends around a boundary. The constants alone do not describe the delivered
rate or how often a legitimate resend is refused.

## Proposal

Retain the current defaults until a four-week operational sample supports a
specific change. Measure delivery latency, resend requests, rate refusals,
successful verification after resend, and support incidents. Record aggregate
counts and latency buckets; do not retain addresses or codes as analytics.
Exclude known synthetic traffic and compare normal load with abuse spikes.

Evaluate candidate limits against legitimate retries, daily mail cost, and the
fixed-window boundary case. Record the sample size and uncertainty; extend
the observation period if it contains too few legitimate resend attempts.
Adopt a change only with evidence that it reduces legitimate refusal without
exceeding the operator's agreed daily mail budget. Record the selected values
and evidence in an ADR, then document them in configuration guidance.

Keep the aggregate per-address ceiling shared across every accepting instance
and relying party using the same replay authority. Per-client limits may
further restrict sending, but creating another client must not multiply that
ceiling. Retain the documented fail-open send-limit outage behaviour from
[ADR 0003](../adr/0003-silent-enumeration-and-rate-limit-defence.md); do not
claim it is a hard mail-budget guarantee. Verification attempt limits are a
separate control.

## Cost

Small instrumentation and configuration work, plus an observation period and
support review. Check counter boundaries, shared-instance aggregation, and
outage behaviour. A data-backed default is the deliverable; changing a
constant without enough evidence is not.
