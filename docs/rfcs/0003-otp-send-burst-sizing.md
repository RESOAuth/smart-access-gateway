# 0003. Whether the OTP send-burst size is right

Status: Proposed

## Context

The email OTP send limit is two codes per ten-minute window per address. It
unsticks somebody whose first code went to spam, without letting the mail
bill run.

## Proposal

Confirm, or retune, the burst size and window once there is real support
load to judge it against, and decide whether the limit should be per
instance, as it is today, or per relying party.

## Cost

Negligible to change - it is a single constant next to the rest of the OTP
send-limit configuration - but needs real usage data to decide well, which
is why it is not decided yet.
