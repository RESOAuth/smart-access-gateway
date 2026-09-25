# 0026. Microsoft consumer accounts use consumer MX

Date: 2026-09-25
Status: Accepted

## Context

[ADR 0019](0019-a-common-upstream-must-bound-what-it-may-assert.md) requires
`xms_edov` for a common Microsoft upstream with no tenant allow list. Personal
Microsoft accounts, including Outlook and Hotmail addresses, do not receive
this Entra ID claim and cannot sign in through that route. Microsoft issues
their tokens from the consumer tenant, whose id is
`9188040d-6c67-4c5b-b112-36a304b66dad`. Consumer mail domains use MX hosts
ending in `.olc.protection.outlook.com`; Microsoft 365 domains use
`.mail.protection.outlook.com`.

MX alone cannot replace `xms_edov`: an Entra tenant administrator could assert
an address at a domain with consumer mail routing. The tenant id must also
identify the personal-account tenant. The domain to inspect must come from
the signed token's `email` claim, not from the address typed at sign-in.

## Decision

For a common Microsoft upstream without `ALLOWED_TENANTS`, accept a missing
`xms_edov` only when the verified token's `tid` is the Microsoft consumer
tenant and every MX record for the token's email domain ends in
`.olc.protection.outlook.com`. Resolve MX at callback regardless of provider
hint settings. A failed lookup, no records, a mixed answer, or any other MX
suffix keeps the `xms_edov` requirement. An explicit `xms_edov: false` is
always refused.

The existing Entra rule and tenant allow list remain in force. The start-up
warning explains that the missing bound affects Entra sign-ins, while the
consumer exception is available through the same common upstream.

## Consequences

Personal accounts with the consumer MX pattern can sign in without an
optional claim that they do not emit. Each callback adds one MX lookup.
If DNS cannot answer, SAG refuses that sign-in rather than treating missing
evidence as a consumer account. Personal accounts using other mail routing
still need a separately configured route or verified claim.
