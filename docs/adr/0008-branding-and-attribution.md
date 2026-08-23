# 0008. Branded and attributed by default; whitelabelling available, attribution never removable

Date: 2026-08-23
Status: Accepted

## Context

The sign-in pages are the only part of SAG a person ever sees, and an
unfamiliar domain with no indication of who is asking for an email address
is indistinguishable from a phishing page. SAG is also both an open-source
project anybody can self-host and a product RESOAuth operates on behalf of
paying customers, so the default has to work for a solo self-hoster, an
enterprise that wants its own name in front, and a hosted offering, without
any of them having to fight the defaults to get there.

## Decision

Default to branded: the header says RESOAuth Smart Access Gateway, the
footer names the software and who made it. `UI_ORG_NAME` and `UI_LOGO_URL`
put an operator's own identity in the header, in front of a person signing
in to *their* service, and `UI_WHITELABEL=true` drops the product name from
the page entirely - but the footer keeps "Powered by RESOAuth" in every
configuration, because a person is entitled to know who is actually
processing their sign-in, whether or not they recognise the name in the
header. A fork is not forced to keep RESOAuth's name specifically:
`UI_BRAND_NAME` and `UI_BRAND_URL` let it rename that attribution to itself
honestly, rather than removing it.

Terms and privacy links follow the same shape as branding generally: an
instance-wide default (`UI_TERMS_URL`, `UI_PRIVACY_URL`), overridden per
relying party (`CLIENT_<SLUG>_TOS_URI` / `_POLICY_URI`, or a CIMD client's
own published `tos_uri`/`policy_uri`), because the relying party's own
terms are what the person is actually agreeing to.

## Consequences

There is no configuration that removes attribution entirely - that is a
deliberate line, not an oversight, and a deployment that wants to present
as fully unbranded software cannot do so through configuration. See
[branding.md](../branding.md) for every variable, and for the CSS mechanism
that lets an operator restyle everything else about the page.
