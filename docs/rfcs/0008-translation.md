# 0008. Translation of user-facing strings

Status: Proposed

## Context

User-facing pages and OTP messages are written in English. `UI_LOCALE`
currently changes the document language without changing its wording, which
can give assistive technology the wrong pronunciation rules. Deployments
serving Wales need consistent Welsh pages and email.

## Proposal

Extract all user-facing text into complete English (`en`) and Welsh (`cy`)
catalogues. `UI_LOCALE` selects one deployment-wide catalogue, defaulting to
English. Set the document language from the selected catalogue. Reject an
unsupported configured locale at startup. This first version does not select
language from browser headers or the OIDC `ui_locales` request parameter.

Translate titles, labels, buttons, errors, status messages, accessible names,
and OTP email subject, text, and HTML body. Use named, typed substitutions and
locale-aware plural forms. Catalogue entries are text, not trusted HTML;
escape substitutions for their output context. Names, addresses, client
metadata, and upstream errors must not inject markup through translation.

Keep protocol field names, OAuth error codes, routes, identifiers, and address
canonicalisation unchanged. Localise the human-readable explanation of an
error, never its protocol value. UI and email use the same locale throughout
a transaction.

Require matching catalogue keys and substitution names in CI. A missing
required entry is a packaging defect, not an empty label or an unnoticed
English fallback. Have a fluent Welsh reviewer check wording in context,
including assistive-technology output, expiry, errors, and resend controls.

## Cost

A moderate refactor of pages and email rendering, complete initial translation,
and ongoing review of both catalogues whenever copy changes. Test every page
and email variant in both locales, escaping with adversarial substitutions,
long labels, plurals, catalogue completeness, and unsupported configuration.
Update the existing `UI_LOCALE` configuration documentation when implemented.
