# 0008. Translation of user-facing strings

Status: Proposed

## Context

Every string a person sees is in `src/ui/pages.js` and
`src/email/message.js`, and `UI_LOCALE` currently only sets the document
language rather than choosing wording. A deployment serving Wales needs
both.

## Proposal

Extract the user-facing strings into per-locale tables keyed by `UI_LOCALE`,
starting with Welsh, and have `src/ui/pages.js` and `src/email/message.js`
look wording up rather than hard-code it.

## Cost

A moderate refactor of both files, plus the ongoing cost of keeping
translations in sync as strings change - every future UI or email copy
change becomes a change in more than one place.
