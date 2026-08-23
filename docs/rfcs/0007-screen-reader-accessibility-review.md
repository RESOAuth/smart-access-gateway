# 0007. Accessibility review with a real screen reader

Status: Proposed

## Context

The markup claims are tested and the pages have been driven in Chromium at
several sizes and zoom levels, but no test substitutes for hearing a page
read aloud.

## Proposal

Run every page in `src/ui/pages.js` through at least one real screen reader
(NVDA or VoiceOver) and fix whatever it surfaces, then record the outcome
somewhere durable enough that a future UI change knows to re-check it.

## Cost

Mainly time: a manual pass, not an automatable one. Any fix it turns up is
likely small, since the markup already passes automated checks.
