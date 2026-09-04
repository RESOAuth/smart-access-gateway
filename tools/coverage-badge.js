#!/usr/bin/env node
// Draw the coverage badge the README shows, from the lcov report that
// `npm test` writes.
//
// Drawn here rather than fetched from a badge service so that nothing
// outside this repository decides what the README claims, and so the badge
// does not go blank when someone else's service does. The badge is checked
// in: `npm test` rewrites it, and CI fails a change that leaves it stale,
// so it cannot quietly go on claiming a figure nothing measures.

import { readFileSync, writeFileSync } from 'node:fs';

const LCOV = 'coverage/lcov.info';
const BADGE = '.github/coverage.svg';
const LABEL = 'coverage';
// --accent from src/ui/css.js: the badge is part of the branding.
const ACCENT = '#1d4ed8';

const report = readFileSync(LCOV, 'utf8');
// lcov counts per file: LF is lines found, LH lines hit.
const total = (records) =>
  [...report.matchAll(records)].reduce((running, [, n]) => running + Number(n), 0);

const found = total(/^LF:(\d+)$/gm);
if (found === 0) {
  console.error(`No line records in ${LCOV}. Run npm test first.`);
  process.exit(1);
}
const value = ((100 * total(/^LH:(\d+)$/gm)) / found).toFixed(2) + '%';

// Verdana at 11px, near enough for a badge: every character we can be asked
// to draw is narrow, wide, or neither. Two or three pixels of slack only
// pads the box around text that is centred in it anyway.
const textWidth = (text) =>
  [...text].reduce(
    (width, c) => width + (' .:il\'|'.includes(c) ? 3.4 : '%@mw'.includes(c) ? 10 : 6.6),
    0,
  );

const labelBox = Math.round(textWidth(LABEL)) + 10;
const valueBox = Math.round(textWidth(value)) + 10;
const width = labelBox + valueBox;

writeFileSync(
  BADGE,
  `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${LABEL}: ${value}">
  <title>${LABEL}: ${value}</title>
  <linearGradient id="shine" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="round"><rect width="${width}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#round)">
    <rect width="${labelBox}" height="20" fill="#555"/>
    <rect x="${labelBox}" width="${valueBox}" height="20" fill="${ACCENT}"/>
    <rect width="${width}" height="20" fill="url(#shine)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11">
    <text x="${labelBox / 2}" y="15" fill="#010101" fill-opacity=".3">${LABEL}</text>
    <text x="${labelBox / 2}" y="14">${LABEL}</text>
    <text x="${labelBox + valueBox / 2}" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${labelBox + valueBox / 2}" y="14">${value}</text>
  </g>
</svg>
`,
);

console.log(value);
