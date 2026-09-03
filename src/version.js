// Kept in sync with package.json by hand - there is no build step to read it
// from there at runtime on every adapter (a Worker, a Lambda zip, plain
// Node), so a single literal here is the least surprising source of truth.
export const VERSION = '0.2.1';
