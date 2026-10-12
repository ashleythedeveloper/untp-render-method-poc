#!/usr/bin/env node
// Rewrites the PoC-hosted URLs in credentials/*.json to BASE_URL from
// js/config.js and recomputes every digestMultibase that pins a PoC-hosted
// file. Node built-ins only.
//
// A string value counts as PoC-hosted when it is an https: URL whose path is
// /templates/..., /images/... or /credentials/... and that file exists in this
// repository; its origin is replaced with BASE_URL whatever it was before. The
// PoC vocabulary URL (/vocab#term, served from vocab.html) is rewritten the
// same way. An object that holds a hosted file URL in `id` or `linkURL` gets
// `digestMultibase` set to the digest of the local file. A credential that pins another credential
// is written after the one it pins, so its digest covers the final bytes.
//
// Usage: node scripts/build-digests.mjs [--check]
//   --check  exits 1 if any file would change, without writing.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const checkOnly = process.argv.includes('--check');

const configText = readFileSync(join(root, 'js/config.js'), 'utf8');
const baseMatch = /export const BASE_URL = '(https:\/\/[^'/]+)';/.exec(configText);
if (!baseMatch) {
  console.error('Could not read BASE_URL from js/config.js');
  process.exit(2);
}
const BASE_URL = baseMatch[1];
const HOSTED_PATH = /^\/(templates|images|credentials)\/[A-Za-z0-9._-]+$/;

function digestMultibase(bytes) {
  const hash = createHash('sha256').update(bytes).digest();
  return 'u' + Buffer.concat([Buffer.from([0x12, 0x20]), hash]).toString('base64url');
}

function parseHttps(value) {
  if (typeof value !== 'string' || !value.startsWith('https://')) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

// Returns the repository-relative path of a PoC-hosted file URL, or null.
function hostedPath(value) {
  const url = parseHttps(value);
  if (!url || url.search || url.hash || !HOSTED_PATH.test(url.pathname)) return null;
  const local = url.pathname.slice(1);
  return existsSync(join(root, local)) ? local : null;
}

// Returns the value rewritten onto BASE_URL when it is a PoC-hosted file or
// vocabulary URL, or null when it is not.
function rebased(value) {
  const local = hostedPath(value);
  if (local) return BASE_URL + '/' + local;
  const url = parseHttps(value);
  if (url && url.pathname === '/vocab' && !url.search && url.hash && existsSync(join(root, 'vocab.html'))) {
    return BASE_URL + '/vocab' + url.hash;
  }
  return null;
}

const credentialFiles = readdirSync(join(root, 'credentials'))
  .filter((name) => name.endsWith('.json'))
  .map((name) => 'credentials/' + name);

const done = new Set();
const inProgress = new Set();
const changes = [];
// Final text of each processed credential, so --check digests the bytes that
// would be written rather than the stale file on disk.
const finalText = new Map();

function localBytes(local) {
  return finalText.has(local) ? Buffer.from(finalText.get(local)) : readFileSync(join(root, local));
}

function processCredential(file) {
  if (done.has(file)) return;
  if (inProgress.has(file)) throw new Error('Credentials pin each other in a cycle at ' + file);
  inProgress.add(file);
  const before = readFileSync(join(root, file), 'utf8');
  const credential = JSON.parse(before);

  (function walk(node) {
    if (Array.isArray(node)) {
      node.forEach((item, i) => {
        const url = rebased(item);
        if (url) node[i] = url;
        else walk(item);
      });
      return;
    }
    if (!node || typeof node !== 'object') return;
    for (const key of Object.keys(node)) {
      const url = rebased(node[key]);
      if (url) node[key] = url;
      else walk(node[key]);
    }
    for (const key of ['id', 'linkURL']) {
      const local = hostedPath(node[key]);
      if (!local) continue;
      if (local.startsWith('credentials/') && local !== file) processCredential(local);
      node.digestMultibase = digestMultibase(localBytes(local));
    }
  })(credential);

  const after = JSON.stringify(credential, null, 2) + '\n';
  finalText.set(file, after);
  if (after !== before) {
    changes.push(file);
    if (!checkOnly) writeFileSync(join(root, file), after);
  }
  inProgress.delete(file);
  done.add(file);
}

credentialFiles.forEach(processCredential);

console.log('BASE_URL ' + BASE_URL);
for (const file of credentialFiles) {
  console.log(file + '  ' + digestMultibase(localBytes(file)));
}
for (const dir of ['templates', 'images']) {
  for (const name of readdirSync(join(root, dir))) {
    console.log(dir + '/' + name + '  ' + digestMultibase(readFileSync(join(root, dir, name))));
  }
}
if (checkOnly) {
  if (changes.length) {
    console.error('Out of date: ' + changes.join(', '));
    process.exit(1);
  }
  console.log('All credentials are up to date.');
} else {
  console.log(changes.length ? 'Updated: ' + changes.join(', ') : 'No changes.');
}
