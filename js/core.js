// Pure functions behind the host page. Nothing here touches the DOM or the
// network, so scripts/test.mjs can run every rule in Node.
//
// W3C references are to "Verifiable Credential Rendering Methods v1.0",
// Working Draft of 6 October 2026 (WD). Host-mediated links and
// host-prefetched images are this PoC's extensions.

// ---------------------------------------------------------------------------
// JSON Pointer (RFC 6901)
// ---------------------------------------------------------------------------

// Splits a JSON Pointer into reference tokens. Returns null when the string
// is not a pointer: a pointer is "" (the whole document) or starts with "/",
// and "~" may only appear as "~0" or "~1".
export function parsePointer(pointer) {
  if (typeof pointer !== 'string') return null;
  if (pointer === '') return [];
  if (pointer.charAt(0) !== '/') return null;
  const tokens = pointer.slice(1).split('/');
  for (const token of tokens) {
    if (/~(?![01])/.test(token)) return null;
  }
  return tokens.map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));
}

// Resolves a pointer against a document. Returns { found, value } or
// { found: false, reason }.
// Only own properties and canonical array indexes resolve, so a pointer
// cannot reach "__proto__" or "length".
export function resolvePointer(document, pointer) {
  const tokens = parsePointer(pointer);
  if (tokens === null) return { found: false, reason: 'not a JSON Pointer' };
  let value = document;
  for (const token of tokens) {
    if (Array.isArray(value)) {
      if (!/^(0|[1-9][0-9]*)$/.test(token) || Number(token) >= value.length) {
        return { found: false, reason: 'no array element at ' + JSON.stringify(token) };
      }
      value = value[Number(token)];
    } else if (value !== null && typeof value === 'object') {
      if (!Object.prototype.hasOwnProperty.call(value, token)) {
        return { found: false, reason: 'no property ' + JSON.stringify(token) };
      }
      value = value[token];
    } else {
      return { found: false, reason: 'path continues past a non-container value' };
    }
  }
  return { found: true, value };
}

// ---------------------------------------------------------------------------
// digestMultibase (WD section 2.2): multibase "u" (base64url, no padding) of a
// multihash with code 0x12 (SHA-2-256) and length 0x20.
// ---------------------------------------------------------------------------

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(text) {
  let binary;
  try {
    binary = atob(text);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64urlToBytes(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return base64ToBytes(base64 + '==='.slice((base64.length + 3) % 4));
}

export function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === 'string') return new TextEncoder().encode(data);
  throw new TypeError('expected bytes, an ArrayBuffer or a string');
}

// Computes the digestMultibase of some bytes with SubtleCrypto.
export async function computeDigestMultibase(data) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', toBytes(data)));
  const multihash = new Uint8Array(2 + hash.length);
  multihash[0] = 0x12;
  multihash[1] = 0x20;
  multihash.set(hash, 2);
  return 'u' + bytesToBase64(multihash).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Checks bytes against an expected digestMultibase. Returns { ok, reason,
// actual }. The expected value is decoded and compared as a multihash, so a
// wrong multibase prefix or hash code is reported as such, not as a mismatch.
export async function verifyDigestMultibase(data, expected) {
  if (typeof expected !== 'string' || expected.charAt(0) !== 'u') {
    return { ok: false, reason: 'digestMultibase is not multibase "u" (base64url, no padding)' };
  }
  const multihash = base64urlToBytes(expected.slice(1));
  if (!multihash || multihash.length !== 34 || multihash[0] !== 0x12 || multihash[1] !== 0x20) {
    return { ok: false, reason: 'digestMultibase is not a SHA-2-256 multihash (0x12, 0x20)' };
  }
  const actual = await computeDigestMultibase(data);
  const actualBytes = base64urlToBytes(actual.slice(1));
  const same = actualBytes.every((byte, i) => byte === multihash[i]);
  return same
    ? { ok: true, actual }
    : { ok: false, actual, reason: 'digest mismatch: expected ' + expected + ', computed ' + actual };
}

// ---------------------------------------------------------------------------
// Render method selection and the template reference (WD 2.2, 2.2.2, 3.2.1)
// ---------------------------------------------------------------------------

// Returns the first renderMethod entry with type SuiteRenderMethod and
// renderSuite "html", or null. renderSuite is compared exactly (WD 2.2).
export function selectHtmlRenderMethod(credential) {
  const methods = [].concat(credential && credential.renderMethod ? credential.renderMethod : []);
  return methods.find((m) => m && m.type === 'SuiteRenderMethod' && m.renderSuite === 'html') || null;
}

// Decodes a data: URL (RFC 2397) to its bytes and media type.
export function decodeDataUrl(url) {
  const match = /^data:([^,]*?)(;base64)?,(.*)$/s.exec(url);
  if (!match) return null;
  const mediaType = match[1] || 'text/plain;charset=US-ASCII';
  if (match[2]) {
    const bytes = base64ToBytes(match[3].replace(/\s/g, ''));
    return bytes ? { mediaType, bytes } : null;
  }
  try {
    return { mediaType, bytes: new TextEncoder().encode(decodeURIComponent(match[3])) };
  } catch {
    return null;
  }
}

// Describes how to obtain the template, without fetching it. Returns one of
//   { kind: 'inline', bytes, digestMultibase? }   template is a data: URL
//   { kind: 'fetch', url, digestMultibase }        template.id is an https: URL with a digest
//   { kind: 'refuse', reason }
// The PoC fetches only digest-pinned templates, so an https: template without
// digestMultibase is refused even though the WD makes the digest optional.
export function templateReference(renderMethod) {
  const template = renderMethod && renderMethod.template;
  if (typeof template === 'string') {
    if (!template.startsWith('data:')) {
      return { kind: 'refuse', reason: 'template is a URL string with no digestMultibase; this PoC fetches only digest-pinned templates' };
    }
    const decoded = decodeDataUrl(template);
    return decoded ? { kind: 'inline', bytes: decoded.bytes } : { kind: 'refuse', reason: 'template data: URL does not decode' };
  }
  if (template && typeof template === 'object' && typeof template.id === 'string') {
    if (template.id.startsWith('data:')) {
      const decoded = decodeDataUrl(template.id);
      return decoded
        ? { kind: 'inline', bytes: decoded.bytes, digestMultibase: template.digestMultibase }
        : { kind: 'refuse', reason: 'template.id data: URL does not decode' };
    }
    if (!/^https:\/\//.test(template.id)) {
      return { kind: 'refuse', reason: 'template.id is neither a data: URL nor an https: URL' };
    }
    if (typeof template.digestMultibase !== 'string') {
      return { kind: 'refuse', reason: 'template.id has no digestMultibase; this PoC fetches only digest-pinned templates' };
    }
    return { kind: 'fetch', url: template.id, digestMultibase: template.digestMultibase };
  }
  return { kind: 'refuse', reason: 'render method has no template' };
}

// ---------------------------------------------------------------------------
// renderProperty filtering (WD 2.2, 3.2.1)
// ---------------------------------------------------------------------------

// A simplified stand-in for the selectJsonLd algorithm the WD names (VC DI
// ECDSA section 3.4.13): keeps the root @context, id and type, then copies the
// value at each pointer into a new document, creating containers on the way.
// Array positions are kept (unselected elements become null), so a pointer
// into the original credential still names the same value in the copy.
export function filterByRenderProperty(credential, renderProperty) {
  const out = {};
  for (const key of ['@context', 'id', 'type']) {
    if (Object.prototype.hasOwnProperty.call(credential, key)) out[key] = credential[key];
  }
  for (const pointer of [].concat(renderProperty)) {
    const tokens = parsePointer(pointer);
    const resolved = resolvePointer(credential, pointer);
    if (!tokens || !tokens.length || !resolved.found) continue;
    let source = credential;
    let target = out;
    tokens.forEach((token, i) => {
      const last = i === tokens.length - 1;
      const next = Array.isArray(source) ? source[Number(token)] : source[token];
      if (last) {
        target[token] = next;
      } else {
        if (target[token] === undefined || target[token] === null) target[token] = Array.isArray(next) ? [] : {};
        target = target[token];
        source = next;
      }
    });
  }
  return JSON.parse(JSON.stringify(out));
}

// ---------------------------------------------------------------------------
// Wrapper code (WD 2.2.2.2.2, 2.2.2.2.3, Examples 9, 10 and 12)
// ---------------------------------------------------------------------------

// Makes JSON safe inside a <script> data block. "<" can only occur inside JSON
// strings, where "\u003c" means the same character, so the parsed value is
// unchanged while "</script>" and "<!--" can no longer end the block.
export function escapeScriptData(jsonText) {
  return jsonText.replace(/</g, '\\u003c');
}

// The wrapper's own script. The first two parts are Example 12 of the WD.
// The third is the PoC extension for host-mediated links: the template names
// a JSON Pointer into the credential and the host decides what, if anything,
// to open.
export const WRAPPER_SCRIPT = `
const portPromise = new Promise(resolve => {
  window.addEventListener('message', function start(event) {
    if(event.data === 'start' && event.ports?.[0]) {
      window.removeEventListener('message', start);
      resolve(event.ports[0]);
    }
  });
});
window.renderMethodReady = function(err) {
  portPromise.then(port => port.postMessage(
    !err ? 'ready' : {error: {message: err.message}}));
};
// PoC extension: host-mediated links. Only a pointer crosses the port.
window.renderMethodOpenLink = function(pointer) {
  if(typeof pointer !== 'string') return;
  portPromise.then(port => port.postMessage({type: 'open-link', pointer}));
};
`;

// The CSP the WD requires in the wrapper (2.2.2.2.2 and 3.2.1).
export const WRAPPER_CSP = "default-src data: 'unsafe-inline'";

// Builds the srcdoc document. credentialText is the JSON text placed in the
// credential data block: the credential file's own text when nothing is
// filtered. resources maps each original image URL to a data: URL (the PoC
// extension for host-prefetched images); it travels in its own block so the
// credential stays unmodified.
export function buildWrapper({ templateHtml, credentialText, resources }) {
  return '<!DOCTYPE html>\n<html>\n<head>\n' +
    '<meta http-equiv="content-security-policy" content="' + WRAPPER_CSP + '">\n' +
    '<script name="credential" type="application/vc">' + escapeScriptData(credentialText) + '</script>\n' +
    '<script name="resources" type="application/json">' + escapeScriptData(JSON.stringify(resources || {})) + '</script>\n' +
    '<script>' + WRAPPER_SCRIPT + '</script>\n' +
    '</head>\n<body>' + templateHtml + '</body>\n</html>';
}

// ---------------------------------------------------------------------------
// PoC extension: host-mediated links
// ---------------------------------------------------------------------------

// Decides what to do with a message from the template's port, resolving the
// pointer against the credential the host holds. Returns one of
//   { action: 'ignore', reason }   not an open-link message with a pointer
//   { action: 'refuse', pointer, reason }
//   { action: 'open', pointer, url }
export function decideOpenLink(credential, message) {
  if (!message || typeof message !== 'object' || message.type !== 'open-link') {
    return { action: 'ignore', reason: 'not an open-link message' };
  }
  if (typeof message.pointer !== 'string' || parsePointer(message.pointer) === null) {
    return { action: 'ignore', reason: 'open-link message without a JSON Pointer (the host acts only on pointers into the credential)' };
  }
  const pointer = message.pointer;
  const resolved = resolvePointer(credential, pointer);
  if (!resolved.found) return { action: 'refuse', pointer, reason: 'pointer does not resolve: ' + resolved.reason };
  const value = resolved.value;
  if (typeof value !== 'string') return { action: 'refuse', pointer, reason: 'value at pointer is not a URL string' };
  if (!/^https:\/\//.test(value) || value !== value.trim()) {
    return { action: 'refuse', pointer, reason: 'value at pointer is not an absolute https: URL: ' + value };
  }
  try {
    new URL(value);
  } catch {
    return { action: 'refuse', pointer, reason: 'value at pointer is not a valid URL: ' + value };
  }
  return { action: 'open', pointer, url: value };
}

// True when url is on the given origin (the PoC's own pages open directly in
// a new tab; anything else needs the reader's confirmation).
export function isSameOrigin(url, origin) {
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// The verify entry point
// ---------------------------------------------------------------------------

// Mirrors the direct query parameters of the reference implementation's
// verify page: uri (the credential's URL), digestMultibase (its digest) and
// optionally decryptionKey. Builds <appBase>/verify?uri=...&digestMultibase=...
export function buildVerifyUrl(appBase, uri, digestMultibase, decryptionKey) {
  let url = appBase + '/verify?uri=' + encodeURIComponent(uri);
  if (digestMultibase) url += '&digestMultibase=' + encodeURIComponent(digestMultibase);
  if (decryptionKey) url += '&decryptionKey=' + encodeURIComponent(decryptionKey);
  return url;
}

// Reads the verify parameters from a query string. Returns null when there is
// no uri, { uri, digestMultibase?, decryptionKey? } when there is, or
// { error } when the request is unusable.
export function parseVerifyParams(search) {
  const params = new URLSearchParams(typeof search === 'string' ? search : '');
  if (!params.has('uri')) return null;
  if (params.getAll('uri').length > 1) return { error: 'more than one uri parameter' };
  const uri = params.get('uri');
  if (!uri) return { error: 'the uri parameter is empty' };
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    return { error: 'uri is not an absolute URL: ' + uri };
  }
  if (parsed.protocol !== 'https:') return { error: 'uri is not an https: URL: ' + uri };
  const result = { uri };
  for (const name of ['digestMultibase', 'decryptionKey']) {
    if (!params.has(name)) continue;
    const value = params.get(name);
    if (!value) return { error: 'the ' + name + ' parameter is empty' };
    result[name] = value;
  }
  return result;
}

// Checks fetched credential bytes against the digestMultibase the verify URL
// carried (if any) and parses them. Returns { ok: true, text, credential, digest } or
// { ok: false, reason }; digest is the check result or null when none was given.
export async function acceptCredentialBytes(bytes, expectedDigest) {
  let digest = null;
  if (expectedDigest) {
    digest = await verifyDigestMultibase(bytes, expectedDigest);
    if (!digest.ok) return { ok: false, reason: 'credential blocked: ' + digest.reason };
  }
  const text = new TextDecoder().decode(toBytes(bytes));
  try {
    return { ok: true, text, credential: JSON.parse(text), digest };
  } catch (err) {
    return { ok: false, reason: 'the response is not JSON: ' + err.message };
  }
}

// ---------------------------------------------------------------------------
// PoC extension: host-prefetched images, declared by the issuer
// ---------------------------------------------------------------------------

// Limits on what one render may prefetch.
export const RESOURCE_LIMITS = { maxCount: 10, maxBytes: 2 * 1024 * 1024 };

const IMAGE_MEDIA_TYPE = /^image\/[A-Za-z0-9.+-]+$/;

// True when pointer names a value the renderProperty list exposes: the same
// pointer as an entry, or a descendant of one.
export function withinRenderProperty(pointer, renderProperty) {
  return [].concat(renderProperty).some((p) =>
    typeof p === 'string' && (pointer === p || pointer.startsWith(p + '/')));
}

// Plans the prefetch from the render method's renderResource list, a PoC
// extension term: an array of JSON Pointers naming the objects the issuer
// allows the host to fetch for the template. Nothing else in the credential is
// fetched. Each pointer must name an object with an https: URL (linkURL, or id
// when there is no linkURL), a digestMultibase and an image/* mediaType.
// Returns { declared, entries } where each entry is
//   { pointer, fetch: true, url, mediaType, digestMultibase }  or
//   { pointer, fetch: false, reason }.
export function planRenderResources(credential, renderMethod, limits = RESOURCE_LIMITS) {
  const declared = renderMethod && renderMethod.renderResource;
  if (declared === undefined) return { declared: [], entries: [] };
  if (!Array.isArray(declared)) {
    return { declared: [], entries: [{ pointer: String(declared), fetch: false, reason: 'renderResource is not an array of JSON Pointers' }] };
  }
  const renderProperty = renderMethod.renderProperty;
  const entries = declared.map((pointer, index) => {
    if (typeof pointer !== 'string' || parsePointer(pointer) === null || pointer === '') {
      return { pointer: String(pointer), fetch: false, reason: 'not a JSON Pointer to a value in the credential' };
    }
    if (index >= limits.maxCount) {
      return { pointer, fetch: false, reason: 'over the limit of ' + limits.maxCount + ' resources per render' };
    }
    if (renderProperty !== undefined && !withinRenderProperty(pointer, renderProperty)) {
      return { pointer, fetch: false, reason: 'outside renderProperty, so not exposed to the template' };
    }
    const resolved = resolvePointer(credential, pointer);
    if (!resolved.found) return { pointer, fetch: false, reason: 'pointer does not resolve: ' + resolved.reason };
    const node = resolved.value;
    if (!node || typeof node !== 'object' || Array.isArray(node)) {
      return { pointer, fetch: false, reason: 'value at pointer is not an object' };
    }
    const url = typeof node.linkURL === 'string' ? node.linkURL : typeof node.id === 'string' ? node.id : null;
    if (!url || !/^https:\/\//.test(url)) return { pointer, fetch: false, reason: 'no https: URL in linkURL or id' };
    if (typeof node.mediaType !== 'string' || !IMAGE_MEDIA_TYPE.test(node.mediaType)) {
      return { pointer, fetch: false, reason: 'mediaType is not image/*' };
    }
    if (typeof node.digestMultibase !== 'string') {
      return { pointer, fetch: false, reason: 'no digestMultibase, so the host does not fetch it' };
    }
    return { pointer, fetch: true, url, mediaType: node.mediaType, digestMultibase: node.digestMultibase };
  });
  return { declared: declared.slice(), entries };
}

// The data: URL handed to the template for a verified image.
export function imageDataUrl(mediaType, bytes) {
  return 'data:' + mediaType + ';base64,' + bytesToBase64(toBytes(bytes));
}
