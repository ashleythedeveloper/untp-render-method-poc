#!/usr/bin/env node
// Checks for the proof of concept. Node built-ins only; run with
// `node scripts/test.mjs`. Each test names the outcome it protects for a
// reader of the rendered credential or for the issuer.
//
// The template checks run the real wrapper script and template script in a
// Node vm context with a small DOM stand-in. They establish what the frame
// side sends and shows; they are not a browser run, and the sandbox and CSP
// behaviour itself is only observable in a browser.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

import { BASE_URL, CATALOGUE, isCatalogueCredential, toFetchUrl } from '../js/config.js';
import {
  WRAPPER_CSP,
  WRAPPER_SCRIPT,
  buildWrapper,
  computeDigestMultibase,
  decideOpenLink,
  escapeScriptData,
  filterByRenderProperty,
  parsePointer,
  planRenderResources,
  resolvePointer,
  selectHtmlRenderMethod,
  templateReference,
  verifyDigestMultibase,
  withinRenderProperty
} from '../js/core.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => readFileSync(join(root, path));
const readText = (path) => readFileSync(join(root, path), 'utf8');

const dppText = readText('credentials/dpp-cathode.json');
const dccText = readText('credentials/dcc-cathode.json');
const dpp = JSON.parse(dppText);
const dcc = JSON.parse(dccText);
const clone = (value) => JSON.parse(JSON.stringify(value));

const DCC_URL = BASE_URL + '/credentials/dcc-cathode.json';
const IMAGE_URL = BASE_URL + '/images/cathode-product.png';

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('ok      ' + name);
  } catch (err) {
    failed++;
    console.log('FAILED  ' + name);
    console.log('        ' + String(err && err.stack ? err.stack : err).split('\n').join('\n        '));
  }
}

function nodeDigest(bytes) {
  return 'u' + Buffer.concat([Buffer.from([0x12, 0x20]), createHash('sha256').update(bytes).digest()]).toString('base64url');
}

// ---------------------------------------------------------------------------
// JSON Pointer (RFC 6901)
// ---------------------------------------------------------------------------

await test('Host-mediated links, pointers: RFC 6901 escapes resolve, so a template can name any property', () => {
  const doc = { 'a/b': { 'm~n': ['x', 'y'] } };
  assert.deepEqual(parsePointer('/a~1b/m~0n/1'), ['a/b', 'm~n', '1']);
  assert.equal(resolvePointer(doc, '/a~1b/m~0n/1').value, 'y');
  assert.equal(resolvePointer(doc, '').value, doc);
});

await test('Host-mediated links, pointers: malformed pointers, non-canonical indexes and inherited properties do not resolve, so a frame cannot reach outside the credential data', () => {
  assert.equal(parsePointer('no-leading-slash'), null);
  assert.equal(parsePointer('/bad~2escape'), null);
  assert.equal(parsePointer('https://example.com/x'), null);
  assert.equal(resolvePointer({ a: [1, 2] }, '/a/01').found, false);
  assert.equal(resolvePointer({ a: [1, 2] }, '/a/-').found, false);
  assert.equal(resolvePointer({ a: [1, 2] }, '/a/length').found, false);
  assert.equal(resolvePointer({}, '/__proto__').found, false);
  assert.equal(resolvePointer({}, '/constructor').found, false);
});

// ---------------------------------------------------------------------------
// Host-mediated link decisions
// ---------------------------------------------------------------------------

await test('Host-mediated links: a pointer to a value that is not a URL (/credentialSubject/name) is refused, so the host never opens a name', () => {
  const decision = decideOpenLink(dpp, { type: 'open-link', pointer: '/credentialSubject/name' });
  assert.equal(decision.action, 'refuse');
  assert.match(decision.reason, /not an absolute https: URL/);
});

await test('Host-mediated links: a pointer to an http: URL is refused, so only https: links leave the page', () => {
  const tampered = clone(dpp);
  tampered.credentialSubject.producedAtFacility.id = 'http://facility-register.example.com/fac-002';
  const decision = decideOpenLink(tampered, { type: 'open-link', pointer: '/credentialSubject/producedAtFacility/id' });
  assert.equal(decision.action, 'refuse');
  assert.match(decision.reason, /https:/);
});

await test('Host-mediated links: a message carrying a URL instead of a pointer is ignored, so the frame cannot choose a destination', () => {
  assert.equal(decideOpenLink(dpp, { type: 'open-link', url: 'https://attacker.example/' }).action, 'ignore');
  assert.equal(decideOpenLink(dpp, { type: 'open-link', pointer: 'https://attacker.example/' }).action, 'ignore');
  assert.equal(decideOpenLink(dpp, 'https://attacker.example/').action, 'ignore');
  assert.equal(decideOpenLink(dpp, { type: 'navigate', pointer: '/credentialSubject/producedAtFacility/id' }).action, 'ignore');
});

await test('Host-mediated links: pointers that do not resolve, or resolve to objects, are refused', () => {
  assert.equal(decideOpenLink(dpp, { type: 'open-link', pointer: '/credentialSubject/nothing' }).action, 'refuse');
  assert.equal(decideOpenLink(dpp, { type: 'open-link', pointer: '/credentialSubject/relatedDocument/0' }).action, 'refuse');
  assert.equal(decideOpenLink(dpp, { type: 'open-link', pointer: '' }).action, 'refuse');
});

await test('Host-mediated links: the DPP relatedDocument link resolves to the PoC-hosted DCC with its digest, so the reader sees the DCC in the viewer', () => {
  const decision = decideOpenLink(dpp, { type: 'open-link', pointer: '/credentialSubject/relatedDocument/0/linkURL' });
  assert.equal(decision.action, 'open');
  assert.equal(decision.url, DCC_URL);
  assert.equal(isCatalogueCredential(decision.url), true);
  assert.equal(decision.digestMultibase, nodeDigest(read('credentials/dcc-cathode.json')));
});

await test('Host-mediated links: an external link resolves to a non-catalogue URL, so the host asks the reader to confirm before opening it', () => {
  const decision = decideOpenLink(dpp, { type: 'open-link', pointer: '/credentialSubject/producedAtFacility/id' });
  assert.equal(decision.action, 'open');
  assert.equal(decision.url, 'https://facility-register.example.com/fac-002');
  assert.equal(isCatalogueCredential(decision.url), false);
});

// ---------------------------------------------------------------------------
// Digests (WD 2.2)
// ---------------------------------------------------------------------------

await test('WD 2.2 digest: SubtleCrypto multibase-u SHA-256 multihash matches an independent Node computation', async () => {
  for (const path of ['images/cathode-product.png', 'templates/DigitalProductPassport-1.0.0.html', 'credentials/dcc-cathode.json']) {
    assert.equal(await computeDigestMultibase(read(path)), nodeDigest(read(path)), path);
  }
});

await test('WD 2.2 digest: every digest recorded in the credentials matches the hosted file, so the deployed PoC renders', async () => {
  const pinned = [
    [dpp.renderMethod[0].template, 'templates/DigitalProductPassport-1.0.0.html'],
    [dcc.renderMethod[0].template, 'templates/DigitalConformityCredential-1.0.0.html'],
    [dpp.credentialSubject.productImage, 'images/cathode-product.png'],
    [dpp.credentialSubject.relatedDocument[0], 'credentials/dcc-cathode.json']
  ];
  for (const [holder, path] of pinned) {
    const url = holder.id || holder.linkURL;
    assert.equal(url, BASE_URL + '/' + path);
    const check = await verifyDigestMultibase(read(path), holder.digestMultibase);
    assert.equal(check.ok, true, path + ': ' + check.reason);
  }
});

await test('WD 2.2 digest: a file changed by one byte fails the check, so a swapped template or image is blocked', async () => {
  const bytes = new Uint8Array(read('images/cathode-product.png'));
  bytes[bytes.length - 1] ^= 0x01;
  const check = await verifyDigestMultibase(bytes, dpp.credentialSubject.productImage.digestMultibase);
  assert.equal(check.ok, false);
  assert.match(check.reason, /digest mismatch/);
});

await test('WD 2.2 digest: a digest that is not multibase u or not SHA-2-256 is reported as such, not as a match', async () => {
  const bytes = read('images/cathode-product.png');
  assert.match((await verifyDigestMultibase(bytes, 'zQmerWC85Wg6wFl9znFCwYxApG270iEu5h6JqWAPdhyxz2dR')).reason, /multibase "u"/);
  assert.match((await verifyDigestMultibase(bytes, 'uEhQ' + 'A'.repeat(27))).reason, /SHA-2-256/);
});

// ---------------------------------------------------------------------------
// Render method and template reference (WD 2.2, 3.2.1)
// ---------------------------------------------------------------------------

await test('WD 3.2.1: the html SuiteRenderMethod is selected and other suites are ignored', () => {
  const credential = { renderMethod: [{ type: 'SuiteRenderMethod', renderSuite: 'summary' }, { type: 'SuiteRenderMethod', renderSuite: 'HTML' }, dpp.renderMethod[0]] };
  assert.equal(selectHtmlRenderMethod(credential), dpp.renderMethod[0]);
  assert.equal(selectHtmlRenderMethod({}), null);
});

await test('WD 2.2: a hosted template must carry a digest before the host fetches it; a data: URL template is used inline', () => {
  assert.equal(templateReference(dpp.renderMethod[0]).kind, 'fetch');
  assert.equal(templateReference({ template: { id: 'https://x.example/t.html' } }).kind, 'refuse');
  assert.equal(templateReference({ template: 'https://x.example/t.html' }).kind, 'refuse');
  const inline = templateReference({ template: 'data:text/html;base64,' + Buffer.from('<p>hi</p>').toString('base64') });
  assert.equal(inline.kind, 'inline');
  assert.equal(new TextDecoder().decode(inline.bytes), '<p>hi</p>');
});

await test('WD 3.2.1 renderProperty: only the listed values reach the template, at their original positions', () => {
  const filtered = filterByRenderProperty(dpp, ['/issuer/name', '/credentialSubject/relatedDocument/0/linkURL']);
  assert.equal(filtered.issuer.name, dpp.issuer.name);
  assert.equal(filtered.issuer.id, undefined);
  assert.equal(filtered.credentialSubject.relatedDocument[0].linkURL, DCC_URL);
  assert.equal(filtered.credentialSubject.name, undefined);
  assert.deepEqual(filtered['@context'], dpp['@context']);
});

// ---------------------------------------------------------------------------
// Wrapper (WD 2.2.2.2.2)
// ---------------------------------------------------------------------------

function dataBlock(wrapper, name) {
  const match = new RegExp('<script name="' + name + '" type="[^"]+">([\\s\\S]*?)</script>').exec(wrapper);
  assert.ok(match, 'no ' + name + ' block');
  return match[1];
}

await test('WD 2.2.2.2.2: the credential block parses back equal to the credential file, so the template sees exactly what the issuer wrote', () => {
  const wrapper = buildWrapper({ templateHtml: '<div></div>', credentialText: dppText, resources: {} });
  const block = dataBlock(wrapper, 'credential');
  assert.deepEqual(JSON.parse(block), JSON.parse(dppText));
  assert.equal(block.replace(/\\u003c/g, '<'), dppText);
});

await test('WD 2.2.2.2.2: the wrapper CSP is default-src data: \'unsafe-inline\' and comes before every script', () => {
  const wrapper = buildWrapper({ templateHtml: '<div></div>', credentialText: '{}', resources: {} });
  const meta = '<meta http-equiv="content-security-policy" content="' + WRAPPER_CSP + '">';
  assert.equal(WRAPPER_CSP, "default-src data: 'unsafe-inline'");
  assert.ok(wrapper.indexOf(meta) > 0 && wrapper.indexOf(meta) < wrapper.indexOf('<script'));
});

await test('Wrapper: "</script>" inside a credential value is escaped, so credential data cannot inject markup into the frame', () => {
  const hostile = { credentialSubject: { name: '</script><script>parent.alert(1)</script><!--' } };
  const text = JSON.stringify(hostile);
  const wrapper = buildWrapper({ templateHtml: '', credentialText: text, resources: { 'https://x.example/a.png': '</script>' } });
  assert.equal(wrapper.includes('</script><script>parent.alert'), false);
  assert.equal(wrapper.split('</script>').length - 1, 3);
  assert.deepEqual(JSON.parse(dataBlock(wrapper, 'credential')), hostile);
  assert.deepEqual(JSON.parse(dataBlock(wrapper, 'resources')), { 'https://x.example/a.png': '</script>' });
  assert.equal(escapeScriptData('"<"'), '"\\u003c"');
});

// ---------------------------------------------------------------------------
// Host-prefetched images plan (renderResource)
// ---------------------------------------------------------------------------

await test('Host-prefetched images: the DPP lists its product image in renderResource, so the host prefetches exactly that image', () => {
  const plan = planRenderResources(dpp, dpp.renderMethod[0]);
  assert.deepEqual(plan.declared, ['/credentialSubject/productImage']);
  assert.equal(plan.entries.length, 1);
  assert.equal(plan.entries[0].fetch, true);
  assert.equal(plan.entries[0].url, IMAGE_URL);
  assert.equal(plan.entries[0].mediaType, 'image/png');
});

await test('Host-prefetched images: an image listed in renderResource without a digest is not fetched', () => {
  const credential = clone(dpp);
  delete credential.credentialSubject.productImage.digestMultibase;
  const [entry] = planRenderResources(credential, credential.renderMethod[0]).entries;
  assert.equal(entry.fetch, false);
  assert.match(entry.reason, /no digestMultibase/);
});

await test('Host-prefetched images: an image with a digest that is not listed in renderResource is not fetched', () => {
  const credential = clone(dpp);
  delete credential.renderMethod[0].renderResource;
  assert.deepEqual(planRenderResources(credential, credential.renderMethod[0]).entries, []);
  credential.renderMethod[0].renderResource = ['/credentialSubject/relatedDocument/0'];
  const entries = planRenderResources(credential, credential.renderMethod[0]).entries;
  assert.equal(entries.some((e) => e.fetch), false);
});

await test('Host-prefetched images: a renderResource pointer outside renderProperty is ignored, so the template never receives an image the issuer did not expose', () => {
  const method = { ...dpp.renderMethod[0], renderProperty: ['/credentialSubject/name'] };
  const [entry] = planRenderResources(dpp, method).entries;
  assert.equal(entry.fetch, false);
  assert.match(entry.reason, /outside renderProperty/);
  assert.equal(withinRenderProperty('/credentialSubject/productImage', ['/credentialSubject']), true);
  assert.equal(withinRenderProperty('/credentialSubject/productImageX', ['/credentialSubject/productImage']), false);
});

await test('Host-prefetched images: non-https URLs, non-image media types and entries past the count limit are not fetched', () => {
  const credential = clone(dpp);
  const image = credential.credentialSubject.productImage;
  const method = { renderResource: ['/credentialSubject/productImage'] };
  image.linkURL = 'http://insecure.example/a.png';
  assert.equal(planRenderResources(credential, method).entries[0].fetch, false);
  image.linkURL = IMAGE_URL;
  image.mediaType = 'text/html';
  assert.equal(planRenderResources(credential, method).entries[0].fetch, false);
  image.mediaType = 'image/png';
  const many = { renderResource: Array(11).fill('/credentialSubject/productImage') };
  const entries = planRenderResources(credential, many, { maxCount: 10, maxBytes: 1 }).entries;
  assert.equal(entries.filter((e) => e.fetch).length, 10);
  assert.match(entries[10].reason, /limit of 10/);
});

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

await test('Config: production URLs map to the serving origin in one place, and the catalogue holds the two PoC credentials', () => {
  assert.equal(toFetchUrl(DCC_URL, 'http://localhost:3000'), 'http://localhost:3000/credentials/dcc-cathode.json');
  assert.equal(toFetchUrl(DCC_URL, BASE_URL), DCC_URL);
  assert.equal(toFetchUrl('https://other.example/x', 'http://localhost:3000'), 'https://other.example/x');
  assert.deepEqual(CATALOGUE.map((c) => c.url), [BASE_URL + '/credentials/dpp-cathode.json', DCC_URL]);
});

// ---------------------------------------------------------------------------
// Frame side: the real wrapper script and template in a DOM stand-in
// ---------------------------------------------------------------------------

class FakeNode {
  constructor(tagName) {
    this.tagName = tagName;
    this.childNodes = [];
    this.parentNode = null;
    this.className = '';
    this.ownText = '';
    this.listeners = {};
    const props = {};
    this.style = {
      setProperty: (name, value) => { props[name] = value; },
      getPropertyValue: (name) => props[name] || ''
    };
  }
  get textContent() {
    return this.ownText + this.childNodes.map((c) => c.textContent).join('');
  }
  set textContent(value) {
    this.ownText = String(value);
    this.childNodes = [];
  }
  get firstChild() {
    return this.childNodes[0] || null;
  }
  set innerHTML(markup) {
    this.content = { firstChild: new FakeNode('svg') };
  }
  appendChild(child) {
    if (child.parentNode) child.parentNode.childNodes = child.parentNode.childNodes.filter((c) => c !== child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }
  remove() {
    if (this.parentNode) this.parentNode.childNodes = this.parentNode.childNodes.filter((c) => c !== this);
    this.parentNode = null;
  }
  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }
}

function all(node, predicate, out = []) {
  if (predicate(node)) out.push(node);
  for (const child of node.childNodes || []) all(child, predicate, out);
  return out;
}

// Runs the wrapper script and the template's script against the wrapper the
// host builds. Returns the root element, the messages the wrapper posted on
// the port, and a click helper.
async function runFrame({ template, credentialText, resources, withWrapper = true }) {
  const wrapper = buildWrapper({ templateHtml: readText(template), credentialText, resources });
  const blocks = {
    credential: { textContent: dataBlock(wrapper, 'credential') },
    resources: { textContent: dataBlock(wrapper, 'resources') }
  };
  const rootNode = new FakeNode('div');
  const windowListeners = {};
  const document = {
    readyState: 'complete',
    createElement: (tag) => new FakeNode(tag),
    createTextNode: (text) => ({ textContent: String(text), childNodes: [] }),
    querySelector: (selector) => {
      const match = /^head > script\[name="(\w+)"\]$/.exec(selector);
      return match ? blocks[match[1]] || null : null;
    },
    getElementById: () => rootNode,
    addEventListener: () => {}
  };
  const context = { document, console };
  context.window = context;
  context.addEventListener = (type, fn) => { (windowListeners[type] = windowListeners[type] || []).push(fn); };
  context.removeEventListener = (type, fn) => { windowListeners[type] = (windowListeners[type] || []).filter((f) => f !== fn); };
  vm.createContext(context);

  const posted = [];
  if (withWrapper) vm.runInContext(WRAPPER_SCRIPT, context);
  else context.renderMethodReady = (err) => posted.push(err ? { error: { message: err.message } } : 'ready');
  const script = /<script>([\s\S]*)<\/script>/.exec(readText(template))[1];
  vm.runInContext(script, context);
  if (withWrapper) {
    const port = { postMessage: (message) => posted.push(message) };
    for (const fn of windowListeners.message || []) fn({ data: 'start', ports: [port] });
  }
  await new Promise((r) => setTimeout(r, 0));

  const anchors = all(rootNode, (n) => n.tagName === 'a');
  async function click(anchor) {
    let prevented = false;
    for (const fn of anchor.listeners.click || []) fn({ preventDefault: () => { prevented = true; } });
    await new Promise((r) => setTimeout(r, 0));
    return prevented;
  }
  return { rootNode, posted, anchors, click };
}

for (const [label, template, credential, text] of [
  ['DPP', 'templates/DigitalProductPassport-1.0.0.html', dpp, dppText],
  ['DCC', 'templates/DigitalConformityCredential-1.0.0.html', dcc, dccText]
]) {
  await test(label + ' template: renders and the wrapper posts "ready" on the port (WD 2.2.2.2.3)', async () => {
    const frame = await runFrame({ template, credentialText: text, resources: {} });
    assert.deepEqual(frame.posted, ['ready']);
    assert.ok(frame.rootNode.textContent.includes(credential.credentialSubject.name));
  });

  await test(label + ' template, host-mediated links: every credential-value link sends the pointer of exactly its own URL, so the host opens what the reader saw', async () => {
    const frame = await runFrame({ template, credentialText: text, resources: {} });
    const linked = frame.anchors.filter((a) => (a.listeners.click || []).length);
    assert.ok(linked.length >= 5, 'expected several credential links, found ' + linked.length);
    for (const anchor of linked) {
      frame.posted.length = 0;
      const prevented = await frame.click(anchor);
      assert.equal(prevented, true, 'click on ' + anchor.href + ' was not prevented');
      assert.equal(frame.posted.length, 1);
      const message = frame.posted[0];
      assert.equal(message.type, 'open-link');
      assert.equal(resolvePointer(credential, message.pointer).value, anchor.href, message.pointer);
      const decision = decideOpenLink(credential, message);
      assert.equal(decision.action, 'open', message.pointer + ': ' + decision.reason);
      assert.equal(decision.url, anchor.href);
    }
    // The only anchor without a pointer is the template's own footer link.
    const unlinked = frame.anchors.filter((a) => !(a.listeners.click || []).length).map((a) => a.href);
    assert.deepEqual(unlinked, label === 'DPP' ? ['https://untp.unece.org'] : []);
  });

  await test(label + ' template, host-mediated links: without renderMethodOpenLink a click is left to the anchor, so strict renderers degrade gracefully', async () => {
    const frame = await runFrame({ template, credentialText: text, resources: {}, withWrapper: false });
    const linked = frame.anchors.filter((a) => (a.listeners.click || []).length);
    assert.ok(linked.length > 0);
    assert.equal(await frame.click(linked[0]), false);
    assert.deepEqual(frame.posted, ['ready']);
  });
}

await test('DPP template, host-mediated links: the Related Documents section links the DCC, so the reader can click through to it', async () => {
  const frame = await runFrame({ template: 'templates/DigitalProductPassport-1.0.0.html', credentialText: dppText, resources: {} });
  assert.ok(frame.rootNode.textContent.includes('Related Documents'));
  const anchor = frame.anchors.find((a) => a.href === DCC_URL);
  assert.ok(anchor, 'no anchor to the DCC');
  frame.posted.length = 0;
  await frame.click(anchor);
  // Messages come from the vm realm, so compare them as plain JSON.
  assert.deepEqual(JSON.parse(JSON.stringify(frame.posted)), [{ type: 'open-link', pointer: '/credentialSubject/relatedDocument/0/linkURL' }]);
});

function headerImage(frame) {
  const header = all(frame.rootNode, (n) => n.className === 'header-image')[0];
  return header.style.getPropertyValue('--image-src');
}

await test('DPP template, host-prefetched images: a verified image in the resources block becomes the header image', async () => {
  const dataUrl = 'data:image/png;base64,' + read('images/cathode-product.png').toString('base64');
  const frame = await runFrame({ template: 'templates/DigitalProductPassport-1.0.0.html', credentialText: dppText, resources: { [IMAGE_URL]: dataUrl } });
  assert.equal(headerImage(frame), 'url("' + dataUrl + '")');
});

await test('DPP template, host-prefetched images: with no resource for the image (digest failed or not listed) the header keeps its gradient', async () => {
  const frame = await runFrame({ template: 'templates/DigitalProductPassport-1.0.0.html', credentialText: dppText, resources: {} });
  assert.equal(headerImage(frame), '');
  const hostile = await runFrame({ template: 'templates/DigitalProductPassport-1.0.0.html', credentialText: dppText, resources: { [IMAGE_URL]: 'javascript:alert(1)' } });
  assert.equal(headerImage(hostile), '');
});

await test('DPP template: an embedded data: image still shows without the host (behaviour kept from the source template)', async () => {
  const credential = clone(dpp);
  const dataUrl = 'data:image/png;base64,' + read('images/cathode-product.png').toString('base64');
  credential.credentialSubject.productImage.linkURL = dataUrl;
  const frame = await runFrame({ template: 'templates/DigitalProductPassport-1.0.0.html', credentialText: JSON.stringify(credential), resources: {} });
  assert.equal(headerImage(frame), 'url("' + dataUrl + '")');
});

await test('DCC template: the embedded trustmark image still shows (behaviour kept from the source template)', async () => {
  const frame = await runFrame({ template: 'templates/DigitalConformityCredential-1.0.0.html', credentialText: dccText, resources: {} });
  const images = all(frame.rootNode, (n) => n.tagName === 'img');
  assert.ok(images.some((img) => img.src.startsWith('data:image/png;base64,iVBOR')));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
