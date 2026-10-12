// The host page controller: fetches credentials, templates and images, builds
// the wrapper, runs the sandboxed frame and handles its messages. The rules
// themselves live in core.js. Section numbers refer to the W3C Working Draft
// of 6 October 2026 (WD); host-mediated links and host-prefetched images are
// this PoC's extensions.

import { CATALOGUE, toFetchUrl } from './config.js';
import {
  RESOURCE_LIMITS,
  acceptCredentialBytes,
  buildVerifyUrl,
  buildWrapper,
  decideOpenLink,
  filterByRenderProperty,
  imageDataUrl,
  openFeatures,
  parseVerifyParams,
  planRenderResources,
  selectHtmlRenderMethod,
  templateReference,
  verifyDigestMultibase
} from './core.js';

const picker = document.getElementById('picker');
const viewerTitle = document.getElementById('viewer-title');
const renderError = document.getElementById('render-error');
const viewer = document.getElementById('viewer');
const activity = document.getElementById('activity');
const confirmDialog = document.getElementById('confirm-link');
const confirmName = document.getElementById('confirm-name');
const confirmUrl = document.getElementById('confirm-url');
const confirmNote = document.getElementById('confirm-note');
const tabs = ['tab-rendered', 'tab-json', 'tab-template'].map((id) => document.getElementById(id));
const credentialJson = document.getElementById('credential-json');
const jsonNote = document.getElementById('json-note');
const copyButton = document.getElementById('copy-json');
const copyStatus = document.getElementById('copy-status');
const rawLink = document.getElementById('raw-link');
const templateUrl = document.getElementById('template-url');
const templateDigest = document.getElementById('template-digest');
const templateCheck = document.getElementById('template-check');
const templateSource = document.getElementById('template-source');
const templateNote = document.getElementById('template-note');
const templateCopy = document.getElementById('copy-template');
const templateCopyStatus = document.getElementById('template-copy-status');
const templateRawLink = document.getElementById('template-raw-link');
const showTemplateButton = document.getElementById('show-template');
const showWrapperButton = document.getElementById('show-wrapper');

const READY_TIMEOUT_MS = 15000;

// The credential on screen. Each page shows one credential, named by its
// verify URL; moving between credentials happens in browser tabs and the
// browser's own history.
let current = null;
// Increases with every render, so messages and timers from a replaced frame
// are recognised as stale.
let renderSeq = 0;
let activePort = null;
// Host-prefetched images: verified bytes by digestMultibase, kept for this
// page session.
const imageCache = new Map();

// ---------------------------------------------------------------------------
// Activity panel
// ---------------------------------------------------------------------------

// The source of each activity entry, as the panel labels it.
const SOURCES = {
  wd: 'WD',
  host: 'Host',
  links: 'Host-mediated links',
  images: 'Host-prefetched images'
};

function log(source, status, message) {
  const item = document.createElement('li');
  const label = document.createElement('span');
  label.className = 'tag tag-' + source;
  label.textContent = SOURCES[source];
  const state = document.createElement('span');
  state.className = 'status status-' + status;
  state.textContent = status;
  const text = document.createElement('span');
  text.className = 'message';
  text.textContent = message;
  item.append(label, state, text);
  activity.appendChild(item);
  activity.scrollTop = activity.scrollHeight;
}

function logSeparator(text) {
  const item = document.createElement('li');
  item.className = 'separator';
  item.textContent = text;
  activity.appendChild(item);
  activity.scrollTop = activity.scrollHeight;
}

function showError(message) {
  renderError.textContent = message;
  renderError.hidden = false;
}

function clearError() {
  renderError.textContent = '';
  renderError.hidden = true;
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

// Fetches a URL (mapped to this origin when it is under BASE_URL) without
// cookies or a referrer, following redirects. Refuses bodies over maxBytes
// when given. Returns the bytes and the final URL after any redirects.
async function fetchResource(url, { maxBytes, accept } = {}) {
  const init = { credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'follow' };
  if (accept) init.headers = { Accept: accept };
  const response = await fetch(toFetchUrl(url), init);
  if (!response.ok) throw new Error('HTTP ' + response.status + ' for ' + url);
  const length = Number(response.headers.get('content-length'));
  if (maxBytes && length > maxBytes) throw new Error('larger than ' + maxBytes + ' bytes (' + length + ')');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (maxBytes && bytes.length > maxBytes) throw new Error('larger than ' + maxBytes + ' bytes (' + bytes.length + ')');
  return { bytes, finalUrl: response.url || url };
}

async function fetchBytes(url, maxBytes) {
  return (await fetchResource(url, { maxBytes })).bytes;
}

// ---------------------------------------------------------------------------
// The verify entry point: ?uri=...&digestMultibase=...&decryptionKey=...
// ---------------------------------------------------------------------------

const CREDENTIAL_ACCEPT = 'application/vc, application/ld+json;q=0.9, application/json;q=0.8';

// Reads the verify parameters from the page address, fetches the credential,
// checks digestMultibase when given and renders it through the normal path.
async function loadFromQuery() {
  const request = parseVerifyParams(location.search);
  updatePicker(request && request.uri);
  if (!request) {
    viewer.replaceChildren(placeholder('Choose a credential above. The activity panel shows each step of the render.'));
    return;
  }
  logSeparator('Verify request ' + location.pathname + location.search);
  if (request.error) {
    log('host', 'refused', 'Verify parameters refused: ' + request.error + '.');
    failLoad('The page address does not name a usable credential: ' + request.error + '.');
    return;
  }
  log('host', 'info', 'uri names ' + request.uri +
    (request.digestMultibase ? ', digestMultibase ' + request.digestMultibase : ', with no digestMultibase') + '.');
  if (request.decryptionKey) {
    log('host', 'refused', 'decryptionKey given: encrypted credentials are out of scope for this proof of concept. Nothing was fetched or decrypted.');
    failLoad('This link is for an encrypted credential (it carries a decryptionKey). Encrypted credentials are out of scope for this proof of concept, so it was not fetched or decrypted.');
    return;
  }
  let fetched;
  try {
    fetched = await fetchResource(request.uri, { accept: CREDENTIAL_ACCEPT });
  } catch (err) {
    const cause = err instanceof TypeError
      ? 'the request did not complete. The server may not allow cross-origin requests (CORS), or the network or address may be unavailable'
      : err.message;
    log('host', 'error', 'Could not fetch ' + request.uri + ': ' + cause + '.');
    failLoad('Could not load the credential from ' + request.uri + ': ' + cause + '.');
    return;
  }
  log('host', 'ok', 'Fetched ' + fetched.bytes.length + ' bytes' +
    (fetched.finalUrl !== toFetchUrl(request.uri) ? ', redirected to ' + fetched.finalUrl : ' from ' + fetched.finalUrl) + '.');
  const accepted = await acceptCredentialBytes(fetched.bytes, request.digestMultibase);
  if (!accepted.ok) {
    log('host', 'refused', 'Credential ' + request.uri + ' refused: ' + accepted.reason + '.');
    failLoad('The credential from ' + request.uri + ' was refused: ' + accepted.reason + '.');
    return;
  }
  log('host', accepted.digest ? 'ok' : 'info', accepted.digest
    ? 'Credential digest matches digestMultibase ' + request.digestMultibase + '.'
    : 'No digestMultibase given, so the credential is loaded without a digest check.');
  current = { url: request.uri, finalUrl: fetched.finalUrl, text: accepted.text, credential: accepted.credential };
  viewerTitle.textContent = typeof current.credential.name === 'string' ? current.credential.name : current.url;
  await render(current);
}

function failLoad(message) {
  viewerTitle.textContent = 'No credential rendered.';
  viewer.replaceChildren();
  showError(message);
}

function updatePicker(uri) {
  for (const button of picker.querySelectorAll('button')) {
    button.setAttribute('aria-pressed', String(button.dataset.url === uri));
  }
}

// ---------------------------------------------------------------------------
// Rendering (WD 3.2.1, 3.2.2)
// ---------------------------------------------------------------------------

async function render(entry) {
  const seq = ++renderSeq;
  if (activePort) {
    activePort.close();
    activePort = null;
  }
  clearError();
  viewer.replaceChildren(placeholder('Preparing the render...'));
  logSeparator('Rendering ' + entry.url);
  log('host', 'info', 'Unsigned sample credential: signature verification is out of scope for this PoC.');

  const { credential, text } = entry;
  showCredentialJson(entry, text, false);
  setTemplateView(seq, null);
  const method = selectHtmlRenderMethod(credential);
  if (!method) {
    setTemplateView(seq, { check: 'No html render method, so there is no template.' });
    return fail(seq, 'wd', 'The credential has no renderMethod with type SuiteRenderMethod and renderSuite "html".');
  }
  log('wd', 'ok', 'Selected render method "' + (method.name || 'html') + '" (SuiteRenderMethod, renderSuite html).');

  // The template (WD 2.2, 2.2.2.2: preload and check before injecting).
  const reference = templateReference(method);
  let templateBytes;
  if (reference.kind === 'refuse') {
    setTemplateView(seq, { check: 'Refused: ' + reference.reason });
    return fail(seq, 'wd', 'Template refused: ' + reference.reason);
  }
  if (reference.kind === 'fetch') {
    try {
      templateBytes = await fetchBytes(reference.url);
    } catch (err) {
      return fail(seq, 'wd', 'Could not fetch template ' + reference.url + ': ' + err.message);
    }
    log('wd', 'info', 'Fetched template ' + reference.url + ' (' + templateBytes.length + ' bytes).');
  } else {
    templateBytes = reference.bytes;
    log('wd', 'info', 'Template is embedded as a data: URL (' + templateBytes.length + ' bytes).');
  }
  if (reference.digestMultibase) {
    const check = await verifyDigestMultibase(templateBytes, reference.digestMultibase);
    if (!check.ok) {
      setTemplateView(seq, { reference, check: 'Does not match, so the template was blocked and not injected: ' + check.reason });
      return fail(seq, 'wd', 'Template blocked: ' + check.reason);
    }
    log('wd', 'ok', 'Template digest matches digestMultibase ' + reference.digestMultibase + '.');
  }
  if (seq !== renderSeq) return;
  const templateHtml = new TextDecoder().decode(templateBytes);
  setTemplateView(seq, {
    reference,
    html: templateHtml,
    check: reference.digestMultibase ? 'Matches.' : 'No digestMultibase given, so nothing to check.'
  });

  // renderProperty filtering (WD 3.2.1). Without it the data block holds the
  // credential file's own text, unmodified.
  let credentialText = text;
  if (method.renderProperty !== undefined) {
    credentialText = JSON.stringify(filterByRenderProperty(credential, method.renderProperty));
    showCredentialJson(entry, credentialText, true);
    log('wd', 'info', 'Filtered the credential to renderProperty ' + JSON.stringify(method.renderProperty) + ' (simplified selectJsonLd).');
  } else {
    log('wd', 'info', 'No renderProperty: the template receives the whole credential, unmodified.');
  }

  // PoC extension: host-prefetched images, only those the issuer lists in
  // renderResource.
  const resources = await prefetchImages(credential, method, seq);
  if (seq !== renderSeq) return;

  const wrapper = buildWrapper({ templateHtml, credentialText, resources });
  if (templateView) templateView.wrapper = wrapper;
  showTemplateSource();
  startFrame(wrapper, method, credential, seq);
}

function placeholder(text) {
  const p = document.createElement('p');
  p.className = 'placeholder';
  p.textContent = text;
  return p;
}

function fail(seq, source, message) {
  if (seq !== renderSeq) return;
  log(source, 'refused', message);
  viewer.replaceChildren();
  showError('Rendering failed: ' + message);
}

async function prefetchImages(credential, method, seq) {
  const resources = {};
  const plan = planRenderResources(credential, method);
  if (!plan.entries.length) {
    log('images', 'info', 'The render method lists no renderResource, so no images are prefetched.');
    return resources;
  }
  log('images', 'info', 'renderResource declares ' + JSON.stringify(plan.declared) + ' (limits: ' + RESOURCE_LIMITS.maxCount + ' resources, ' + RESOURCE_LIMITS.maxBytes + ' bytes each).');
  for (const entry of plan.entries) {
    if (seq !== renderSeq) return resources;
    if (!entry.fetch) {
      log('images', 'refused', entry.pointer + ': not prefetched, ' + entry.reason + '.');
      continue;
    }
    let bytes = imageCache.get(entry.digestMultibase);
    if (bytes) {
      log('images', 'ok', entry.pointer + ': ' + entry.url + ' already verified in this session (digest ' + entry.digestMultibase + ').');
    } else {
      try {
        bytes = await fetchBytes(entry.url, RESOURCE_LIMITS.maxBytes);
      } catch (err) {
        log('images', 'error', entry.pointer + ': could not fetch ' + entry.url + ': ' + err.message + '. The template falls back.');
        continue;
      }
      const check = await verifyDigestMultibase(bytes, entry.digestMultibase);
      if (!check.ok) {
        log('images', 'refused', entry.pointer + ': ' + entry.url + ' blocked, ' + check.reason + '. The template falls back.');
        continue;
      }
      imageCache.set(entry.digestMultibase, bytes);
      log('images', 'ok', entry.pointer + ': fetched ' + entry.url + ' (' + bytes.length + ' bytes), digest matches ' + entry.digestMultibase + '.');
    }
    resources[entry.url] = imageDataUrl(entry.mediaType, bytes);
  }
  log('images', 'info', 'Passing ' + Object.keys(resources).length + ' image(s) in <script name="resources">, keyed by the URL in the credential.');
  return resources;
}

// Creates the sandboxed frame, sets up the MessageChannel on load (WD
// 2.2.2.2.3, Example 11) and shows the frame on 'ready'. Unlike Example 11 the
// port stays open after 'ready' for open-link messages (host-mediated links),
// and only an error-shaped message rejects the render (WD 3.2.1).
function startFrame(wrapper, method, credential, seq) {
  const frame = document.createElement('iframe');
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.title = 'Rendered credential';
  frame.hidden = true;
  const style = method.outputPreference && method.outputPreference.style;
  if (style && typeof style.width === 'string') frame.style.width = style.width;
  if (style && typeof style.height === 'string') frame.style.height = style.height;

  let settled = false;
  let started = false;
  const settle = (ok, message) => {
    if (settled || seq !== renderSeq) return;
    settled = true;
    if (ok) {
      frame.hidden = false;
      viewer.querySelector('.placeholder')?.remove();
      log('wd', 'ok', 'Template called renderMethodReady(): showing the frame.');
    } else {
      viewer.replaceChildren();
      showError('Rendering failed: ' + message);
      log('wd', 'error', 'Template reported an error: ' + message);
    }
  };

  frame.addEventListener('load', () => {
    if (started || seq !== renderSeq) return;
    started = true;
    const channel = new MessageChannel();
    channel.port1.start();
    activePort = channel.port1;
    channel.port1.onmessage = (event) => {
      if (seq !== renderSeq) return;
      const data = event.data;
      if (data === 'ready') return settle(true);
      if (data && typeof data === 'object' && data.error) return settle(false, String(data.error.message));
      if (data && typeof data === 'object' && data.type === 'open-link') return handleOpenLink(credential, data);
      log('host', 'ignored', 'Ignored a message from the frame that is neither ready, error nor open-link.');
    };
    frame.contentWindow.postMessage('start', '*', [channel.port2]);
    log('wd', 'info', 'Frame loaded: sent "start" with a MessagePort.');
  });

  frame.srcdoc = wrapper;
  log('wd', 'info', 'Injected the wrapper into iframe srcdoc (sandbox="allow-scripts", wrapper CSP default-src data: \'unsafe-inline\').');
  viewer.replaceChildren(placeholder('Waiting for the template...'), frame);

  setTimeout(() => {
    if (!settled && seq === renderSeq) {
      log('wd', 'error', 'No ready or error message after ' + READY_TIMEOUT_MS / 1000 + ' seconds.');
    }
  }, READY_TIMEOUT_MS);
}

// ---------------------------------------------------------------------------
// PoC extension: host-mediated links
// ---------------------------------------------------------------------------

async function handleOpenLink(credential, message) {
  const decision = decideOpenLink(credential, message);
  if (decision.action === 'ignore') {
    log('links', 'ignored', 'Ignored an open-link message: ' + decision.reason + '.');
    return;
  }
  if (decision.action === 'refuse') {
    log('links', 'refused', 'open-link ' + decision.pointer + ' refused: ' + decision.reason + '.');
    return;
  }
  log('links', 'info', 'open-link ' + decision.pointer + ' resolves to ' + decision.url + '.');
  // Every link waits for the reader's confirmation, then opens in a new tab.
  confirmLink(toFetchUrl(decision.url), decision.name);
}

// The host's own dialog, shown for every link. On "Open in new tab" the PoC's
// own pages (a verify URL, for example) open as the same application, and
// every other address opens with noopener and noreferrer.
function confirmLink(target, name) {
  if (confirmDialog.open) {
    log('links', 'ignored', 'A dialog is already open; ignored the request to open ' + target + '.');
    return;
  }
  const features = openFeatures(target, location.origin);
  confirmName.textContent = name || '';
  confirmName.hidden = !name;
  confirmUrl.textContent = target;
  confirmNote.textContent = features
    ? 'It opens in a new tab, without a referrer and without access to this page.'
    : 'This is a page of this proof of concept. It opens in a new tab.';
  confirmDialog.returnValue = '';
  confirmDialog.onclose = () => {
    if (confirmDialog.returnValue !== 'open') {
      log('links', 'info', 'Reader cancelled opening ' + target + '.');
      return;
    }
    window.open(target, '_blank', features);
    log('links', 'ok', 'Reader confirmed: opened ' + target + ' in a new tab' + (features ? ' with ' + features : '') + '.');
  };
  log('links', 'info', 'Asking the reader to confirm before opening ' + target + '.');
  confirmDialog.showModal();
}

// ---------------------------------------------------------------------------
// Credential JSON view
// ---------------------------------------------------------------------------

// Shows the credential JSON the host passes to the frame (credentialText),
// pretty-printed. It reads the host's copy and never touches the frame.
function showCredentialJson(entry, credentialText, filtered) {
  if (entry !== current) return;
  let pretty;
  try {
    pretty = JSON.stringify(JSON.parse(credentialText), null, 2);
  } catch {
    pretty = credentialText;
  }
  const code = document.createElement('code');
  code.textContent = pretty;
  credentialJson.replaceChildren(code);
  jsonNote.hidden = !filtered;
  jsonNote.textContent = filtered
    ? 'Filtered by renderProperty: this is what the template receives. The raw file holds the full credential.'
    : '';
  rawLink.href = toFetchUrl(entry.url);
  rawLink.textContent = 'Raw file: ' + entry.url;
  rawLink.hidden = false;
  copyButton.disabled = false;
  copyStatus.textContent = '';
}

// Copies a pre block's text, or selects it when the clipboard is unavailable.
async function copyText(pre, status, what) {
  try {
    await navigator.clipboard.writeText(pre.textContent);
    status.textContent = 'Copied.';
  } catch {
    const range = document.createRange();
    range.selectNodeContents(pre);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    status.textContent = 'Copy is not available here; the ' + what + ' is selected instead.';
  }
}

copyButton.addEventListener('click', () => copyText(credentialJson, copyStatus, 'JSON'));

// ---------------------------------------------------------------------------
// Template HTML view
// ---------------------------------------------------------------------------

// What the host knows about the current render's template: the reference, the
// exact text it injects (once checked), the digest result and, once built,
// the wrapper it set as srcdoc. Filled in by render(); read only here.
let templateView = null;
let showWrapper = false;

function setTemplateView(seq, view) {
  if (seq !== renderSeq) return;
  templateView = view;
  const reference = view && view.reference;
  if (!reference) {
    templateUrl.textContent = view ? 'Not available.' : 'Waiting for the render.';
    templateDigest.textContent = 'None.';
  } else if (reference.kind === 'fetch') {
    templateUrl.textContent = reference.url;
    templateDigest.textContent = reference.digestMultibase;
  } else {
    templateUrl.textContent = 'Embedded in the credential as a data: URL (decoded below).';
    templateDigest.textContent = reference.digestMultibase || 'None given.';
  }
  templateCheck.textContent = view ? view.check : 'Waiting for the render.';
  if (reference && reference.kind === 'fetch') {
    templateRawLink.href = toFetchUrl(reference.url);
    templateRawLink.hidden = false;
  } else {
    templateRawLink.hidden = true;
  }
  showTemplateSource();
}

function showTemplateSource() {
  showTemplateButton.setAttribute('aria-pressed', String(!showWrapper));
  showWrapperButton.setAttribute('aria-pressed', String(showWrapper));
  const view = templateView;
  let text;
  let note = '';
  if (showWrapper) {
    text = view && view.wrapper ? view.wrapper : 'The wrapper has not been built for this render.';
    note = 'Host-generated: the wrapper document the host built and set as the frame\'s srcdoc, holding the credential and resources data blocks, the wrapper script and the template.';
  } else {
    text = view && typeof view.html === 'string' ? view.html : 'No checked template for this render.';
    if (view && view.reference && view.reference.kind === 'inline') {
      note = 'The template came inline as a data: URL; this is its decoded text.';
    } else if (view && typeof view.html === 'string') {
      note = 'The template text exactly as fetched and checked, the same text the host injects into the wrapper.';
    }
  }
  const code = document.createElement('code');
  code.textContent = text;
  templateSource.replaceChildren(code);
  templateSource.setAttribute('aria-label', showWrapper ? 'Full wrapper (host-generated)' : 'Template HTML');
  templateNote.textContent = note;
  templateNote.hidden = !note;
  templateCopy.disabled = !(view && (showWrapper ? view.wrapper : typeof view.html === 'string'));
  templateCopyStatus.textContent = '';
}

showTemplateButton.addEventListener('click', () => {
  showWrapper = false;
  showTemplateSource();
});
showWrapperButton.addEventListener('click', () => {
  showWrapper = true;
  showTemplateSource();
});
templateCopy.addEventListener('click', () => copyText(templateSource, templateCopyStatus, showWrapper ? 'wrapper' : 'template'));

// Tabs follow the WAI-ARIA tabs pattern: one tab in the Tab order, arrow keys,
// Home and End move between tabs, and activation shows its panel.
function selectTab(tab, focus) {
  for (const t of tabs) {
    const selected = t === tab;
    t.setAttribute('aria-selected', String(selected));
    t.tabIndex = selected ? 0 : -1;
    document.getElementById(t.getAttribute('aria-controls')).hidden = !selected;
  }
  if (focus) tab.focus();
}

for (const tab of tabs) {
  tab.addEventListener('click', () => selectTab(tab, false));
  tab.addEventListener('keydown', (event) => {
    const i = tabs.indexOf(tab);
    let next = null;
    if (event.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
    else if (event.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
    else if (event.key === 'Home') next = tabs[0];
    else if (event.key === 'End') next = tabs[tabs.length - 1];
    if (next) {
      event.preventDefault();
      selectTab(next, true);
    }
  });
}

// ---------------------------------------------------------------------------
// Page set-up
// ---------------------------------------------------------------------------

for (const entry of CATALOGUE) {
  const button = document.createElement('button');
  button.type = 'button';
  button.dataset.url = entry.url;
  button.setAttribute('aria-pressed', 'false');
  const label = document.createElement('span');
  label.textContent = entry.label;
  const detail = document.createElement('span');
  detail.className = 'detail';
  detail.textContent = entry.detail;
  button.append(label, detail);
  // Each choice navigates to the credential's verify URL, so every rendered
  // credential has a shareable address and the browser's back button works.
  button.addEventListener('click', () => {
    location.href = buildVerifyUrl(location.origin, entry.url);
  });
  picker.appendChild(button);
}

document.getElementById('clear-activity').addEventListener('click', () => {
  activity.replaceChildren();
});

loadFromQuery();
