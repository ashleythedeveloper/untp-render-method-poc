// The host page controller: fetches credentials, templates and images, builds
// the wrapper, runs the sandboxed frame and handles its messages. The rules
// themselves live in core.js. Section numbers refer to the W3C Working Draft
// of 6 October 2026 (WD); host-mediated links and host-prefetched images are
// this PoC's extensions.

import { CATALOGUE, isCatalogueCredential, toFetchUrl } from './config.js';
import {
  RESOURCE_LIMITS,
  buildWrapper,
  decideOpenLink,
  filterByRenderProperty,
  imageDataUrl,
  planRenderResources,
  selectHtmlRenderMethod,
  templateReference,
  verifyDigestMultibase
} from './core.js';

const picker = document.getElementById('picker');
const backButton = document.getElementById('back');
const viewerTitle = document.getElementById('viewer-title');
const renderError = document.getElementById('render-error');
const viewer = document.getElementById('viewer');
const activity = document.getElementById('activity');
const confirmDialog = document.getElementById('confirm-link');
const confirmUrl = document.getElementById('confirm-url');
const tabs = [document.getElementById('tab-rendered'), document.getElementById('tab-json')];
const credentialJson = document.getElementById('credential-json');
const jsonNote = document.getElementById('json-note');
const copyButton = document.getElementById('copy-json');
const copyStatus = document.getElementById('copy-status');
const rawLink = document.getElementById('raw-link');

const READY_TIMEOUT_MS = 15000;

// The credential on screen, and the ones behind it for the Back control.
let current = null;
const history = [];
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
// cookies or a referrer. Refuses bodies over maxBytes when given.
async function fetchBytes(url, maxBytes) {
  const response = await fetch(toFetchUrl(url), { credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!response.ok) throw new Error('HTTP ' + response.status + ' for ' + url);
  const length = Number(response.headers.get('content-length'));
  if (maxBytes && length > maxBytes) throw new Error('larger than ' + maxBytes + ' bytes (' + length + ')');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (maxBytes && bytes.length > maxBytes) throw new Error('larger than ' + maxBytes + ' bytes (' + bytes.length + ')');
  return bytes;
}

// ---------------------------------------------------------------------------
// Loading a credential
// ---------------------------------------------------------------------------

// Loads a credential by URL and renders it. expectedDigest comes from the
// host-mediated link that named it, when the link carries one.
async function openCredential(url, { expectedDigest, fromLink } = {}) {
  let bytes;
  try {
    bytes = await fetchBytes(url);
  } catch (err) {
    log(fromLink ? 'links' : 'host', 'error', 'Could not fetch credential ' + url + ': ' + err.message);
    return false;
  }
  if (fromLink) {
    if (expectedDigest) {
      const check = await verifyDigestMultibase(bytes, expectedDigest);
      if (!check.ok) {
        log('links', 'refused', 'Linked credential ' + url + ' blocked: ' + check.reason);
        return false;
      }
      log('links', 'ok', 'Linked credential digest matches the link\'s digestMultibase (' + expectedDigest + ').');
    } else {
      log('links', 'info', 'The link carries no digestMultibase, so the linked credential is loaded without a digest check.');
    }
  }
  const text = new TextDecoder().decode(bytes);
  let credential;
  try {
    credential = JSON.parse(text);
  } catch (err) {
    log('host', 'error', 'Credential ' + url + ' is not JSON: ' + err.message);
    return false;
  }
  if (fromLink && current) history.push(current);
  current = { url, text, credential };
  updateChrome();
  await render(current);
  return true;
}

function updateChrome() {
  backButton.disabled = history.length === 0;
  const name = current && typeof current.credential.name === 'string' ? current.credential.name : current ? current.url : '';
  viewerTitle.textContent = name || 'Choose a credential to render.';
  for (const button of picker.querySelectorAll('button')) {
    button.setAttribute('aria-pressed', String(Boolean(current) && button.dataset.url === current.url));
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
  const method = selectHtmlRenderMethod(credential);
  if (!method) return fail(seq, 'wd', 'The credential has no renderMethod with type SuiteRenderMethod and renderSuite "html".');
  log('wd', 'ok', 'Selected render method "' + (method.name || 'html') + '" (SuiteRenderMethod, renderSuite html).');

  // The template (WD 2.2, 2.2.2.2: preload and check before injecting).
  const reference = templateReference(method);
  let templateBytes;
  if (reference.kind === 'refuse') return fail(seq, 'wd', 'Template refused: ' + reference.reason);
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
    if (!check.ok) return fail(seq, 'wd', 'Template blocked: ' + check.reason);
    log('wd', 'ok', 'Template digest matches digestMultibase ' + reference.digestMultibase + '.');
  }
  if (seq !== renderSeq) return;
  const templateHtml = new TextDecoder().decode(templateBytes);

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
  if (isCatalogueCredential(decision.url)) {
    log('links', 'info', 'This is one of the PoC\'s own credentials: rendering it here.');
    await openCredential(decision.url, { expectedDigest: decision.digestMultibase, fromLink: true });
    return;
  }
  confirmExternal(decision.url);
}

function confirmExternal(url) {
  if (confirmDialog.open) {
    log('links', 'ignored', 'A confirmation is already open; ignored the request to open ' + url + '.');
    return;
  }
  confirmUrl.textContent = url;
  confirmDialog.returnValue = '';
  confirmDialog.onclose = () => {
    if (confirmDialog.returnValue === 'open') {
      window.open(url, '_blank', 'noopener,noreferrer');
      log('links', 'ok', 'User confirmed: opened ' + url + ' in a new tab.');
    } else {
      log('links', 'info', 'User cancelled opening ' + url + '.');
    }
  };
  log('links', 'info', 'Not a PoC credential: asking the user to confirm the external link.');
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

copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(credentialJson.textContent);
    copyStatus.textContent = 'Copied.';
  } catch {
    const range = document.createRange();
    range.selectNodeContents(credentialJson);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    copyStatus.textContent = 'Copy is not available here; the JSON is selected instead.';
  }
});

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
  button.addEventListener('click', () => {
    history.length = 0;
    openCredential(entry.url);
  });
  picker.appendChild(button);
}

backButton.addEventListener('click', () => {
  const previous = history.pop();
  if (!previous) return;
  current = previous;
  updateChrome();
  render(current);
});

document.getElementById('clear-activity').addEventListener('click', () => {
  activity.replaceChildren();
});

viewer.replaceChildren(placeholder('Choose a credential above. The activity panel shows each step of the render.'));
