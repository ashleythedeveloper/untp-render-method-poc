# UNTP render method proof of concept

A static web page that renders [UN Transparency Protocol](https://untp.unece.org) (UNTP) credentials with the W3C `html` render suite, as specified in [Verifiable Credential Rendering Methods v1.0, W3C Working Draft of 6 October 2026](https://www.w3.org/TR/2026/WD-vc-render-method-20261006/) (the WD below). It adds two extensions, named the same way throughout the code and the page:

- **Host-mediated links.** Clicking a link in a rendered credential sends the host page a JSON Pointer into the credential. The host resolves the pointer itself and opens the address in a new tab: the PoC's own pages (such as the verify URL of the linked Digital Conformity Credential) directly, anything else after the reader confirms. The template frame never navigates.
- **Host-prefetched images.** Before rendering, the host fetches the images the issuer lists in the render method's `renderResource` property, checks each one against its `digestMultibase`, and passes them to the template in a separate data block keyed by the original URL. The credential the template receives is the issuer's credential, unmodified.

An activity panel beside the rendered credential lists every step: the template fetch and digest check, each declared image and what happened to it, and each link request and how the host handled it.

The **Credential JSON** tab above the viewer shows the credential currently rendered, pretty-printed: the same object the host passes to the frame. It has a Copy button and a link to the raw file, and it always shows the credential rendered in that tab. When a render method has `renderProperty`, the tab shows the filtered credential the frame receives and says so.

The sample credentials are unsigned. Signature verification is out of scope for this proof of concept, and the page says so.

This is a demonstration for discussion, not production code. The parts the WD makes normative are implemented as written; the extensions are clearly separated so they can be judged on their own.

## What to try

1. Open the page and choose **Digital Product Passport**. The page moves to that credential's verify URL (see below). The activity panel shows the template fetched and its digest checked, the product image declared in `renderResource`, fetched and checked, and the template reporting ready.
2. Scroll to **Related Documents** and click the conformity credential link. The host resolves the pointer `/credentialSubject/relatedDocument/0/linkURL` to the DCC's verify URL on this site and opens it in a new tab, which fetches the DCC, checks it against the `digestMultibase` in the URL and renders it. If the browser blocks the new tab, the host shows a dialog with an **Open in new tab** button.
3. Click any other link, for example the facility under **Produced at**. The host shows its own confirmation with the address before opening anything. Most sample addresses are fictitious, so the new tab may not load a real page.

## What follows the Working Draft

| Behaviour | WD section | Where |
|---|---|---|
| Choose the `renderMethod` entry with `type` `SuiteRenderMethod` and `renderSuite` `html` (exact match) | 2.2, 3.2.1 | `selectHtmlRenderMethod` in `js/core.js` |
| Host page CSP includes `frame-src 'none'`, as a meta element and as a response header | 2.2.2.2 | `index.html`, `vercel.json` |
| Template frame has `sandbox="allow-scripts"` only and is populated through `srcdoc` | 2.2.2.2, 3.2.1 | `startFrame` in `js/host.js` |
| Hosted template fetched by the host and checked against `digestMultibase` (multibase `u`, SHA-2-256 multihash `0x12 0x20`, computed with SubtleCrypto) before injection; refused on mismatch | 2.2, 2.2.2.2 | `templateReference`, `verifyDigestMultibase` in `js/core.js`; `render` in `js/host.js` |
| `template` as a `data:` URL | 2.2, 2.2.2 | `templateReference`, `decodeDataUrl` in `js/core.js` |
| Wrapper code: `<meta http-equiv="content-security-policy" content="default-src data: 'unsafe-inline'">`, the credential in `<script name="credential" type="application/vc">` in the head, the template in the body | 2.2.2.2.2, 3.2.1, Example 9 | `buildWrapper` in `js/core.js` |
| `renderProperty` filtering when present | 2.2, 3.2.1 | `filterByRenderProperty` in `js/core.js` (see limits below) |
| Ready and error: a `MessageChannel` set up on frame load, `start` sent with `port2`, `window.renderMethodReady(err)` defined by the wrapper, frame shown on `ready`, error shown otherwise | 2.2.2.2.3, 3.2.1, 3.2.2, Examples 11 and 12 | `WRAPPER_SCRIPT` in `js/core.js`; `startFrame` in `js/host.js` |
| `outputPreference.style` width and height applied to the frame when given | 2.2.2.3 | `startFrame` in `js/host.js` |

Two details worth knowing:

- The host keeps listening on the port after `ready`, because open-link messages for host-mediated links arrive later. Following the normative text in 3.2.1, it rejects the render only on an error message, rather than treating any message other than `ready` as an error as Example 11's handler does.
- JSON placed in a data block has `<` written as `\u003c`. That is the same character once parsed, so the credential is unchanged, but `</script>` inside a credential value cannot close the block. When there is no `renderProperty`, the credential block holds the credential file's own text, so it parses back equal to the file.

## The extensions

Both extensions keep the WD's security model intact. The sandbox is not relaxed, the wrapper CSP is not weakened, and no request ever leaves the frame.

### Host-mediated links

The wrapper, which the host writes, defines `window.renderMethodOpenLink(pointer)`. It posts `{type: 'open-link', pointer}` on the same port as `ready`. The templates call it from a link's click handler when it exists, and otherwise leave the link alone, so in a strict renderer they behave exactly as before.

The host resolves the pointer (RFC 6901) against the credential it holds, never against anything the frame supplies. It acts only when the value there is a single absolute `https:` URL string, and logs a refusal otherwise. A message that carries a URL instead of a pointer is ignored. Every link opens in a new browser tab; there is no in-place navigation. When the address is on the PoC's own origin (a verify URL for a linked credential, for example), the host opens it with `window.open(url, '_blank')`, and if the browser blocks that, shows a dialog whose **Open in new tab** button opens it. Any other address needs the reader's confirmation in a host dialog, then opens with `window.open(url, '_blank', 'noopener,noreferrer')`.

Why this shape: the template can name a place in the signed credential but can never build a URL, so it cannot encode credential data into an address or send the reader somewhere the issuer did not write. The host stays in charge of every navigation.

When the host offers `renderMethodOpenLink`, a named link that it will follow (an `https:` URL with a pointer) shows only its name, with the URL as its hover title. Without the hook the templates keep the URL visible as text beside the name, because in a strict renderer the click does nothing and the reader needs the address.

Code: `decideOpenLink` and `isSameOrigin` in `js/core.js`, `handleOpenLink`, `openOwnTab` and `confirmLink` in `js/host.js`, and the `hostFollows()` and `link()` helpers in both templates.

### The verify URL

In UNTP practice a link to another credential is already a verify-page address, built when the credential is issued: the resolver's target, pointing at the reference implementation's verify page with the direct query parameters `uri` (the credential's URL), `digestMultibase` (its digest) and optionally `decryptionKey`. The PoC mirrors those direct parameters (not the deprecated `?q={"payload":...}` form):

```
https://untp-render-method-poc.vercel.app/verify?uri=<encodeURIComponent(credential URL)>&digestMultibase=<u...>&decryptionKey=<optional>
```

The passport's related-document link is such a URL for the hosted DCC, with `mediaType` `text/html` because it is a web page; the credential's digest travels in the URL, so the link object carries no `digestMultibase` of its own. `scripts/build-digests.mjs` builds it from `BASE_URL` and the DCC's digest.

When the page loads with `uri` in its query, the host fetches that address (following redirects, with `Accept: application/vc, application/ld+json;q=0.9, application/json;q=0.8`, no cookies and no referrer), checks `digestMultibase` when given and refuses the credential on a mismatch, parses the JSON and renders it through the normal path. The activity panel logs each step, including the final URL after redirects. A fetch that fails, for example because the server does not allow cross-origin requests, is reported as an error naming the likely cause. When `decryptionKey` is present, the page says encrypted credentials are out of scope for this PoC and fetches nothing.

The picker also navigates to each credential's verify URL, so every rendered credential has an address that can be shared, and the browser's back button moves between them. `/verify` is served by the same `index.html` through a rewrite in `vercel.json` (and in `serve.json` for `npx serve`). Any static server without rewrites can use `index.html?uri=...` with the same parameters.

Code: `buildVerifyUrl`, `parseVerifyParams` and `acceptCredentialBytes` in `js/core.js`, `loadFromQuery` in `js/host.js`.

### Host-prefetched images

The issuer declares what may be prefetched with `renderResource`, an array of JSON Pointers on the `SuiteRenderMethod` next to `renderProperty`. The passport declares `["/credentialSubject/productImage"]`. For each pointer the host requires the named object to have an `https:` URL in `linkURL` (or `id`), a `digestMultibase` and a `mediaType` starting `image/`. It fetches at most 10 images of at most 2 MB each, checks every digest, keeps verified images for the rest of the page session keyed by digest, and passes them to the template as

```html
<script name="resources" type="application/json">{"<original URL>": "data:image/png;base64,..."}</script>
```

next to the credential block. When `renderProperty` is present, a `renderResource` pointer outside it is ignored. Images that are not declared, lack a digest or fail the check are not passed, and the panel says why. The passport template then keeps its gradient header, as it does for any credential without an embedded image.

Why this shape: the WD already has the host fetch a template only when it is digest-pinned. This extension applies the same rule to images the issuer names explicitly, so the template still makes no request, the issuer controls what is fetched, and the credential is never rewritten to carry `data:` URLs.

`renderResource` is a PoC extension term. It is not part of the W3C draft or of UNTP. Because the UNTP v0.8.0 context does not define it, each PoC credential appends an inline context entry, `{"renderResource": {"@id": "https://untp-render-method-poc.vercel.app/vocab#renderResource", "@container": "@list"}}`, and `vocab.html` describes the term.

Code: `planRenderResources` in `js/core.js`, `prefetchImages` in `js/host.js`, and `prefetched()` and `productImage()` in the passport template.

## Limits and simplifications

- Signatures are not verified. The credentials are unsigned samples.
- Encrypted credentials are not supported: a verify URL with `decryptionKey` is refused without fetching.
- The verify page fetches whatever `https:` address its `uri` names, as the reference implementation's does. A template it renders still runs only in the sandboxed frame.
- `renderProperty` filtering is a simplified stand-in for the `selectJsonLd` algorithm the WD names (Data Integrity ECDSA Cryptosuites v1.0, section 3.4.13). It keeps the root `@context`, `id` and `type` and copies each selected value to the same position. The samples do not use `renderProperty`.
- The WD makes a template's `digestMultibase` optional. This PoC fetches only digest-pinned templates and refuses others.
- The WD recommends protecting the privacy of template requests, for example with Oblivious HTTP (2.2.2.1). This PoC fetches directly, without cookies or a referrer.
- Only the passport template uses host-prefetched images. The conformity credential carries its trustmark as embedded image data, which the template already shows.

## Changes from the upstream templates and samples

Templates (`templates/`): the changes are marked with `// PoC extension: host-mediated links` or `// PoC extension: host-prefetched images`. Every link built from a credential value now carries the JSON Pointer of that value, and shows its name alone when the host follows it. The passport template also gains a **Related Documents** section, because the upstream template does not show `relatedDocument` and the passport's link to its conformity credential lives there. Otherwise, layout, labels, text-only rendering and the `renderMethodReady` calls are unchanged.

Credentials (`credentials/`), edited for the PoC:

- Both: `renderMethod.template` points at the PoC-hosted template with its digest, and `@context` gains the inline `renderResource` entry.
- Passport: the product image moved from an embedded `data:` URL to `images/cathode-product.png` (the same image, decoded) with a digest; the render method declares `renderResource`; the related conformity credential link is the PoC verify URL for `credentials/dcc-cathode.json`, carrying the DCC's digest, with `mediaType` `text/html` and the original `linkType`.
- Both: the em-dash characters in sample values (names and link names) were replaced with " - ".

## Run it locally

Any static file server works. `npx serve` also reads `serve.json`, which serves `/verify`:

```sh
npx serve .
```

Then open the address it prints. The credentials name their template, image and linked credential under the production address. When the page is served from another origin, the host fetches those files from the current origin instead. This mapping happens in one place, `toFetchUrl` in `js/config.js`, and changes only where the host fetches from and which origin counts as the PoC's own when a link is opened, never the URLs in the credential. On a server without rewrites, use `index.html?uri=...` instead of `/verify?uri=...`.

Opening `index.html` straight from the file system does not work, because browsers do not load JavaScript modules from `file:` URLs.

## Tests

```sh
node scripts/test.mjs
node scripts/build-digests.mjs --check
```

`scripts/test.mjs` uses Node built-ins only. It checks pointer resolution and the host-mediated link refusal rules, the digest computation against the digests recorded in the credentials, the wrapper's credential block and escaping, the verify URL parameters and its digest refusal, own-origin and external link handling, the host-prefetched image `renderResource` rules, and runs the real wrapper script and both templates against a small DOM stand-in to confirm that every credential link sends the pointer of its own URL and that the image path and its fallback work. It is not a browser test: the sandbox and CSP behaviour can only be observed in a browser.

## Deploy

The repository is a static site with no build step. `vercel.json` rewrites `/verify` and `/vocab`, sets the host page CSP header, `Access-Control-Allow-Origin: *` on `/images/*`, `/templates/*` and `/credentials/*`, the content types, and a `sandbox` CSP on the templates so that opening a template address directly in a browser does not run its script.

To deploy on another domain:

1. Change the `BASE_URL` line in `js/config.js`.
2. Run `node scripts/build-digests.mjs`. It rewrites every PoC-hosted URL in `credentials/` to the new base and recomputes every digest, writing the conformity credential before the passport that pins it.
3. Commit and deploy.

Run `node scripts/build-digests.mjs` again after any change to a template, an image or a credential, because the digests pin exact bytes.

## Layout

```
index.html            host page, also served at /verify
vocab.html            the PoC's renderResource term
css/host.css          host page styles
js/config.js          BASE_URL, the picker's credentials, origin mapping
js/core.js            pointers, digests, wrapper, link and image rules (no DOM)
js/host.js            host page controller
templates/            the two render templates, with the extension changes
credentials/          the two sample credentials, edited for the PoC
images/               the product image the passport links to
scripts/              build-digests.mjs and test.mjs
vercel.json           headers and the /verify rewrite for Vercel
serve.json            the /verify rewrite for npx serve
```

## Provenance and licence

The templates and sample credentials derive from UN/CEFACT [spec-untp](https://opensource.unicc.org/un/unece/uncefact/spec-untp) and [uncefact/tests-untp](https://github.com/uncefact/tests-untp). They come from work in progress for [spec-untp issue 885](https://opensource.unicc.org/un/unece/uncefact/spec-untp/-/issues/885), built on top of [merge request 864](https://opensource.unicc.org/un/unece/uncefact/spec-untp/-/merge_requests/864) and not yet merged:

- `artefacts/render-templates/v0.8.0/dpp/DigitalProductPassport-1.0.0.html`
- `artefacts/render-templates/v0.8.0/dcc/DigitalConformityCredential-1.0.0.html`
- `artefacts/samples/v0.8.0/dpp/DigitalProductPassport_cathode_instance.json`
- `artefacts/samples/v0.8.0/dcc/ConformityCredential_cathode_scheme_instance.json`

The rendering rules follow the [W3C Working Draft of 6 October 2026](https://www.w3.org/TR/2026/WD-vc-render-method-20261006/).

This repository is licensed under the GNU General Public License v3.0, the same terms as spec-untp. See `LICENSE`.
