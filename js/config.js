// Deployment settings for the proof of concept.
//
// BASE_URL is the single source of every absolute URL the PoC publishes. The
// credentials name their template, image and linked credential under it. To
// deploy on another domain, change this one line and run
// `node scripts/build-digests.mjs`, which rewrites the URLs in credentials/
// and recomputes their digests.
export const BASE_URL = 'https://untp-render-method-poc.vercel.app';

// The credentials this PoC hosts and knows how to render. The host offers
// them in its picker, and a host-mediated link (a PoC extension) whose URL is
// one of these renders the credential in the viewer instead of opening a tab.
export const CATALOGUE = [
  {
    url: BASE_URL + '/credentials/dpp-cathode.json',
    label: 'Digital Product Passport',
    detail: 'LME Grade A copper cathode'
  },
  {
    url: BASE_URL + '/credentials/dcc-cathode.json',
    label: 'Digital Conformity Credential',
    detail: 'Responsible cathode production attestation'
  }
];

// Maps a URL under BASE_URL to the origin the page is actually served from,
// so the same credentials work on `npx serve`, on a preview deployment and on
// the production domain. On the production domain this returns the URL
// unchanged. This is the only place the mapping happens; it changes where the
// host fetches from, never the URL the credential holds or the template sees.
export function toFetchUrl(url, origin) {
  const here = origin || (typeof location !== 'undefined' ? location.origin : BASE_URL);
  if (here !== BASE_URL && url.startsWith(BASE_URL + '/')) {
    return here + url.slice(BASE_URL.length);
  }
  return url;
}

// True when the URL is one of the PoC's own hosted credentials.
export function isCatalogueCredential(url) {
  return CATALOGUE.some((entry) => entry.url === url);
}
