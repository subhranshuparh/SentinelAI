/**
 * Service worker: site trust checks and the toolbar badge.
 *
 * Two jobs, both of which must happen outside the page:
 *
 *   1. **Site checks on navigation.** The content script cannot do this — it runs
 *      after the page has already loaded and executed. By the time it exists, a
 *      credential-harvesting page has already rendered its fake login form.
 *   2. **The badge.** It is the only always-visible surface the extension owns,
 *      so it carries the site verdict rather than a count of anything.
 *
 * MV3 service workers are terminated aggressively (~30s idle). Nothing here may
 * live in a module-level variable and be expected to survive; every piece of
 * state that must persist goes to chrome.storage.
 */

import './lib/allowlist.js';
import './lib/api.js';

const VERDICT_BADGE = {
  // Text is one character because the badge is ~4 characters wide at best, and
  // truncated words read as gibberish.
  dangerous: { text: '!', color: '#dc2626', title: 'Dangerous site — SentinelAI recommends leaving' },
  suspicious: { text: '?', color: '#d97706', title: 'Suspicious site — be careful what you enter' },
  safe: { text: '', color: '#16a34a', title: 'SentinelAI — no problems found on this site' },
  // "unknown" is its own verdict and is NOT rendered as safe. A missing answer
  // from RDAP or Safe Browsing means we do not know, and telling the user a site
  // is fine when we never checked is the one lie a security tool cannot afford.
  unknown: { text: '·', color: '#64748b', title: 'SentinelAI could not check this site' },
};

/** Schemes worth checking. chrome://, about:, file:// have no meaningful verdict. */
function isCheckableUrl(url) {
  return typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'));
}

async function setBadge(tabId, verdict) {
  const style = VERDICT_BADGE[verdict] || VERDICT_BADGE.unknown;
  try {
    await chrome.action.setBadgeText({ tabId, text: style.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
    await chrome.action.setTitle({ tabId, title: style.title });
  } catch (_error) {
    // Tab closed between the check starting and finishing. Not an error worth
    // surfacing — the user has already moved on.
  }
}

/**
 * Cache verdicts per tab so the popup can render instantly.
 *
 * Keyed by tab id and stamped with the URL, because a tab is reused across
 * navigations and a stale verdict shown for a new site is actively misleading.
 *
 * The whole `reasons` array is stored, not a single summary sentence. The badge
 * has room for one character and the summary is one line, but a user who opens
 * the popup after seeing a red badge is asking "why?" — and the itemised list is
 * the answer. Storing only the summary here would throw it away before the
 * popup ever ran.
 */
async function cacheVerdict(tabId, url, result) {
  await chrome.storage.session.set({
    [`verdict_${tabId}`]: {
      url,
      verdict: result?.verdict ?? 'unknown',
      summary: result?.summary ?? 'SentinelAI could not reach its backend to check this site.',
      // Defended against a malformed body: the popup iterates this directly.
      reasons: Array.isArray(result?.reasons) ? result.reasons : [],
      trustScore: typeof result?.trust_score === 'number' ? result.trust_score : null,
      confidence: typeof result?.confidence === 'number' ? result.confidence : null,
      checkedAt: Date.now(),
    },
  });
}

chrome.webNavigation.onCompleted.addListener(async (details) => {
  // frameId 0 is the top-level document. Ad iframes and embedded widgets each
  // fire this event too; checking them would multiply requests by ~20x for
  // verdicts the user cannot act on anyway.
  if (details.frameId !== 0) return;
  if (!isCheckableUrl(details.url)) return;

  // Show the pending state immediately. A site check can take a couple of
  // seconds when RDAP is slow, and a badge that still reads "safe" from the
  // previous page during that window is the worst possible thing to display.
  await setBadge(details.tabId, 'unknown');

  const result = await globalThis.SentinelAPI.checkSite(details.url);

  // Null covers both "backend down" and "endpoint not deployed yet". Either way
  // the honest badge is "unknown", not "safe".
  await setBadge(details.tabId, result?.verdict ?? 'unknown');
  await cacheVerdict(details.tabId, details.url, result);
});

// Drop cached verdicts when their tab dies, so storage.session does not grow
// unbounded across a long browsing day.
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`verdict_${tabId}`);
});

// ---------------------------------------------------------------------------
// Network bridge (see lib/bridge.js for why content scripts route through here)
// ---------------------------------------------------------------------------

/** Message type -> handler. An explicit table, so an unknown type cannot reach
 *  the network. A content script runs inside a page the extension does not
 *  control; treating its messages as a trusted command channel would let any
 *  site drive the extension's fetches. */
const HANDLERS = {
  'sentinel:scan': (payload) => globalThis.SentinelAPI.scan(payload),
  'sentinel:check-site': (payload) => globalThis.SentinelAPI.checkSite(payload.url),
  'sentinel:scam-analyze': (payload) => globalThis.SentinelAPI.analyzeScam(payload),
  // Module 12. Routed through here rather than done in the content script for
  // two reasons: a content script has no access to chrome.offscreen, and the
  // image bytes should never be handed to code running inside a page the
  // extension does not control.
  'sentinel:ocr-scan': (payload) => ocrScanImages(payload),
  'sentinel:health': () => globalThis.SentinelAPI.health(),
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handler = HANDLERS[message?.type];
  if (!handler) return false;

  // Only messages from a real tab's content script are served. Without this,
  // any other extension able to guess the id could use this worker as an
  // open proxy to the local backend.
  if (!sender.tab) return false;

  handler(message.payload || {})
    .then((data) => sendResponse({ online: globalThis.SentinelAPI.backendOnline, data }))
    .catch(() => sendResponse({ online: false, data: null }));

  // `true` keeps the message channel open for the async reply above. Omitting
  // it closes the port immediately and the content script gets undefined.
  return true;
});

// ---------------------------------------------------------------------------
// Module 9 — QR codes
// ---------------------------------------------------------------------------

const QR_MENU_ID = 'sentinel-check-qr';
const OFFSCREEN_PATH = 'offscreen/offscreen.html';

/**
 * Failure codes -> the sentence the user reads.
 *
 * The mapping is here, in the extension, and not in the string the decoder
 * throws — same rule the backend follows for signals. A raw error message is a
 * developer artefact; "SentinelAI could not download that image" is an answer.
 *
 * Every line says what did *not* happen. None of them can be misread as "this
 * QR code is fine", which is the failure mode that matters: a user who
 * right-clicked a code and saw a grey box would otherwise assume it passed.
 */
const QR_FAILURE_COPY = {
  // An answer, not an absence: we looked at every pixel and there was no code.
  'no-qr-found': 'No QR code found in that image.',
  'not-an-image': 'SentinelAI could not read that image, so the QR code was not checked.',
  'too-large': 'That image is too large for SentinelAI to check safely.',
  unreadable: 'SentinelAI could not read that image, so the QR code was not checked.',
  unreachable: 'SentinelAI could not open that image, so the QR code was not checked.',
  // Decoded fine; the verdict is what is missing.
  'no-verdict': 'SentinelAI could not reach its backend, so this QR code was not checked.',
};

/**
 * Bring the offscreen document up if it is not already running.
 *
 * The `hasDocument` check is not sufficient on its own: two clicks in quick
 * succession can both pass it before either creates anything, and the second
 * `createDocument` then throws. Chrome gives no error code for that, only a
 * message, so it is matched by text — narrowly, so that a genuinely different
 * failure still propagates.
 */
async function ensureOffscreen() {
  if (await chrome.offscreen.hasDocument()) return;
  try {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_PATH,
      // BLOBS for the canvas both decoders draw on; WORKERS because Module 12's
      // Tesseract engine runs in a Web Worker inside that document. Chrome does
      // not enforce these beyond requiring at least one, but they are the
      // extension's written justification for holding a hidden document open and
      // an inaccurate one would be a small lie in a security tool's manifest.
      reasons: ['BLOBS', 'WORKERS'],
      justification:
        'Read a QR code or the printed text out of an image the user chose, using ' +
        'a canvas and a local OCR engine, without sending the image anywhere.',
    });
  } catch (error) {
    if (!String(error?.message || error).includes('single offscreen document')) throw error;
  }
}

/**
 * Decode one image to a QR payload.
 *
 * The document is closed as soon as the decode finishes rather than kept warm.
 * An offscreen document that outlives its work keeps the service worker alive
 * indefinitely — it counts as an active extension context — which turns a
 * once-in-a-while user action into a permanently resident process. Re-creating
 * it costs tens of milliseconds on a path where somebody just used a mouse.
 *
 * @returns {Promise<{ok: true, payload: string} | {ok: false, code: string}>}
 */
async function decodeImage(source) {
  await ensureOffscreen();
  try {
    const reply = await chrome.runtime.sendMessage({
      target: 'sentinel-offscreen',
      type: 'decode-qr',
      payload: { source },
    });
    return reply || { ok: false, code: 'unreadable' };
  } catch (_error) {
    return { ok: false, code: 'unreadable' };
  } finally {
    await chrome.offscreen.closeDocument().catch(() => {});
  }
}

/** Send to a tab's content script, tolerating its absence. */
async function sendToTab(tabId, message) {
  try {
    return await chrome.tabs.sendMessage(tabId, message);
  } catch (_error) {
    // No content script in this tab: an excluded match, a PDF viewer, a
    // chrome:// page, or the extension was reloaded since the page loaded.
    return null;
  }
}

/** Push a QR panel state to the page the user right-clicked in. */
async function showQrState(tabId, state) {
  const delivered = await sendToTab(tabId, { type: 'sentinel:qr', payload: state });
  if (delivered === null) {
    // The answer has nowhere to go. Say so in the extension's own console
    // rather than failing silently, because from the user's side an absent
    // panel is indistinguishable from a panel that said nothing was wrong.
    console.warn('SentinelAI: no content script in this tab to show the QR result.');
  }
}

/**
 * Turn the right-clicked image into something the offscreen document can fetch.
 *
 * `blob:` is the case that matters. Blob URLs are scoped to the document that
 * minted them, so neither the service worker nor the offscreen document can
 * fetch one — only the content script in that exact tab shares the origin. And
 * this is not an edge case: WhatsApp Web, Telegram Web and Gmail all render
 * received images as blob: URLs, which is precisely where a scam QR code
 * arrives. Skipping it would mean the feature failed on its own demo.
 *
 * @returns {Promise<string|null>} A URL the offscreen document may fetch.
 */
async function resolveImageSource(info, tabId) {
  const src = info.srcUrl;
  if (typeof src !== 'string' || src.length === 0) return null;

  if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('data:')) {
    return src;
  }
  if (src.startsWith('blob:')) {
    const reply = await sendToTab(tabId, { type: 'sentinel:read-image', payload: { url: src } });
    return typeof reply?.dataUrl === 'string' ? reply.dataUrl : null;
  }
  // filesystem:, chrome-extension:, and whatever is invented next. An allowlist
  // rather than a denylist, because this string decides what gets fetched.
  return null;
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== QR_MENU_ID) return;
  const tabId = tab?.id;
  if (typeof tabId !== 'number') return;

  // Loading state first. A site check behind a URL QR can take several seconds,
  // and a right-click that appears to do nothing reads as a broken extension.
  await showQrState(tabId, { state: 'checking' });

  const source = await resolveImageSource(info, tabId);
  if (source === null) {
    await showQrState(tabId, { state: 'failed', message: QR_FAILURE_COPY.unreachable });
    return;
  }

  const decoded = await decodeImage(source);
  if (!decoded.ok) {
    const message = QR_FAILURE_COPY[decoded.code] || QR_FAILURE_COPY.unreadable;
    await showQrState(tabId, { state: 'failed', message });
    return;
  }

  const result = await globalThis.SentinelAPI.checkQr(decoded.payload);
  if (result === null) {
    await showQrState(tabId, { state: 'failed', message: QR_FAILURE_COPY['no-verdict'] });
    return;
  }

  await showQrState(tabId, { state: 'result', result });
});

// ---------------------------------------------------------------------------
// Module 11 — chat scams (right-click path)
// ---------------------------------------------------------------------------

const CHAT_MENU_ID = 'sentinel-check-chat';

/** Matches MIN_CONVERSATION_CHARS in `services/scam/heuristics.py`. Checked here
 *  as well so a two-word selection gets an instant, specific sentence instead of
 *  a round trip that comes back "not enough text". */
const MIN_SELECTION_CHARS = 12;

/** Matches MAX_MESSAGE_CHARS. Chrome truncates `selectionText` around 1,000
 *  characters of its own accord, so this is belt-and-braces. */
const MAX_SELECTION_CHARS = 2000;

const CHAT_FAILURE_COPY = {
  'too-short':
    'Select more of the conversation — including the part where they say what they ' +
    'want — and try again.',
  'no-verdict': 'SentinelAI could not reach its backend, so these messages were not checked.',
};

/** Push a scam panel state to the page the user right-clicked in. */
async function showScamState(tabId, state) {
  const delivered = await sendToTab(tabId, { type: 'sentinel:scam', payload: state });
  if (delivered === null) {
    console.warn('SentinelAI: no content script in this tab to show the message result.');
  }
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== CHAT_MENU_ID) return;
  const tabId = tab?.id;
  if (typeof tabId !== 'number') return;

  const selection = (info.selectionText || '').trim().slice(0, MAX_SELECTION_CHARS);
  if (selection.length < MIN_SELECTION_CHARS) {
    await showScamState(tabId, { state: 'failed', message: CHAT_FAILURE_COPY['too-short'] });
    return;
  }

  await showScamState(tabId, { state: 'checking' });

  // One message, marked incoming. Chrome hands over a flat string with no idea
  // who wrote which line, and the honest reading of "the user highlighted this
  // and asked about it" is that they are asking about something they received.
  // Marking it outgoing instead would cause the backend to discard it and return
  // "nothing to judge", which is an answer to a question nobody asked.
  const result = await globalThis.SentinelAPI.analyzeScam({
    messages: [{ text: selection, incoming: true }],
    surface: 'selection',
  });

  if (result === null) {
    await showScamState(tabId, { state: 'failed', message: CHAT_FAILURE_COPY['no-verdict'] });
    return;
  }

  await showScamState(tabId, { state: 'result', result });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'sentinel_check_review') return;
  const tabId = tab?.id;
  if (typeof tabId !== 'number') return;

  const selection = (info.selectionText || '').trim().slice(0, 2000);
  if (selection.length < 10) return;

  const result = await globalThis.SentinelAPI.analyzeReviews({
    reviews: [{ body: selection }],
  });

  if (result) {
    await sendToTab(tabId, { type: 'sentinel:review_result', payload: result });
  }
});

// ---------------------------------------------------------------------------
// Module 12 — screenshot OCR
// ---------------------------------------------------------------------------

/**
 * How many images one upload is checked against.
 *
 * OCR is ~1-3 seconds per image and the user is standing at a file picker
 * waiting for an answer. Twenty holiday photos would mean a minute of frozen
 * attention for a feature that is looking for one card in one screenshot.
 *
 * The cap is *reported*, never silent: `checkedCount` and `skippedCount` travel
 * back with the result and the panel says "SentinelAI checked the first 3
 * images". A cap the user cannot see is a coverage gap that reads as an all-clear.
 */
const MAX_IMAGES_PER_CHECK = 3;

const IMAGE_FAILURE_COPY = {
  'engine-unavailable':
    'SentinelAI could not start its text reader, so this image was not checked.',
  'not-an-image': 'SentinelAI could not read that file, so it was not checked.',
  'too-large': 'That image is too large for SentinelAI to check safely.',
  unreadable: 'SentinelAI could not read the text in that image, so it was not checked.',
  unreachable: 'SentinelAI could not open that image, so it was not checked.',
  'no-verdict': 'SentinelAI could not reach its backend, so this image was not checked.',
};

/**
 * OCR a batch of images and scan whatever text comes out.
 *
 * The offscreen document is held open across the whole batch, unlike the QR
 * path which closes it per decode. The reason is asymmetric cost: bringing the
 * QR decoder up is a 40 KB script parse, while bringing the OCR engine up is
 * 4.7 MB of wasm to compile plus a 4 MB language model to load — two to four
 * seconds. Paying that per image would make a three-file upload feel broken.
 * The document still closes at the end of the batch, because an offscreen
 * document that outlives its work keeps the service worker resident forever.
 *
 * @param {{images: Array<{name?: string, dataUrl: string}>, origin: string,
 *          suppressed?: string[]}} payload
 * @returns {Promise<{results: Array<object>, checkedCount: number,
 *                    skippedCount: number}>}
 */
async function ocrScanImages(payload) {
  const all = Array.isArray(payload?.images) ? payload.images : [];
  const images = all.slice(0, MAX_IMAGES_PER_CHECK);
  const origin = typeof payload?.origin === 'string' ? payload.origin : '';
  const suppressed = Array.isArray(payload?.suppressed) ? payload.suppressed : [];

  const results = [];
  if (images.length === 0) {
    return { results, checkedCount: 0, skippedCount: 0 };
  }

  await ensureOffscreen();
  try {
    for (const image of images) {
      const name = typeof image?.name === 'string' ? image.name : '';
      const source = typeof image?.dataUrl === 'string' ? image.dataUrl : '';
      if (source.length === 0) {
        results.push({ name, status: 'failed', message: IMAGE_FAILURE_COPY.unreachable });
        continue;
      }

      let read;
      try {
        read = await chrome.runtime.sendMessage({
          target: 'sentinel-offscreen',
          type: 'ocr-image',
          payload: { source },
        });
      } catch (_error) {
        read = null;
      }

      if (!read?.ok) {
        const message = IMAGE_FAILURE_COPY[read?.code] || IMAGE_FAILURE_COPY.unreadable;
        results.push({ name, status: 'failed', message });
        continue;
      }

      if (read.text.length === 0) {
        // An answer, not a failure: the engine ran and the picture had no
        // readable text. Most uploaded images are in this state — a photo, a
        // logo, a chart — and treating it as a failure would put a "could not
        // check" warning on nearly every file anybody attaches.
        results.push({ name, status: 'no-text' });
        continue;
      }

      const scan = await globalThis.SentinelAPI.scan({
        text: read.text,
        origin,
        // Module 12's two request markers. `fieldKind` records where the text
        // arrived from for the dashboard timeline; `source` is what tells the
        // engine it may run checksum-backed character correction. They are
        // separate because a pasted screenshot path would set the first
        // differently and the second identically.
        fieldKind: 'image',
        source: 'ocr',
        suppressed,
      });

      if (scan === null) {
        results.push({ name, status: 'failed', message: IMAGE_FAILURE_COPY['no-verdict'] });
        continue;
      }

      results.push({
        name,
        status: 'checked',
        // Travels with the verdict rather than being folded into it. A clean
        // result off a badly-read image is a weaker claim than a clean result
        // off a sharp one, and the panel is the place that says so.
        poorRead: read.poorRead === true,
        confidence: read.confidence,
        scan,
      });
    }
  } finally {
    // Free the wasm heap before the document goes, then close it. The offscreen
    // document also releases on `pagehide`, so this is belt and braces — but an
    // explicit teardown is the one that runs while there is still a live message
    // channel to report a problem on.
    await chrome.runtime
      .sendMessage({ target: 'sentinel-offscreen', type: 'ocr-release' })
      .catch(() => {});
    await chrome.offscreen.closeDocument().catch(() => {});
  }

  return {
    results,
    checkedCount: images.length,
    skippedCount: all.length - images.length,
  };
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(async () => {
  // Mint the device id at install rather than on first scan, so the very first
  // request already carries a stable identifier and the dashboard has something
  // to group by from keystroke one.
  await globalThis.SentinelAllowlist.deviceId();

  // Context menus survive a browser restart but not a reinstall, and creating
  // one that already exists throws. removeAll first is the only arrangement
  // that is correct on a fresh install, an update, and a developer reload.
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({
    id: QR_MENU_ID,
    // Written as an instruction, not a feature name. "Check this QR code" tells
    // someone who has never opened the popup what the click will do.
    title: 'Check this QR code with SentinelAI',
    contexts: ['image'],
  });
  chrome.contextMenus.create({
    id: CHAT_MENU_ID,
    title: 'Check this message with SentinelAI',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'sentinel_check_review',
    title: 'Check this review with SentinelAI',
    contexts: ['selection'],
  });
});
