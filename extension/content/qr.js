/**
 * Page-side half of Module 9.
 *
 * Two responsibilities, both of which exist only because a content script can
 * do something no other extension context can:
 *
 *   1. **Read `blob:` images.** A blob URL is scoped to the document that
 *      created it. The service worker and the offscreen document are different
 *      origins and get an opaque failure. This script shares the page's origin,
 *      so it is the only place in the extension that can turn one into bytes.
 *      That matters more than it sounds: WhatsApp Web, Telegram Web and Gmail
 *      all render received images as blob: URLs, and a QR code sent by a
 *      stranger in a chat is the exact thing this module was built for.
 *
 *   2. **Show the verdict.** The panel lives in the page because that is where
 *      the user is looking. It is drawn by `SentinelToast`, in a closed shadow
 *      root, from `textContent` only.
 *
 * Nothing here decides anything. It fetches bytes and it renders a sentence
 * somebody else wrote.
 */

(() => {
  /** Matches the offscreen document's ceiling. Beyond this the base64 string
   *  is larger than the message channel wants to carry, and no QR photo is. */
  const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

  /**
   * Read a page-scoped blob URL into a data URL.
   *
   * Returns `{dataUrl: null}` rather than throwing on every failure path. The
   * service worker treats a null as "could not read that image" and says so;
   * an exception here would surface as an unhandled rejection in the host
   * page's console, which is both noisy and useless.
   */
  async function readBlobUrl(url) {
    try {
      const response = await fetch(url);
      if (!response.ok) return { dataUrl: null };

      const blob = await response.blob();
      // Type and size are checked again in the offscreen document. Checking
      // here as well is not redundant: it avoids base64-encoding megabytes
      // that are about to be rejected, and the two contexts do not trust each
      // other's inputs by design.
      if (!blob.type.toLowerCase().startsWith('image/')) return { dataUrl: null };
      if (blob.size === 0 || blob.size > MAX_IMAGE_BYTES) return { dataUrl: null };

      const dataUrl = await new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : null);
        reader.onerror = () => resolve(null);
        reader.readAsDataURL(blob);
      });
      return { dataUrl };
    } catch (_error) {
      return { dataUrl: null };
    }
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Only this extension. Web pages cannot reach a content script's listener
    // without `externally_connectable`, which is not declared — but the check
    // costs a line and the alternative is trusting that forever.
    if (sender.id !== chrome.runtime.id) return false;

    if (message?.type === 'sentinel:read-image') {
      const url = message.payload?.url;
      if (typeof url !== 'string' || !url.startsWith('blob:')) {
        sendResponse({ dataUrl: null });
        return false;
      }
      readBlobUrl(url).then(sendResponse);
      return true; // async reply
    }

    if (message?.type === 'sentinel:qr') {
      const state = message.payload || {};
      if (state.state === 'checking') {
        globalThis.SentinelToast.showQrChecking();
      } else if (state.state === 'failed') {
        globalThis.SentinelToast.showQrUnavailable(state.message);
      } else if (state.state === 'result' && state.result) {
        globalThis.SentinelToast.showQr(state.result);
      }
      sendResponse({ shown: true });
      return false;
    }

    return false;
  });
})();
