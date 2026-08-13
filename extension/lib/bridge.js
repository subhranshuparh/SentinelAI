/**
 * Content-script side of the network bridge.
 *
 * Why this file exists instead of the content script calling fetch() directly:
 *
 * Under Manifest V3 a content script's fetch() is subject to the *host page's*
 * CORS policy, not the extension's. A scan fired from mail.google.com would be
 * a cross-origin request to 127.0.0.1:8000 that Gmail's policy blocks outright,
 * and the failure surfaces as an opaque TypeError with no useful message. Host
 * permissions do not lift that restriction for content scripts — only for
 * extension-origin contexts.
 *
 * So every request is forwarded to the service worker, which runs at the
 * extension origin, holds the host permission, and is exempt. This also means
 * the backend URL and every network call live in exactly one place, which is
 * the arrangement a security review wants to see anyway.
 *
 * Presents the same surface as lib/api.js so content.js does not care which of
 * the two it is talking to.
 */

const SentinelAPI = {
  backendOnline: null, // null = unknown, true/false once probed.

  async _send(type, payload) {
    try {
      const reply = await chrome.runtime.sendMessage({ type, payload });

      // An undefined reply means the service worker was asleep and did not wake
      // in time, or the extension was reloaded out from under this page. Neither
      // is a backend verdict, so nothing may be inferred about the text.
      if (!reply) return null;

      this.backendOnline = reply.online;
      return reply.data ?? null;
    } catch (_error) {
      // Thrown when the extension context is invalidated (a reload during
      // development, or an update). Swallowed: the alternative is an uncaught
      // rejection on every keystroke in the host page's console.
      return null;
    }
  },

  /**
   * Scan text for PII.
   *
   * Returns null on any failure rather than throwing. A null means "no verdict",
   * which the UI renders as silence — never as "clean".
   *
   * @param {{text: string, origin: string, fieldKind: string,
   *          suppressed: string[], source?: 'typed'|'paste'|'ocr'}} args
   * @returns {Promise<object|null>}
   */
  scan(args) {
    return this._send('sentinel:scan', args);
  },

  /** Site trust check. @returns {Promise<object|null>} */
  checkSite(url) {
    return this._send('sentinel:check-site', { url });
  },

  /**
   * Chat scam check (Module 11), for the auto-watch path.
   *
   * The right-click path does not come through here — the service worker
   * already has the selection from the context-menu event and calls the API
   * directly. This entry point exists for `content/chat.js`, which is the only
   * context that can read a conversation out of the page.
   *
   * @param {{messages: Array<{text: string, incoming: boolean}>, surface: string}} args
   * @returns {Promise<object|null>}
   */
  analyzeScam(args) {
    return this._send('sentinel:scam-analyze', args);
  },

  /**
   * Read the text out of images the user is about to upload, and scan it (M12).
   *
   * One round trip covers both halves. The service worker owns the offscreen
   * document — a content script cannot touch `chrome.offscreen` — and it also
   * owns the backend call, so the image bytes go from this page straight into an
   * extension-origin context and the reply that comes back is already a verdict.
   *
   * Batched on purpose: the OCR engine costs seconds to start and the worker
   * keeps it warm for the whole array. Sending one message per file would pay
   * that per file.
   *
   * @param {{images: Array<{name: string, dataUrl: string}>, origin: string,
   *          suppressed: string[]}} args
   * @returns {Promise<{results: Array<object>, checkedCount: number,
   *                    skippedCount: number}|null>}
   */
  ocrScan(args) {
    return this._send('sentinel:ocr-scan', args);
  },

  /** Liveness + which detection tiers are armed. */
  health() {
    return this._send('sentinel:health', {});
  },
};

globalThis.SentinelAPI = SentinelAPI;
