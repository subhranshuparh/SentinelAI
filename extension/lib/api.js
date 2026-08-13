/**
 * Backend client.
 *
 * Note what is NOT in this file: any API key. The extension talks only to the
 * SentinelAI backend, which holds the Gemini and Safe Browsing credentials
 * server-side. Extension source is plain text to anyone who opens
 * chrome://extensions — a key shipped here is a published key.
 */

const SENTINEL_BACKEND = 'http://127.0.0.1:8000';

/** Abort a scan that outlives its usefulness. The user has typed more since. */
const SCAN_TIMEOUT_MS = 4000;

/**
 * Site checks get a longer budget than scans, and need one.
 *
 * The backend runs Safe Browsing and RDAP concurrently, and RDAP's own ceiling
 * is 8s — a real registry lookup goes through a bootstrap redirect to a server
 * that may be on another continent. Anything under that would abort valid
 * answers client-side and render "unknown" for sites the backend was about to
 * rate correctly. The extra seconds are affordable because this runs once per
 * navigation, in the service worker, with nobody waiting on a keystroke.
 */
const SITE_TIMEOUT_MS = 12000;

const SentinelAPI = {
  backendOnline: null, // null = unknown, true/false once probed.

  async _headers() {
    return {
      'Content-Type': 'application/json',
      'X-Sentinel-Device-Id': await globalThis.SentinelAllowlist.deviceId(),
    };
  },

  /**
   * Scan text for PII.
   *
   * Returns null on any failure rather than throwing. The caller runs on every
   * keystroke; an exception there would spam the page console and, worse, could
   * break the host site's own error handling. A null means "no verdict", which
   * the UI renders as silence — never as "clean".
   *
   * `source` (Module 12) tells the backend how the text reached it: `typed`,
   * `paste`, or `ocr`. It is the flag that permits checksum-backed correction of
   * characters an optical reader commonly confuses, and it is deliberately a
   * separate axis from `fieldKind` — a screenshot dropped on the dashboard has a
   * source and no field at all. Defaulted here rather than left undefined so
   * that a caller which forgets it gets the safe behaviour: on `typed` text no
   * character is ever rewritten, because a typed `S` is an `S`.
   *
   * @param {{text: string, origin: string, fieldKind: string,
   *          suppressed: string[], source?: 'typed'|'paste'|'ocr'}} args
   * @returns {Promise<object|null>}
   */
  async scan({ text, origin, fieldKind, suppressed, source }) {
    const controller = new AbortController();
    // An OCR scan gets the site budget, not the keystroke budget. Nobody is
    // typing behind it — the user picked a file and is watching a spinner — and
    // a page of recognised text is long enough to open the Tier-2 gate, which
    // alone can spend more than the four seconds a keystroke is allowed.
    const budget = source === 'ocr' ? SITE_TIMEOUT_MS : SCAN_TIMEOUT_MS;
    const timer = setTimeout(() => controller.abort(), budget);

    try {
      const response = await fetch(`${SENTINEL_BACKEND}/api/v1/pii/scan`, {
        method: 'POST',
        headers: await this._headers(),
        signal: controller.signal,
        body: JSON.stringify({
          text,
          site_origin: origin,
          field_kind: fieldKind,
          suppressed_types: suppressed,
          source: source || 'typed',
        }),
      });

      if (response.status === 429) {
        // The limiter engaged. Back off silently rather than showing an error —
        // this is self-inflicted load, not something the user did wrong.
        this.backendOnline = true;
        return null;
      }
      if (!response.ok) {
        this.backendOnline = true; // Reachable, just unhappy with this request.
        return null;
      }

      this.backendOnline = true;
      return await response.json();
    } catch (_error) {
      // Network failure, timeout, or backend down.
      this.backendOnline = false;
      return null;
    } finally {
      clearTimeout(timer);
    }
  },

  /**
   * Site trust check. Used by the service worker on navigation.
   *
   * Returns null on any failure, which the caller renders as the "unknown"
   * badge. Never returns a fabricated "safe".
   *
   * @param {string} url Full page URL.
   * @returns {Promise<object|null>}
   */
  async checkSite(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SITE_TIMEOUT_MS);

    try {
      const response = await fetch(`${SENTINEL_BACKEND}/api/v1/site/check`, {
        method: 'POST',
        headers: await this._headers(),
        signal: controller.signal,
        body: JSON.stringify({ url }),
      });
      if (!response.ok) {
        // Reachable but unhappy — a 422 on an odd URL, or a 429. Distinct from
        // a network failure, so the offline flag must not be set here.
        this.backendOnline = true;
        return null;
      }
      this.backendOnline = true;
      return await response.json();
    } catch (_error) {
      this.backendOnline = false;
      return null;
    } finally {
      clearTimeout(timer);
    }
  },

  /**
   * Check a decoded QR payload (Module 9).
   *
   * Only the decoded *string* is sent. The image never leaves the machine — it
   * is read into a canvas in the offscreen document and released. That is not a
   * performance choice: the pictures people right-click on are screenshots of
   * their own payment apps, and a security tool that uploads them to check them
   * has become the leak it was installed to prevent.
   *
   * Shares the site-check budget rather than the scan budget. A QR that decodes
   * to a URL runs the full site engine behind this call — Safe Browsing and
   * RDAP included — so the four seconds a keystroke gets would abort valid
   * answers. Nobody is typing while this runs; they right-clicked and are
   * waiting.
   *
   * Returns null on any failure. The caller renders that as "could not check",
   * never as a clean QR code.
   *
   * @param {string} payload The decoded QR string, verbatim.
   * @returns {Promise<object|null>}
   */
  async checkQr(payload) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SITE_TIMEOUT_MS);

    try {
      const response = await fetch(`${SENTINEL_BACKEND}/api/v1/qr/check`, {
        method: 'POST',
        headers: await this._headers(),
        signal: controller.signal,
        body: JSON.stringify({ payload }),
      });
      if (!response.ok) {
        // Reachable, unhappy: a 422 on a payload past the 4,500-char cap, or a
        // 429. Distinct from a network failure, so the offline flag stays true.
        this.backendOnline = true;
        return null;
      }
      this.backendOnline = true;
      return await response.json();
    } catch (_error) {
      this.backendOnline = false;
      return null;
    } finally {
      clearTimeout(timer);
    }
  },

  /**
   * Check a chat conversation for scam patterns (Module 11).
   *
   * The one call in this file that carries somebody else's words. Three
   * consequences, all deliberate:
   *
   * Messages are sent with their `direction` intact rather than pre-filtered
   * here. Dropping outgoing messages client-side would look safer and would be
   * worse: the guarantee "the user's own words are never scored" would then live
   * in extension code that anyone can modify, instead of in one function on the
   * server that every path goes through. The extension states which is which;
   * the backend is what enforces it.
   *
   * Nothing is stored on the other end — `/api/v1/scam/analyze` has no database
   * session in its signature — so this request leaves no trace of a private
   * conversation anywhere.
   *
   * Given the scan budget rather than the site budget. This can run
   * unattended behind a MutationObserver while somebody is mid-conversation, and
   * a request that outlives its usefulness should be abandoned rather than
   * answered late.
   *
   * Returns null on any failure. The caller renders that as "not checked",
   * never as a clean conversation.
   *
   * @param {{messages: Array<{text: string, incoming: boolean}>, surface: string}} args
   * @returns {Promise<object|null>}
   */
  async analyzeScam({ messages, surface }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

    try {
      const response = await fetch(`${SENTINEL_BACKEND}/api/v1/scam/analyze`, {
        method: 'POST',
        headers: await this._headers(),
        signal: controller.signal,
        body: JSON.stringify({
          messages: (messages || []).map((m) => ({
            text: m.text,
            direction: m.incoming ? 'incoming' : 'outgoing',
          })),
          surface: surface || null,
        }),
      });
      if (!response.ok) {
        // Reachable, unhappy: a 422 on an over-long message, or a 429 from the
        // observer path firing too often. Not a network failure.
        this.backendOnline = true;
        return null;
      }
      this.backendOnline = true;
      return await response.json();
    } catch (_error) {
      this.backendOnline = false;
      return null;
    } finally {
      clearTimeout(timer);
    }
  },

  /**
   * Analyze reviews (Module 5).
   *
   * @param {{reviews: Array<{body: string}>, productTitle?: string}} args
   * @returns {Promise<object|null>}
   */
  async analyzeReviews({ reviews, productTitle }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

    try {
      const response = await fetch(`${SENTINEL_BACKEND}/api/v1/review/analyze`, {
        method: 'POST',
        headers: await this._headers(),
        signal: controller.signal,
        body: JSON.stringify({
          reviews,
          product_title: productTitle || null,
        }),
      });
      if (!response.ok) {
        this.backendOnline = true;
        return null;
      }
      this.backendOnline = true;
      return await response.json();
    } catch (_error) {
      this.backendOnline = false;
      return null;
    } finally {
      clearTimeout(timer);
    }
  },

  /**
   * Fetch the k-anonymity range for a SHA-1 prefix (Module 4).
   *
   * The caller has already hashed the password locally and is sending five hex
   * characters. Roughly a thousand passwords share any given prefix (1,978 for
   * the prefix of "password", measured against the live API), so what crosses
   * the wire identifies a crowd, not a person.
   *
   * Throws on failure rather than returning null, unlike every other method
   * here. Deliberate: those run on the typing path where an exception would be
   * noise, but this one runs because a user pressed a button and is watching a
   * spinner. "Could not check" must reach the screen, not vanish — a silent
   * null would render as an absence of bad news, which is the one thing this
   * codebase never lets a failed check look like.
   *
   * @param {string} prefix Exactly 5 uppercase hex characters.
   * @returns {Promise<{prefix: string, suffixes: Record<string, number>, count: number}>}
   */
  async pwnedRange(prefix) {
    const response = await fetch(
      `${SENTINEL_BACKEND}/api/v1/identity/pwned-range/${encodeURIComponent(prefix)}`,
      { headers: await this._headers() },
    );
    if (!response.ok) {
      this.backendOnline = response.status !== 0;
      throw new Error(`range lookup failed (${response.status})`);
    }
    this.backendOnline = true;
    return await response.json();
  },

  /**
   * Record a locally-matched password result and get the scored verdict back.
   *
   * @param {{hashPrefix: string, breachCount: number, label: string|null}} args
   * @returns {Promise<object>}
   */
  async recordPasswordCheck({ hashPrefix, breachCount, label }) {
    const response = await fetch(`${SENTINEL_BACKEND}/api/v1/identity/password-check`, {
      method: 'POST',
      headers: await this._headers(),
      body: JSON.stringify({
        hash_prefix: hashPrefix,
        breach_count: breachCount,
        label: label || null,
      }),
    });
    if (!response.ok) throw new Error(`password check failed (${response.status})`);
    this.backendOnline = true;
    return await response.json();
  },

  /** Liveness + which detection tiers are armed. Drives the popup status line. */
  async health() {
    try {
      const response = await fetch(`${SENTINEL_BACKEND}/health`);
      if (!response.ok) return null;
      this.backendOnline = true;
      return await response.json();
    } catch (_error) {
      this.backendOnline = false;
      return null;
    }
  },
};

globalThis.SentinelAPI = SentinelAPI;
globalThis.SENTINEL_BACKEND = SENTINEL_BACKEND;
