/**
 * Per-site false-positive overrides.
 *
 * This file is ~80 lines and it is the difference between a product and a
 * nuisance. A tool that flags your order number on every e-commerce site gets
 * uninstalled within ten minutes, and a user who uninstalls is worse off than
 * one who was never protected.
 *
 * Two deliberate design choices:
 *
 *   1. Overrides are stored in chrome.storage.local, NEVER on the backend. They
 *      are private, they work offline, and they survive the backend being down.
 *   2. The suppressed list is SENT to the server with each scan, so a suppressed
 *      type is never matched, never scored, and never persisted. This is a real
 *      opt-out, not a UI-level hide — which matters because the alternative
 *      would still be writing rows about data the user told us to ignore.
 *
 * Scope is (origin, pii_type). "Always allow phone numbers on shop.example.com"
 * must not disable phone detection on Gmail.
 */

const ALLOWLIST_KEY = 'sentinel_allowlist';
const DEVICE_ID_KEY = 'sentinel_device_id';

const SentinelAllowlist = {
  /**
   * Return the set of pii_type values suppressed for this origin.
   * @param {string} origin
   * @returns {Promise<string[]>}
   */
  async suppressedFor(origin) {
    const stored = await chrome.storage.local.get(ALLOWLIST_KEY);
    const allowlist = stored[ALLOWLIST_KEY] || {};
    return allowlist[origin] || [];
  },

  /**
   * Permanently stop warning about `piiType` on `origin`.
   * @param {string} origin
   * @param {string} piiType
   */
  async allow(origin, piiType) {
    const stored = await chrome.storage.local.get(ALLOWLIST_KEY);
    const allowlist = stored[ALLOWLIST_KEY] || {};
    const forOrigin = new Set(allowlist[origin] || []);
    forOrigin.add(piiType);
    allowlist[origin] = [...forOrigin];
    await chrome.storage.local.set({ [ALLOWLIST_KEY]: allowlist });
  },

  /** Undo a single override. Surfaced in the popup so the choice is reversible. */
  async revoke(origin, piiType) {
    const stored = await chrome.storage.local.get(ALLOWLIST_KEY);
    const allowlist = stored[ALLOWLIST_KEY] || {};
    allowlist[origin] = (allowlist[origin] || []).filter((t) => t !== piiType);
    if (allowlist[origin].length === 0) delete allowlist[origin];
    await chrome.storage.local.set({ [ALLOWLIST_KEY]: allowlist });
  },

  /** Full map, for the popup's "what have I muted?" view. */
  async all() {
    const stored = await chrome.storage.local.get(ALLOWLIST_KEY);
    return stored[ALLOWLIST_KEY] || {};
  },

  /**
   * Stable per-install identifier, created once on first use.
   *
   * This is the MVP's stand-in for a user account. crypto.randomUUID() is used
   * rather than anything derived from the machine: SentinelAI should not be able
   * to correlate installs, and a random opaque id is the honest choice for a
   * privacy tool.
   */
  async deviceId() {
    const stored = await chrome.storage.local.get(DEVICE_ID_KEY);
    if (stored[DEVICE_ID_KEY]) return stored[DEVICE_ID_KEY];

    const id = crypto.randomUUID();
    await chrome.storage.local.set({ [DEVICE_ID_KEY]: id });
    return id;
  },
};

// Content scripts share one global scope per frame; there is no module system
// here without a bundler, and adding a bundler for this is not worth 45 minutes.
globalThis.SentinelAllowlist = SentinelAllowlist;
