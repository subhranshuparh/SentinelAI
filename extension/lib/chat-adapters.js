/**
 * Per-surface chat readers.
 *
 * This is the fragile half of Module 11 and it is isolated here on purpose.
 * WhatsApp Web and Telegram Web ship obfuscated class names that change without
 * notice; any selector written below has a shelf life measured in months. The
 * design consequence is not "write better selectors" — it is **assume they will
 * break and make the breakage visible**:
 *
 *   1. Every adapter reports `ok`/`why` rather than silently returning nothing.
 *      A reader that finds zero messages on a page full of messages is a broken
 *      adapter, and it says so in the console instead of looking like a quiet
 *      conversation with nothing wrong in it.
 *   2. `content/chat.js` disables an adapter that fails twice, and the on-screen
 *      indicator disappears with it. The user is never left with a badge
 *      claiming a conversation is being watched when nothing is being read.
 *   3. The right-click path in `background.js` uses no selectors at all. When an
 *      adapter dies, the feature degrades to "select the messages and right-click"
 *      — which works on every chat app that has ever existed, including the ones
 *      with no adapter here.
 *
 * Nothing in this file makes a judgement, sends a request, or stores anything.
 * It converts DOM into `{text, incoming}` and stops.
 *
 * **Outgoing messages are read only so they can be labelled outgoing.** The
 * backend drops them before any pattern runs (`incoming_text` in
 * `services/scam/heuristics.py`). They are collected rather than skipped here
 * because a scam is a two-sided exchange and the *count* matters for knowing
 * whether the visible thread changed — but their content is never scored, and
 * the schema field that carries them exists to guarantee that.
 */

/** Never send more than this, regardless of how long the thread is. Matches
 *  MAX_MESSAGES in `services/scam/heuristics.py`; a larger request is rejected
 *  by the schema, so the cap belongs on both sides. */
const CHAT_MAX_MESSAGES = 40;

/** Per message, matching MAX_MESSAGE_CHARS on the backend. A longer "message"
 *  is a pasted document, which is Module 3's job. */
const CHAT_MAX_MESSAGE_CHARS = 2000;

/**
 * Pull readable text out of a message row.
 *
 * `innerText` rather than `textContent`: it respects `display:none`, and both
 * clients keep hidden accessibility labels and pre-rendered timestamps in the
 * tree. `textContent` would splice "10:42 AM" and screen-reader boilerplate into
 * the middle of the sentence — which then appears inside a quoted excerpt on the
 * warning panel, and a quote the user cannot find in their own chat window is
 * worse than no quote at all.
 */
function readText(node) {
  if (!node) return '';
  const text = (node.innerText || '').replace(/\s+$/, '');
  return text.length > CHAT_MAX_MESSAGE_CHARS ? text.slice(0, CHAT_MAX_MESSAGE_CHARS) : text;
}

/** Drop a trailing "12:04" / "12:04 PM" / "12:04 PM ✓✓" that both clients render
 *  inside the message bubble rather than beside it. */
function stripTrailingTimestamp(text) {
  return text.replace(/\s*\b\d{1,2}:\d{2}\s*(?:[AaPp]\.?[Mm]\.?)?\s*[✓✔️\s]*$/u, '').trim();
}

/**
 * Shared row-walker. Each adapter supplies its own selectors and nothing else.
 *
 * @param {{root: string, row: string, outgoing: string, text: string}} selectors
 * @returns {{ok: boolean, why: string, messages: Array<{text: string, incoming: boolean}>}}
 */
function collect(selectors) {
  const root = document.querySelector(selectors.root);
  if (!root) {
    // Not necessarily a break: the user may be on the chat list with no
    // conversation open. Reported as a reason, not an error, and the caller
    // treats "no root" as "nothing to do" rather than as a dead adapter.
    return { ok: false, why: 'no-conversation-open', messages: [] };
  }

  const rows = root.querySelectorAll(selectors.row);
  if (rows.length === 0) {
    return { ok: false, why: 'no-message-rows', messages: [] };
  }

  const messages = [];
  // Walk backwards: the end of a conversation is where a scam declares itself,
  // and if the thread is longer than the cap, the last forty messages are the
  // forty worth reading.
  const recent = Array.from(rows).slice(-CHAT_MAX_MESSAGES);
  for (const row of recent) {
    const body = row.querySelector(selectors.text) || row;
    const text = stripTrailingTimestamp(readText(body));
    if (!text) continue; // Sticker, voice note, image with no caption.
    messages.push({ text, incoming: !row.matches(selectors.outgoing) });
  }

  if (messages.length === 0) {
    // Rows existed and every one of them read as empty. That is a selector
    // problem, not a quiet chat, and it is the exact failure this return value
    // exists to make loud.
    return { ok: false, why: 'rows-had-no-text', messages: [] };
  }

  return { ok: true, why: '', messages };
}

/**
 * Registry, keyed by hostname.
 *
 * Deliberately small. Every entry is a maintenance liability, and the
 * selector-free right-click path already covers Discord, Slack, Instagram, and
 * anything else — so an adapter only earns its place where auto-watch adds
 * something the user could not easily do themselves, which means the two apps
 * where Indian chat fraud actually happens.
 */
const CHAT_ADAPTERS = {
  'web.whatsapp.com': {
    id: 'whatsapp',
    label: 'WhatsApp Web',
    read: () =>
      collect({
        root: '#main',
        row: 'div.message-in, div.message-out',
        outgoing: 'div.message-out',
        // The copyable-text span is the message body proper; quoted replies and
        // reactions live outside it. Falling back to the row (in `collect`)
        // keeps a class rename from producing zero messages outright.
        text: 'span.selectable-text, div.copyable-text',
      }),
  },

  'web.telegram.org': {
    id: 'telegram',
    label: 'Telegram Web',
    read: () =>
      collect({
        root: '.bubbles, .messages-container',
        row: '.bubble',
        outgoing: '.bubble.is-out',
        text: '.message',
      }),
  },
};

const SentinelChatAdapters = {
  MAX_MESSAGES: CHAT_MAX_MESSAGES,

  /** The adapter for a hostname, or null. Used by the popup to decide whether to
   *  offer the toggle at all, and by the content script to decide whether to
   *  observe anything. */
  forHost(hostname) {
    return CHAT_ADAPTERS[hostname] || null;
  },

  /** Hostnames with an adapter. The popup renders this list when the user is not
   *  on one of them, so "why is there no toggle here?" has an answer on screen. */
  hosts() {
    return Object.keys(CHAT_ADAPTERS);
  },

  // -- opt-in state --------------------------------------------------------
  //
  // Auto-watch reads messages written by somebody who never installed this
  // extension and never agreed to anything. That is the feature's real risk —
  // not a technical one — so consent is explicit, per surface, off by default,
  // and stored locally. There is no remote flag that could turn it on.

  /** @returns {Promise<boolean>} */
  async isWatching(hostname) {
    const stored = await chrome.storage.local.get('sentinel_scam_watch');
    const map = stored.sentinel_scam_watch || {};
    return map[hostname] === true;
  },

  /** @param {boolean} enabled */
  async setWatching(hostname, enabled) {
    const stored = await chrome.storage.local.get('sentinel_scam_watch');
    const map = stored.sentinel_scam_watch || {};
    if (enabled) map[hostname] = true;
    else delete map[hostname]; // Absent, not `false` — the default is off, and
    // storing the default would make an accidental
    // "true" the thing that survives a merge.
    await chrome.storage.local.set({ sentinel_scam_watch: map });
  },
};

globalThis.SentinelChatAdapters = SentinelChatAdapters;
