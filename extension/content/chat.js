/**
 * Page-side half of Module 11.
 *
 * Two entry points, and the split between them is the whole design:
 *
 *   1. **Right-click a selection → "Check this message".** Selector-free, works
 *      on Discord, Slack, Instagram, a forum, an SMS bridge, anything. It cannot
 *      break when a chat client reships its DOM, and it reads only what the user
 *      deliberately highlighted. This is the path that always works.
 *
 *   2. **Auto-watch.** A MutationObserver over a supported thread, so the
 *      warning arrives while the conversation is happening rather than after the
 *      user has already been persuaded. This is the path that impresses, and it
 *      is **off until switched on, per surface, in the popup**.
 *
 * Why auto-watch is opt-in when nothing else in this extension is: every other
 * module reads what *the user* typed, pasted, or clicked. This one reads what
 * somebody else wrote. The other party to a WhatsApp conversation did not
 * install SentinelAI and cannot be asked. Defaulting that on would be a decision
 * made about a third party by a tool they never chose, so the switch stays off,
 * lives on one host at a time, and shows a visible marker for as long as it is
 * running — the user should never have to remember it is on.
 *
 * Nothing here decides anything. It collects text, hands it to the backend, and
 * renders the sentence the backend wrote.
 */

(() => {
  /** How long the thread must be quiet before a check runs. A chat fires dozens
   *  of mutations per message — read receipts, typing indicators, timestamp
   *  re-renders — and checking on each would be a request per keystroke of
   *  somebody else's typing. */
  const SETTLE_MS = 2500;

  /** Consecutive read failures before the adapter is switched off. One is a
   *  transient render; two in a row on a page with visible messages is a broken
   *  selector, and the honest response is to stop claiming to watch. */
  const MAX_READ_FAILURES = 2;

  const host = location.hostname;
  const adapter = globalThis.SentinelChatAdapters?.forHost(host) || null;

  let observer = null;
  let settleTimer = null;
  let readFailures = 0;
  let inFlight = false;

  /** Fingerprint of the last conversation actually sent, so an unchanged thread
   *  is not re-checked every time a read receipt ticks over. */
  let lastSent = '';
  /** Fingerprint of the last conversation the user was warned about. Re-warning
   *  about a thread they already dismissed is how a tool trains people to close
   *  it without reading. */
  let lastWarned = '';

  /** Cheap, order-sensitive fingerprint. Not a hash for security purposes — it
   *  never leaves this frame and only has to answer "is this the same text". */
  function fingerprint(messages) {
    let value = 0;
    const joined = messages.map((m) => (m.incoming ? '<' : '>') + m.text).join('\n');
    for (let i = 0; i < joined.length; i += 1) {
      value = (value * 31 + joined.charCodeAt(i)) | 0;
    }
    return `${joined.length}:${value}`;
  }

  // -------------------------------------------------------------------------
  // Auto-watch
  // -------------------------------------------------------------------------

  function stopWatching(reason) {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    clearTimeout(settleTimer);
    globalThis.SentinelToast.hideChatWatch();
    if (reason) {
      // Loud, in the page console, naming the surface. A silent adapter failure
      // is indistinguishable from a safe conversation, which is the one thing
      // this codebase never lets a failed check look like.
      console.warn(
        `SentinelAI: chat watching disabled on ${host} — ${reason}. ` +
          'Select the messages and right-click "Check this message with SentinelAI" instead.',
      );
    }
  }

  async function runCheck() {
    if (inFlight || !adapter) return;

    const reading = adapter.read();

    if (!reading.ok) {
      // An empty chat list is not a failure; a page full of bubbles that reads
      // as zero messages is.
      if (reading.why === 'no-conversation-open') return;
      readFailures += 1;
      if (readFailures >= MAX_READ_FAILURES) {
        stopWatching(`could not read messages (${reading.why})`);
      }
      return;
    }
    readFailures = 0;

    const incoming = reading.messages.filter((m) => m.incoming);
    if (incoming.length === 0) return; // Only the user has spoken. Module 1's job.

    const mark = fingerprint(reading.messages);
    if (mark === lastSent) return;
    lastSent = mark;

    inFlight = true;
    try {
      const result = await globalThis.SentinelAPI.analyzeScam({
        messages: reading.messages,
        surface: adapter.id,
      });

      // Null means no verdict — backend down, timeout, rate limited. Auto-watch
      // stays silent here rather than showing a "could not check" panel: the
      // user did not ask a question, so there is no unanswered question to
      // report, and a banner on every message while the backend is off is how
      // the feature gets switched back off for good. The indicator itself is the
      // standing claim, and `showChatWatch` marks it offline instead.
      if (!result) {
        globalThis.SentinelToast.setChatWatchOffline(true);
        return;
      }
      globalThis.SentinelToast.setChatWatchOffline(false);

      // Only speak up when there is something to say. "safe" and "unknown" are
      // real answers to a question the user asked by right-clicking — but nobody
      // asked here, and a green banner on an ordinary conversation is noise that
      // costs the red one its meaning.
      if (result.verdict !== 'dangerous' && result.verdict !== 'suspicious') return;
      if (mark === lastWarned) return;
      lastWarned = mark;

      globalThis.SentinelToast.showScam(result, { source: 'watch' });
    } finally {
      inFlight = false;
    }
  }

  function startWatching() {
    if (observer || !adapter) return;

    // Observed at the document root rather than at the thread container: both
    // clients tear down and rebuild that container when the user switches
    // conversation, and an observer bound to the old node would silently stop
    // seeing anything — which reads exactly like a chat with no scam in it.
    observer = new MutationObserver(() => {
      clearTimeout(settleTimer);
      settleTimer = setTimeout(runCheck, SETTLE_MS);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    globalThis.SentinelToast.showChatWatch(adapter.label);

    // One immediate pass, so switching the toggle on mid-conversation checks the
    // thread already on screen instead of waiting for the scammer's next line.
    clearTimeout(settleTimer);
    settleTimer = setTimeout(runCheck, 400);
  }

  async function syncWatchState() {
    if (!adapter) return;
    const wanted = await globalThis.SentinelChatAdapters.isWatching(host);
    if (wanted) startWatching();
    else stopWatching('');
  }

  // The toggle lives in the popup, which is a different context, so the switch
  // is observed rather than passed. This also means turning it off takes effect
  // in every open tab of that surface at once, which is the behaviour somebody
  // reaching for the off switch expects.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.sentinel_scam_watch) syncWatchState();
  });

  syncWatchState();

  // -------------------------------------------------------------------------
  // Right-click path
  // -------------------------------------------------------------------------

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Only this extension. A page cannot reach a content script listener without
    // `externally_connectable`, which is not declared — the check costs a line
    // and the alternative is trusting that forever.
    if (sender.id !== chrome.runtime.id) return false;
    if (message?.type !== 'sentinel:scam') return false;

    const state = message.payload || {};
    if (state.state === 'checking') {
      globalThis.SentinelToast.showScamChecking();
    } else if (state.state === 'failed') {
      globalThis.SentinelToast.showScamUnavailable(state.message);
    } else if (state.state === 'result' && state.result) {
      // Shown whatever the verdict — including "safe" and "unknown". The user
      // asked a direct question with a right-click, and a question that gets no
      // visible answer reads as "nothing wrong".
      globalThis.SentinelToast.showScam(state.result, { source: 'selection' });
    }
    sendResponse({ shown: true });
    return false;
  });
})();
