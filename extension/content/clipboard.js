/**
 * Module 10 — Clipboard Guardian.
 *
 * The typing scanner in content.js does fire on paste, but it is late and
 * blind. Late, because by the time the debounce elapses the secret is already
 * in the field and, on a chat surface, one Enter away from being sent. Blind,
 * because a finding says *what* was found and never *where it was going* — and
 * an AWS key in the AWS console is a person doing their job while the same key
 * in Discord is an incident.
 *
 * ## The constraint that shapes this file
 *
 * `preventDefault()` on a paste event is only honoured **synchronously**. The
 * moment this handler awaits anything, the browser has already inserted the
 * text and there is nothing left to prevent. But the real scan is a network
 * call. Those two facts are irreconcilable, so the feature is split in two:
 *
 *   1. a **synchronous pre-filter** over prefix-anchored credential shapes.
 *      Pure regex, no `await`, no network, works with the backend dead. This is
 *      what actually blocks the paste, and it only fires on strings whose shape
 *      is unambiguous — a checksum-grade decision, because cancelling somebody's
 *      paste on a guess is not acceptable;
 *   2. the **existing async scan**, which then fills the destination sentence
 *      into the panel that is already on screen.
 *
 * Everything the pre-filter does not recognise is allowed through untouched and
 * picked up by the debounced scanner exactly as before. Nothing else on the web
 * pays a latency tax for this feature.
 *
 * ## Why the patterns are duplicated here, and why that is safe
 *
 * `backend/app/services/pii/detectors.py` is the source of truth. These are a
 * strict subset of it — the branches of the `api_key` and `jwt` detectors that
 * are anchored on a distinctive literal prefix. `backend/tests/test_destinations.py`
 * reads *this file*, extracts the `prefix` fields below, and asserts every one
 * is still a key of `API_KEY_PREFIXES` (or the JWT prefix). The two cannot drift
 * silently; the suite goes red the day someone edits one and not the other.
 */

(() => {
  /**
   * Upper bound on the synchronous regex scan.
   *
   * This runs inside a paste handler, blocking the browser. A user pasting a
   * 40 MB log file must not feel it. Beyond this cut the async scanner still
   * applies — up to its own 20,000-character server-side cap — so the coverage
   * gap is "credentials past 100 KB into a very large paste", which is real and
   * is stated here rather than hidden.
   */
  const MAX_PREFILTER_CHARS = 100000;

  /**
   * How long a legitimate paste is allowed to wait for the backend before the
   * user has to click. Short on purpose: this window only exists so that a
   * paste into a place the key *belongs* completes without an interruption.
   * Past this, the panel stays up and the decision is the user's.
   */
  const AUTO_ALLOW_BUDGET_MS = 1500;

  /**
   * Prefix-anchored credential shapes.
   *
   * `prefix` is not used at runtime — the regex already encodes it. It is
   * declared so the backend parity test has something unambiguous to extract,
   * and so a reader can see the provider list without parsing a regex.
   */
  const BLOCKING_PATTERNS = [
    { prefix: 'AKIA', detector: 'api_key', label: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
    { prefix: 'ASIA', detector: 'api_key', label: 'AWS temporary key', re: /\bASIA[0-9A-Z]{16}\b/ },
    { prefix: 'AIza', detector: 'api_key', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
    { prefix: 'ghp_', detector: 'api_key', label: 'GitHub token', re: /\bghp_[A-Za-z0-9]{36,}\b/ },
    { prefix: 'gho_', detector: 'api_key', label: 'GitHub token', re: /\bgho_[A-Za-z0-9]{36,}\b/ },
    { prefix: 'ghu_', detector: 'api_key', label: 'GitHub token', re: /\bghu_[A-Za-z0-9]{36,}\b/ },
    { prefix: 'ghs_', detector: 'api_key', label: 'GitHub token', re: /\bghs_[A-Za-z0-9]{36,}\b/ },
    { prefix: 'sk_l', detector: 'api_key', label: 'Stripe secret key', re: /\bsk_live_[0-9a-zA-Z]{16,}\b/ },
    { prefix: 'sk_t', detector: 'api_key', label: 'Stripe secret key', re: /\bsk_test_[0-9a-zA-Z]{16,}\b/ },
    { prefix: 'sk-p', detector: 'api_key', label: 'OpenAI API key', re: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/ },
    { prefix: 'sk-', detector: 'api_key', label: 'OpenAI API key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
    { prefix: 'xoxb', detector: 'api_key', label: 'Slack token', re: /\bxoxb-[0-9A-Za-z-]{10,}\b/ },
    { prefix: 'xoxp', detector: 'api_key', label: 'Slack token', re: /\bxoxp-[0-9A-Za-z-]{10,}\b/ },
    { prefix: 'xoxa', detector: 'api_key', label: 'Slack token', re: /\bxoxa-[0-9A-Za-z-]{10,}\b/ },
    { prefix: 'xoxs', detector: 'api_key', label: 'Slack token', re: /\bxoxs-[0-9A-Za-z-]{10,}\b/ },
    { prefix: 'xoxo', detector: 'api_key', label: 'Slack token', re: /\bxoxo-[0-9A-Za-z-]{10,}\b/ },
    {
      prefix: 'eyJ',
      detector: 'jwt',
      label: 'session token',
      re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
    },
  ];

  /**
   * Mask a credential locally, without waiting for the backend.
   *
   * Keeps the first four characters so the user can still tell *which* key it
   * was — the provider prefix is the part that identifies it and the part that
   * is not a secret. Everything after is replaced with a fixed-width run rather
   * than a length-preserving one: the length of a secret is itself a small hint.
   */
  function maskCredential(value) {
    return `${value.slice(0, 4)}${'•'.repeat(16)}`;
  }

  /** First blocking match in `text`, or null. Synchronous and bounded. */
  function firstCredentialIn(text) {
    const window = text.length > MAX_PREFILTER_CHARS ? text.slice(0, MAX_PREFILTER_CHARS) : text;
    for (const pattern of BLOCKING_PATTERNS) {
      const match = pattern.re.exec(window);
      if (match) return { pattern, value: match[0], index: match.index };
    }
    return null;
  }

  /** Server-side cap on `ScanRequest.text`. Mirrored here so the request that
   *  fills in the destination is never rejected as too long. */
  const MAX_SCAN_CHARS = 20000;

  /**
   * A window of a very long paste, centred on the credential.
   *
   * Truncating from the front would be the obvious implementation and the wrong
   * one: a key 60,000 characters into a config dump would be cut away, the
   * backend would find nothing, and the panel would report "could not grade
   * that" for a paste it had already blocked. Centring keeps the surrounding
   * prose too, which is what the semantic tier needs to be worth calling.
   */
  function excerptAround(text, index, length) {
    if (text.length <= MAX_SCAN_CHARS) return text;
    const margin = Math.max(0, Math.floor((MAX_SCAN_CHARS - length) / 2));
    const start = Math.max(0, index - margin);
    return text.slice(start, start + MAX_SCAN_CHARS);
  }

  // -------------------------------------------------------------------------
  // Inserting text ourselves
  // -------------------------------------------------------------------------

  /**
   * Insert `text` at the caret, as though the user had pasted it.
   *
   * `document.execCommand('insertText')` is formally deprecated and is still
   * the correct tool here, for three reasons no replacement offers:
   *
   *   - it inserts at the caret in a contenteditable without any of the
   *     TreeWalker arithmetic that `replaceInContentEditable` needs, because the
   *     selection is already exactly where the paste was going;
   *   - it pushes onto the browser's native undo stack, so Ctrl+Z after
   *     "Paste anyway" behaves the way the user expects;
   *   - it emits real `beforeinput`/`input` events, which is what makes React
   *     and Draft.js-based editors (Gmail, WhatsApp Web) see the change.
   *
   * The fallback path exists because execCommand returns false in a few
   * editors that intercept it. It only covers input/textarea — a contenteditable
   * that refuses execCommand is left untouched, which loses the paste but never
   * corrupts the document.
   */
  function insertAtCaret(element, text) {
    if (document.execCommand && document.execCommand('insertText', false, text)) return true;

    if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
      const start = element.selectionStart ?? element.value.length;
      const end = element.selectionEnd ?? start;
      const next = element.value.slice(0, start) + text + element.value.slice(end);

      const prototype =
        element.tagName === 'TEXTAREA'
          ? window.HTMLTextAreaElement.prototype
          : window.HTMLInputElement.prototype;
      const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
      if (descriptor?.set) descriptor.set.call(element, next);
      else element.value = next;

      const caret = start + text.length;
      element.setSelectionRange?.(caret, caret);
      element.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    }
    return false;
  }

  /**
   * Complete a held paste and stop the typing scanner from re-warning about it.
   *
   * The `skipNext` call is why this is a function rather than three call sites:
   * forgetting it anywhere would produce a second, identical toast for a
   * decision the user just made, and a tool that repeats itself gets dismissed
   * without being read.
   */
  function completePaste(element, text) {
    const inserted = insertAtCaret(element, text);
    if (inserted) {
      globalThis.SentinelScanner?.skipNext(globalThis.SentinelScanner.readText(element));
    }
    return inserted;
  }

  // -------------------------------------------------------------------------
  // The handler
  // -------------------------------------------------------------------------

  /** Increments on every held paste. See the comment at its only write site. */
  let pasteToken = 0;

  /**
   * Ask the backend where this was going, and finish the panel.
   *
   * Runs after the paste has already been blocked, so nothing here is on a
   * critical path. Three outcomes, and none of them is silence:
   *
   *   - a destination note arrives -> the panel gains a sentence naming the site;
   *   - the fit is `expected` and the user has not moved -> the paste completes
   *     itself and the panel disappears. Interrupting somebody pasting a key
   *     into the console that key is *for* is exactly the over-alerting that
   *     trains people to ignore the tool;
   *   - the backend is unreachable -> the panel says so. It does not quietly
   *     drop the destination line, because an absent line reads as "fine".
   */
  async function annotateDestination(element, held, panelStillOpen) {
    const origin = window.location.origin;
    const started = Date.now();

    const result = await globalThis.SentinelAPI.scan({
      text: held.excerpt,
      origin,
      fieldKind: 'paste',
      suppressed: await globalThis.SentinelAllowlist.suppressedFor(origin),
    });

    if (!panelStillOpen()) return;

    if (result === null || !result.destination) {
      globalThis.SentinelToast.setPasteDestination(
        'SentinelAI could not check where this was going.',
        'unknown',
      );
      return;
    }

    // The finding that matches what we blocked on, falling back to the worst
    // one the backend saw. The backend may legitimately find more than the
    // pre-filter did — it runs fourteen detectors, not seventeen prefixes.
    const finding =
      result.findings.find((f) => f.pii_type === held.detector) || result.findings[0] || null;
    const note = finding?.destination_note || null;
    const fit = finding?.destination_fit || 'unknown';

    if (note === null) {
      globalThis.SentinelToast.setPasteDestination(
        `Going to ${result.destination.name}. SentinelAI could not grade that.`,
        'unknown',
      );
      return;
    }

    if (
      fit === 'expected' &&
      Date.now() - started < AUTO_ALLOW_BUDGET_MS &&
      document.activeElement === element
    ) {
      // The caret is still where it was and the answer came back fast. Honour
      // the paste the user asked for and get out of the way.
      globalThis.SentinelToast.dismissPaste();
      completePaste(element, held.text);
      return;
    }

    globalThis.SentinelToast.setPasteDestination(note, fit);
  }

  /**
   * One delegated listener, capture phase.
   *
   * Capture matters more here than for `input`: chat apps routinely attach
   * their own paste handlers to support image upload, and several call
   * `stopPropagation`. A bubble-phase listener would never run on the exact
   * surfaces this feature exists for.
   */
  document.addEventListener(
    'paste',
    (event) => {
      const element = event.target;
      // `isEditable` is imported, not reimplemented: it is the single place
      // that excludes `type="password"`, and the clipboard must never be read
      // when the target is one.
      if (!globalThis.SentinelScanner?.isEditable(element)) return;

      const text = event.clipboardData?.getData('text/plain');
      if (!text) return;

      const hit = firstCredentialIn(text);
      if (hit === null) return; // Not certain enough to block. The scanner will look.

      // Past this point the paste does not happen unless the user says so.
      event.preventDefault();
      event.stopPropagation();

      const held = {
        text,
        detector: hit.pattern.detector,
        excerpt: excerptAround(text, hit.index, hit.value.length),
      };

      // A second paste replaces the first panel. Without this token the first
      // paste's late-arriving destination sentence would land in the second
      // paste's panel and describe the wrong secret.
      const token = ++pasteToken;
      let open = true;
      const panelStillOpen = () => open && token === pasteToken;
      const close = () => {
        open = false;
      };

      globalThis.SentinelToast.showPaste(
        {
          label: hit.pattern.label,
          maskedPreview: maskCredential(hit.value),
        },
        {
          onMask: () => {
            close();
            completePaste(element, text.replace(hit.value, maskCredential(hit.value)));
          },
          onCancel: () => {
            close();
            // Nothing to undo: the paste was never applied. Return focus so the
            // user can carry on typing where they were.
            element.focus?.();
          },
          onPasteAnyway: () => {
            close();
            completePaste(element, text);
          },
        },
      );

      annotateDestination(element, held, panelStillOpen);
    },
    true,
  );
})();
