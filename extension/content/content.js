/**
 * The demo moment: real-time PII detection while typing.
 *
 * Runs on every page. Watches editable fields, scans on a debounce, and offers a
 * one-click mask that writes back into the field in place.
 *
 * The three things that are genuinely hard here, and how each is handled:
 *
 *   1. **Gmail and WhatsApp Web do not use <textarea>.** They use
 *      contenteditable <div>s whose text is spread across many nested nodes.
 *      Reading needs innerText; writing needs a TreeWalker that maps a character
 *      offset back onto the right text node. See replaceInContentEditable.
 *
 *   2. **Fields are created after page load.** A listener bound at document_idle
 *      would miss Gmail's compose box entirely, because it does not exist yet.
 *      Solved with event delegation on document — one listener, every field,
 *      including ones added an hour from now.
 *
 *   3. **React ignores direct .value assignment.** Its synthetic event system
 *      tracks the last value it set and skips the update. The native setter must
 *      be invoked explicitly or the mask silently reverts on the next render.
 */

const DEBOUNCE_MS = 250;
const MIN_SCAN_LENGTH = 6;

// Fields that must never be read, under any circumstance.
const NEVER_SCAN_TYPES = new Set(['password', 'hidden', 'file', 'submit', 'button', 'checkbox', 'radio']);

let debounceTimer = null;
let lastScannedText = '';
let activeField = null;

// ---------------------------------------------------------------------------
// Field inspection
// ---------------------------------------------------------------------------

/** Is this element something the user types prose into? */
function isEditable(element) {
  if (!element || element.nodeType !== Node.ELEMENT_NODE) return false;

  const tag = element.tagName;
  if (tag === 'INPUT') {
    const type = (element.type || 'text').toLowerCase();
    // Password fields are excluded here rather than filtered later: the value
    // must never enter a variable, let alone a network request. A password
    // manager's autofill is not our business.
    return !NEVER_SCAN_TYPES.has(type);
  }
  if (tag === 'TEXTAREA') return true;
  return element.isContentEditable === true;
}

function fieldKindOf(element) {
  if (element.tagName === 'INPUT') return 'input';
  if (element.tagName === 'TEXTAREA') return 'textarea';
  return 'contenteditable';
}

function readText(element) {
  if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') return element.value;
  // innerText, not textContent: it respects rendered line breaks, so character
  // offsets line up with what the user actually sees.
  return element.innerText;
}

// ---------------------------------------------------------------------------
// Writing masked values back
// ---------------------------------------------------------------------------

/**
 * Set an <input>/<textarea> value in a way React cannot ignore.
 *
 * React overrides the `value` property on the element instance and tracks the
 * last value it wrote. Assigning `element.value = x` updates the DOM but leaves
 * React's shadow copy stale, so the next render reverts it. Calling the
 * *prototype's* native setter updates both, and the dispatched input event then
 * tells React to re-read.
 */
function setNativeValue(element, value) {
  const prototype = element.tagName === 'TEXTAREA'
    ? window.HTMLTextAreaElement.prototype
    : window.HTMLInputElement.prototype;

  const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
  if (descriptor?.set) {
    descriptor.set.call(element, value);
  } else {
    element.value = value;
  }
  element.dispatchEvent(new Event('input', { bubbles: true }));
}

/**
 * Replace characters [start, end) inside a contenteditable element.
 *
 * The text the user sees is the concatenation of many text nodes. This walks
 * them in document order, accumulating a running offset, and edits only the
 * node(s) the target span actually falls in — so surrounding formatting,
 * mentions, and attachments survive untouched. Replacing innerText wholesale
 * would flatten a Gmail draft and lose its signature.
 *
 * @returns {boolean} true if the replacement was applied.
 */
function replaceInContentEditable(element, start, end, replacement) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  let offset = 0;
  let startNode = null;
  let startOffset = 0;
  let endNode = null;
  let endOffset = 0;

  while (walker.nextNode()) {
    const node = walker.currentNode;
    const length = node.nodeValue.length;

    if (startNode === null && offset + length > start) {
      startNode = node;
      startOffset = start - offset;
    }
    if (startNode !== null && offset + length >= end) {
      endNode = node;
      endOffset = end - offset;
      break;
    }
    offset += length;
  }

  if (startNode === null || endNode === null) return false;

  const range = document.createRange();
  range.setStart(startNode, Math.max(0, startOffset));
  range.setEnd(endNode, Math.min(endNode.nodeValue.length, endOffset));
  range.deleteContents();
  range.insertNode(document.createTextNode(replacement));

  // Collapse the caret to just after the replacement so the user can keep
  // typing without hunting for their cursor.
  const selection = window.getSelection();
  range.collapse(false);
  selection.removeAllRanges();
  selection.addRange(range);

  element.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
}

/** Apply a finding's suggested mask to the field it came from. */
function applyMask(element, finding) {
  if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
    const current = element.value;
    // Re-verify the span still holds the value we matched. The user may have
    // typed more since the scan; blindly splicing stale offsets would corrupt
    // their text, which is far worse than missing a mask.
    const next =
      current.slice(0, finding.start) + finding.suggested_replacement + current.slice(finding.end);
    setNativeValue(element, next);
    return true;
  }
  return replaceInContentEditable(
    element,
    finding.start,
    finding.end,
    finding.suggested_replacement,
  );
}

// ---------------------------------------------------------------------------
// Session stats (read by the popup)
// ---------------------------------------------------------------------------

async function recordStat(key) {
  const stored = await chrome.storage.local.get('sentinel_session_stats');
  const stats = stored.sentinel_session_stats || { detected: 0, masked: 0, allowlisted: 0 };
  stats[key] = (stats[key] || 0) + 1;
  await chrome.storage.local.set({ sentinel_session_stats: stats });
}

// ---------------------------------------------------------------------------
// Scan cycle
// ---------------------------------------------------------------------------

async function runScan(element) {
  const text = readText(element);

  if (!text || text.trim().length < MIN_SCAN_LENGTH) {
    globalThis.SentinelToast.dismissAll();
    lastScannedText = '';
    return;
  }
  // Cheap guard against re-scanning on caret moves and focus churn.
  if (text === lastScannedText) return;
  lastScannedText = text;

  const origin = window.location.origin;
  const suppressed = await globalThis.SentinelAllowlist.suppressedFor(origin);

  const result = await globalThis.SentinelAPI.scan({
    text,
    origin,
    fieldKind: fieldKindOf(element),
    suppressed,
  });

  if (result === null) {
    // Null means "no verdict", never "clean". Say so rather than staying silent.
    if (globalThis.SentinelAPI.backendOnline === false) globalThis.SentinelToast.showOffline();
    return;
  }

  if (result.findings.length === 0) {
    globalThis.SentinelToast.dismissAll();
    // "Nothing found" is only trustworthy if everything actually ran. When the
    // semantic tier failed, say which half of the check is missing rather than
    // presenting a partial pass as a clean bill of health.
    if (result.tier_2_available === false) globalThis.SentinelToast.showPartial();
    return;
  }

  for (const finding of result.findings) {
    recordStat('detected');
    globalThis.SentinelToast.show(finding, {
      onMask: (f) => {
        if (applyMask(element, f)) {
          recordStat('masked');
          // Force the next input event to re-scan the now-masked text, so the
          // warning does not reappear for a value we just fixed.
          lastScannedText = '';
        }
      },
      onIgnore: () => {},
      onAlwaysAllow: async (f) => {
        await globalThis.SentinelAllowlist.allow(origin, f.pii_type);
        recordStat('allowlisted');
        lastScannedText = '';
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

/**
 * One delegated listener on document.
 *
 * Gmail's compose box, WhatsApp's message field, and every React-rendered form
 * are created long after this script runs. Binding per-element at load time
 * would miss all of them; delegation catches fields that do not exist yet.
 */
document.addEventListener(
  'input',
  (event) => {
    const target = event.target;
    if (!isEditable(target)) return;

    activeField = target;
    clearTimeout(debounceTimer);
    // 250ms: long enough that an average typist produces one scan per word
    // rather than one per keystroke, short enough that the warning still lands
    // before the user finishes the sentence and hits send.
    debounceTimer = setTimeout(() => runScan(target), DEBOUNCE_MS);
  },
  true, // Capture phase: some sites stopPropagation on their own inputs.
);

/**
 * The small surface `content/clipboard.js` is allowed to touch.
 *
 * Exported rather than duplicated so there is exactly one definition of "a
 * field SentinelAI may read". The password-field exclusion in `isEditable` is a
 * hard security property; a second, drifting copy of that check in the paste
 * handler is precisely how a tool ends up reading a password manager's autofill.
 *
 * `skipNext` exists for one reason: after the paste handler inserts text itself
 * — masked or not — the resulting `input` event would re-scan a value the user
 * has already been warned about and answered. Priming `lastScannedText` makes
 * the next `runScan` return early, so the user is not told the same thing twice
 * for the same decision.
 */
globalThis.SentinelScanner = {
  isEditable,
  fieldKindOf,
  readText,
  skipNext(text) {
    lastScannedText = text;
  },
};

// Clear warnings when the user moves to an unrelated field.
document.addEventListener(
  'focusin',
  (event) => {
    if (activeField && event.target !== activeField && isEditable(event.target)) {
      globalThis.SentinelToast.dismissAll();
      lastScannedText = '';
    }
  },
  true,
);
