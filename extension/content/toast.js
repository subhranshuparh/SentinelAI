/**
 * Non-blocking warning UI.
 *
 * Three rules, each of which is a product decision rather than a styling one:
 *
 *   1. NEVER a modal. It appears while the user is mid-sentence. A dialog that
 *      steals focus would make SentinelAI the thing that interrupted them, and
 *      an interrupted user disables the tool rather than reading it.
 *   2. Calm by default. Red is reserved for critical/high. If every finding
 *      screams, users learn to dismiss without reading, and the one warning that
 *      mattered gets dismissed with the rest.
 *   3. Rendered in a shadow root. Host pages ship global CSS that would
 *      otherwise turn the panel invisible or unreadable.
 *
 * Copy is written for the least technical user in the target list — a senior
 * citizen typing into WhatsApp Web — so: no jargon, short sentences, and the
 * consequence stated before the instruction.
 */

const RISK_STYLES = {
  critical: { color: '#f87171', bg: 'rgba(248,113,113,0.12)', label: 'Critical risk', icon: '!' },
  high: { color: '#fb923c', bg: 'rgba(251,146,60,0.12)', label: 'High risk', icon: '!' },
  // Amber, not red. A phone number in a form is worth a note, not an alarm.
  medium: { color: '#fbbf24', bg: 'rgba(251,191,36,0.10)', label: 'Worth checking', icon: 'i' },
  low: { color: '#60a5fa', bg: 'rgba(96,165,250,0.10)', label: 'Low risk', icon: 'i' },
};

const SHADOW_STYLES = `
  :host { all: initial; }
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }

  .panel {
    pointer-events: auto;
    width: 360px;
    background: #12161f;
    border: 1px solid #253048;
    border-left: 4px solid var(--accent, #60a5fa);
    border-radius: 12px;
    padding: 14px 16px;
    color: #e6ebf5;
    box-shadow: 0 12px 32px rgba(0,0,0,0.45);
    margin-top: 10px;
    animation: slide-in 160ms ease-out;
  }
  @keyframes slide-in {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @media (prefers-reduced-motion: reduce) {
    .panel { animation: none; }
  }

  .head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .badge {
    width: 18px; height: 18px; border-radius: 50%;
    background: var(--accent); color: #0b0e14;
    font-size: 12px; font-weight: 700;
    display: flex; align-items: center; justify-content: center; flex: 0 0 auto;
  }
  .title { font-size: 14px; font-weight: 650; letter-spacing: -0.01em; }
  .risk  { margin-left: auto; font-size: 11px; color: var(--accent); font-weight: 600; }

  /* 13px is the floor. Part of the target audience is senior citizens, and a
     warning nobody can read is not a warning. */
  .reason { font-size: 13px; line-height: 1.5; color: #aab6cc; margin-bottom: 6px; }
  .why    { font-size: 13px; line-height: 1.5; color: #8794ad; margin-bottom: 10px; }

  .preview {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 13px; background: #0b0e14; border: 1px solid #1e2740;
    border-radius: 6px; padding: 7px 10px; margin-bottom: 12px;
    color: #cbd5e1; word-break: break-all;
  }
  .preview .arrow { color: #64748b; margin: 0 6px; }

  .meta { font-size: 11px; color: #64748b; margin-bottom: 10px; }

  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  button {
    font-size: 12.5px; font-weight: 600; padding: 7px 12px;
    border-radius: 7px; border: 1px solid #2b3752;
    background: #1a2133; color: #cbd5e1; cursor: pointer;
  }
  button:hover  { background: #222c44; }
  button:focus-visible { outline: 2px solid #60a5fa; outline-offset: 2px; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #0b0e14; }
  button.subtle  { background: transparent; border-color: transparent; color: #7c8aa5; margin-left: auto; }

  .offline {
    font-size: 12px; color: #fbbf24; background: rgba(251,191,36,0.08);
    border: 1px solid rgba(251,191,36,0.25); border-radius: 8px;
    padding: 8px 10px; pointer-events: auto; width: 300px;
  }

  /* --- QR panel (Module 9) ---------------------------------------------- */

  /* The destination gets the largest type in the panel, above the verdict and
     above the reasons. A QR code is unreadable to a human, and simply showing
     where it actually goes is most of the protection this feature provides —
     the score is the supporting detail, not the headline. */
  .dest {
    font-size: 14px; line-height: 1.45; font-weight: 600; color: #e6ebf5;
    background: #0b0e14; border: 1px solid #1e2740; border-left: 3px solid var(--accent);
    border-radius: 6px; padding: 10px 12px; margin-bottom: 10px;
    word-break: break-word;
  }

  .signals { list-style: none; margin: 0 0 10px; padding: 0; }
  .signals li {
    display: flex; gap: 8px; align-items: flex-start;
    font-size: 12.5px; line-height: 1.45; color: #aab6cc; margin-bottom: 5px;
  }
  .signals .dot {
    width: 6px; height: 6px; border-radius: 50%; flex: 0 0 auto; margin-top: 6px;
  }
  .signals .bad     .dot { background: #f87171; }
  .signals .unknown .dot { background: #94a3b8; }
  .signals .good    .dot { background: #4ade80; }
  /* Grey, not green: a row that says "we could not verify this" must not read
     like a row that says "we checked and it was fine". */
  .signals .unknown { color: #8794ad; }

  .working {
    display: flex; align-items: center; gap: 9px;
    font-size: 13px; color: #aab6cc;
  }
  .spinner {
    width: 13px; height: 13px; border-radius: 50%; flex: 0 0 auto;
    border: 2px solid #2b3752; border-top-color: #60a5fa;
    animation: spin 700ms linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    .spinner { animation: none; border-top-color: #60a5fa; }
  }

  /* --- Paste panel (Module 10) ------------------------------------------ */

  /* The destination line arrives ~300ms after the panel does. Reserving its
     height up front stops the buttons from jumping out from under a cursor
     that is already moving towards them — a layout shift on a panel with a
     "Paste anyway" button is a way to make somebody click the wrong thing. */
  .dest.pending { min-height: 40px; color: #7c8aa5; font-weight: 500; }
  .dest.never   { border-left-color: #f87171; }
  .dest.rarely  { border-left-color: #fb923c; }
  .dest.expected{ border-left-color: #4ade80; }
  .dest.unknown { border-left-color: #94a3b8; color: #8794ad; }

  /* --- Chat scam panel (Module 11) --------------------------------------- */

  /* The quoted line, styled as a quotation rather than as data. This is the
     single most important element on the panel: "this resembles an OTP fraud"
     is an assertion, and the sentence the scammer actually wrote is the
     evidence for it. Without the quote the user has to take the tool's word,
     and taking a stranger's word is the thing that got them here. */
  .quote {
    font-size: 13px; line-height: 1.5; color: #cbd5e1;
    background: #0b0e14; border: 1px solid #1e2740; border-left: 3px solid var(--accent);
    border-radius: 6px; padding: 9px 12px; margin-bottom: 10px;
    font-style: italic; word-break: break-word;
  }

  /* The standing indicator shown while a conversation is being watched.
     Small, fixed, and never hidden: auto-watch reads messages written by
     somebody who did not install this extension, so the user must be able to
     see at a glance that it is running. It is a claim, and a claim needs to be
     visible to be withdrawable. */
  .watch {
    pointer-events: auto;
    display: flex; align-items: center; gap: 7px;
    width: max-content; max-width: 300px; margin-top: 10px; margin-left: auto;
    font-size: 11.5px; font-weight: 600; letter-spacing: 0.01em;
    color: #93a3bd; background: rgba(18,22,31,0.92);
    border: 1px solid #253048; border-radius: 999px;
    padding: 5px 11px 5px 9px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.35);
  }
  .watch .pip {
    width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto;
    background: #4ade80;
  }
  /* Amber, and the words change too. A green pip while the backend is
     unreachable would be the indicator lying about the thing it exists to
     assert. */
  .watch.offline { color: #fbbf24; border-color: rgba(251,191,36,0.35); }
  .watch.offline .pip { background: #fbbf24; }

  /* --- Upload panel (Module 12) ------------------------------------------ */

  /* The file name, so a user removing one image from a three-image upload knows
     which one is being talked about. Truncated from the left, because the end of
     a filename ("...aadhaar-front.jpg") is the part that identifies it. */
  .file {
    font-size: 12px; color: #93a3bd; margin-bottom: 8px;
    direction: rtl; text-align: left; overflow: hidden;
    white-space: nowrap; text-overflow: ellipsis;
  }

  /* The OCR caveat. Small, permanent, and never omitted on a clean result —
     that is the case where it matters, because "SentinelAI found nothing" and
     "there is nothing in this image" are not the same sentence and only the
     first one is true. */
  .caveat {
    font-size: 11.5px; line-height: 1.45; color: #7c8aa5;
    border-top: 1px solid #1e2740; padding-top: 8px; margin-top: 10px;
  }
`;

/**
 * QR verdicts get their own palette, not the PII risk_level one.
 *
 * They need a fourth state the PII toast has never had to render: **safe**.
 * A typing warning only appears when something was found, so "nothing wrong"
 * is expressed by showing no panel at all. A QR check is explicitly asked for
 * by a right-click, so it must answer even when the answer is good — silence
 * there would look like a broken menu item.
 *
 * "unknown" is grey and says so in words. It is deliberately not green.
 */
const QR_STYLES = {
  dangerous: { color: '#f87171', label: 'Dangerous', icon: '!' },
  suspicious: { color: '#fb923c', label: 'Be careful', icon: '!' },
  unknown: { color: '#94a3b8', label: 'Not verified', icon: '?' },
  safe: { color: '#4ade80', label: 'Looks fine', icon: '✓' },
};

/**
 * What kind of thing the code turned out to be, in the user's words.
 *
 * The backend's `kind` is a machine token (`upi`, `vcard`). Showing it raw
 * would be the same mistake as putting `domain_age` on screen. The headline
 * matters most for `upi`: someone who was told they are *receiving* money needs
 * to read the words "payment request" before anything else on the panel.
 */
const QR_KIND_LABELS = {
  upi: 'UPI payment request',
  url: 'Web link',
  wifi: 'Wi-Fi network',
  vcard: 'Contact card',
  tel: 'Phone number',
  sms: 'Text message',
  mailto: 'Email address',
  geo: 'Map location',
  crypto: 'Cryptocurrency payment',
  text: 'Plain text',
};

/** One key for every QR panel, so a second right-click replaces the first and
 *  the result replaces its own loading state instead of stacking under it. */
const QR_KEY = '__qr__';

/** Same idea for held pastes: one at a time, and a second paste replaces the
 *  first rather than stacking two panels that both claim the clipboard. */
const PASTE_KEY = '__paste__';

/** One scam panel, and one standing watch indicator, at a time. */
const SCAM_KEY = '__scam__';
const WATCH_KEY = '__watch__';

/** One upload panel. A second file selection replaces the first — the earlier
 *  one described files the user has already moved on from. */
const UPLOAD_KEY = '__upload__';

/**
 * The sentence that rides on every screenshot result, including the clean ones.
 *
 * Required by the plan and, more to the point, required by honesty. OCR misses
 * handwriting, misses text at an angle, misses low-contrast overlays, and misses
 * anything below about ten pixels tall. A panel that said "no sensitive data
 * found" and stopped would be converting a limitation of Tesseract into a
 * statement about the user's file.
 *
 * Declared as a constant rather than typed into each panel so that it cannot be
 * present on the alarming results and quietly absent from the reassuring one,
 * which is the direction that mistake always goes.
 */
const OCR_CAVEAT =
  'SentinelAI reads screenshots as text and can miss handwriting or ' +
  'low-resolution images.';

/**
 * Chat verdicts share the QR palette's shape but not its words.
 *
 * "Looks fine" is deliberately not "safe". A conversation is a live thing: the
 * message that turns it into a fraud may not have been sent yet, and a panel
 * that says "safe" is making a promise about the next ten minutes that nothing
 * in this product can keep. Every label below describes what was read, not what
 * will happen.
 */
const SCAM_STYLES = {
  dangerous: { color: '#f87171', label: 'Known scam pattern', icon: '!' },
  suspicious: { color: '#fb923c', label: 'Does not add up', icon: '!' },
  unknown: { color: '#94a3b8', label: 'Not enough to judge', icon: '?' },
  safe: { color: '#4ade80', label: 'Nothing matched', icon: '✓' },
};

/**
 * The AI tier's scam family, in the user's words.
 *
 * The model returns a machine key from a fixed enum and nothing else — it never
 * writes a sentence that reaches this file. The mapping from key to English
 * happens here, which is what makes "the model cannot author user-facing copy"
 * a structural fact rather than a promise. An unrecognised key renders nothing
 * at all rather than falling through to the raw token.
 */
const SCAM_TYPE_LABELS = {
  otp_fraud: 'This resembles a common OTP fraud.',
  advance_fee: 'This resembles an advance-fee scam.',
  investment_fraud: 'This resembles an investment scam.',
  tech_support_fraud: 'This resembles a fake tech-support scam.',
  impersonation: 'This resembles someone impersonating a person or an office.',
  job_task_scam: 'This resembles a task or part-time job scam.',
  romance_fraud: 'This resembles a romance scam.',
};

const SentinelToast = {
  _host: null,
  _shadow: null,
  /** pii_type -> element, so re-scanning the same field replaces rather than stacks. */
  _active: new Map(),

  _ensureHost() {
    if (this._host && document.documentElement.contains(this._host)) return;

    this._host = document.createElement('div');
    this._host.id = 'sentinelai-toast-host';
    this._shadow = this._host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = SHADOW_STYLES;
    this._shadow.appendChild(style);

    document.documentElement.appendChild(this._host);
  },

  /**
   * Show one warning.
   *
   * @param {object} finding      A FindingOut from the backend.
   * @param {object} handlers     { onMask, onIgnore, onAlwaysAllow }
   */
  show(finding, handlers) {
    this._ensureHost();

    // Same type already on screen? Replace it. Typing "1234 5678 9013" one digit
    // at a time would otherwise queue five near-identical toasts.
    if (this._active.has(finding.pii_type)) {
      this._active.get(finding.pii_type).remove();
    }

    const style = RISK_STYLES[finding.risk_level] || RISK_STYLES.low;
    const panel = document.createElement('div');
    panel.className = 'panel';
    panel.style.setProperty('--accent', style.color);
    panel.setAttribute('role', 'alert');

    const confidencePct = Math.round(finding.confidence * 100);

    panel.innerHTML = `
      <div class="head">
        <span class="badge">${style.icon}</span>
        <span class="title"></span>
        <span class="risk">${style.label}</span>
      </div>
      <div class="reason"></div>
      <div class="why"></div>
      <div class="preview">
        <span class="masked"></span>
      </div>
      <div class="meta">${confidencePct}% confidence &middot; ${
        finding.detection_tier === 'regex' ? 'pattern + checksum' : 'context analysis'
      }</div>
      <div class="actions">
        <button class="primary" data-act="mask">Mask it</button>
        <button data-act="ignore">Not now</button>
        <button class="subtle" data-act="allow">Always allow here</button>
      </div>
    `;

    // textContent, never innerHTML, for anything derived from page content.
    // finding.label and the previews originate in text the user typed on an
    // arbitrary site; interpolating them into HTML would be a self-inflicted XSS
    // in a security tool.
    panel.querySelector('.title').textContent = `${finding.label} detected`;
    panel.querySelector('.reason').textContent = finding.reason;
    panel.querySelector('.why').textContent = finding.explanation;
    panel.querySelector('.masked').textContent = `Will become: ${finding.masked_preview}`;

    panel.querySelector('[data-act="mask"]').addEventListener('click', () => {
      handlers.onMask?.(finding);
      this._dismiss(finding.pii_type);
    });
    panel.querySelector('[data-act="ignore"]').addEventListener('click', () => {
      handlers.onIgnore?.(finding);
      this._dismiss(finding.pii_type);
    });
    panel.querySelector('[data-act="allow"]').addEventListener('click', () => {
      handlers.onAlwaysAllow?.(finding);
      this._dismiss(finding.pii_type);
    });

    this._shadow.appendChild(panel);
    this._active.set(finding.pii_type, panel);
  },

  _dismiss(piiType) {
    this._active.get(piiType)?.remove();
    this._active.delete(piiType);
  },

  /** Clear everything — called when the field is cleared or the value stops matching. */
  dismissAll() {
    this._active.forEach((el) => el.remove());
    this._active.clear();
  },

  /**
   * Backend unreachable.
   *
   * Shown once per page, deliberately. Silence here would be indistinguishable
   * from "nothing sensitive found", and a security tool that fails quietly is
   * worse than one that is obviously off.
   */
  showOffline() {
    this._notice('__offline__', 'SentinelAI is offline — typing is not being checked.');
  },

  /**
   * Pattern checks ran, the deeper context check did not.
   *
   * Same reasoning as showOffline, one level down. The backend answered and the
   * checksum tier is genuinely covering card and Aadhaar numbers — but the
   * semantic tier that catches addresses and travel plans timed out, so "no
   * warning" is weaker evidence than usual and the user should know which half
   * of the system is speaking.
   */
  showPartial() {
    this._notice(
      '__partial__',
      'Pattern checks ran. The deeper context check is unavailable right now.',
    );
  },

  // -------------------------------------------------------------------------
  // Module 9 — QR codes
  // -------------------------------------------------------------------------

  /** Guards against a spinner that never resolves. See `showQrChecking`. */
  _qrTimer: null,

  /** Replace whatever QR panel is on screen with a fresh, empty one. */
  _qrPanel(accent, assertive) {
    this._ensureHost();
    clearTimeout(this._qrTimer);
    this._active.get(QR_KEY)?.remove();

    const panel = document.createElement('div');
    panel.className = 'panel';
    panel.style.setProperty('--accent', accent);
    // "alert" interrupts a screen reader mid-sentence. Correct for a warning,
    // rude for "this looks fine" — and part of the audience for this product
    // uses a screen reader all day.
    panel.setAttribute('role', assertive ? 'alert' : 'status');

    this._shadow.appendChild(panel);
    this._active.set(QR_KEY, panel);
    return panel;
  },

  /** Wire the single Close button every QR panel carries. */
  _qrClose(panel) {
    panel.querySelector('[data-act="close"]').addEventListener('click', () => {
      clearTimeout(this._qrTimer);
      this._dismiss(QR_KEY);
    });
  },

  /**
   * The right-click has been received; the answer is being fetched.
   *
   * A URL QR runs the full site engine — Safe Browsing and a registry lookup —
   * which can take several seconds. Without this, a menu click that appears to
   * do nothing reads as a broken extension, and the user right-clicks again.
   *
   * The timeout is the important half. If the service worker is terminated
   * mid-flight the reply never arrives, and a spinner left running forever is a
   * lie of a particular kind: it says an answer is coming when none is.
   */
  showQrChecking() {
    const panel = this._qrPanel('#60a5fa', false);
    panel.innerHTML = `
      <div class="working">
        <span class="spinner"></span>
        <span class="label"></span>
      </div>
    `;
    panel.querySelector('.label').textContent = 'Checking where this QR code goes…';

    this._qrTimer = setTimeout(() => {
      this.showQrUnavailable('SentinelAI did not get an answer in time. This QR code was not checked.');
    }, 20000);
  },

  /**
   * The check did not happen — image unreadable, no code in it, backend down.
   *
   * Deliberately shaped like the other panels rather than like a quiet
   * footnote. A user who asked a security tool a direct question and got a
   * blank space will assume the answer was "fine".
   *
   * @param {string} message A sentence written in background.js. Never a raw
   *                         error string, and never rendered as HTML.
   */
  showQrUnavailable(message) {
    const panel = this._qrPanel('#94a3b8', false);
    panel.innerHTML = `
      <div class="head">
        <span class="badge">?</span>
        <span class="title">QR code</span>
        <span class="risk">Not checked</span>
      </div>
      <div class="reason"></div>
      <div class="actions">
        <button class="primary" data-act="close">Close</button>
      </div>
    `;
    panel.querySelector('.reason').textContent =
      message || 'SentinelAI could not check this QR code.';
    this._qrClose(panel);
  },

  /**
   * The verdict.
   *
   * Layout order is the argument: **destination first**, then what it means,
   * then what to do, then the itemised reasons. A QR code is opaque to a human
   * being, so the single most useful thing this panel can do is state plainly
   * where the code actually points — before any score, because the score is
   * only worth reading once the user knows what is being scored.
   *
   * @param {object} result A QrCheckResponse from the backend.
   */
  showQr(result) {
    const style = QR_STYLES[result?.verdict] || QR_STYLES.unknown;
    const assertive = result?.verdict === 'dangerous' || result?.verdict === 'suspicious';
    const panel = this._qrPanel(style.color, assertive);

    panel.innerHTML = `
      <div class="head">
        <span class="badge"></span>
        <span class="title"></span>
        <span class="risk"></span>
      </div>
      <div class="dest"></div>
      <div class="reason"></div>
      <div class="why"></div>
      <ul class="signals"></ul>
      <div class="meta"></div>
      <div class="actions">
        <button class="primary" data-act="close">Close</button>
      </div>
    `;

    // textContent throughout. Every string below originates in a QR code that
    // an attacker printed — the payee name, the note, the host. Interpolating
    // any of it into HTML would be a self-inflicted XSS in the one panel whose
    // entire job is to be trustworthy.
    panel.querySelector('.badge').textContent = style.icon;
    panel.querySelector('.title').textContent = QR_KIND_LABELS[result?.kind] || 'QR code';
    panel.querySelector('.risk').textContent = style.label;
    panel.querySelector('.dest').textContent = result?.destination || 'Destination unknown';
    panel.querySelector('.reason').textContent = result?.summary || '';
    panel.querySelector('.why').textContent = result?.recommendation || '';

    // Four rows, matching the cap the dashboard uses. A list long enough to
    // scroll is a list nobody reads, and the backend has already sorted
    // findings above the rows that merely confirm something was checked.
    const list = panel.querySelector('.signals');
    const signals = Array.isArray(result?.signals) ? result.signals.slice(0, 4) : [];
    for (const signal of signals) {
      const row = document.createElement('li');
      row.className = ['bad', 'unknown', 'good'].includes(signal?.weight) ? signal.weight : 'unknown';
      const dot = document.createElement('span');
      dot.className = 'dot';
      const text = document.createElement('span');
      text.textContent = signal?.detail || '';
      row.append(dot, text);
      list.appendChild(row);
    }

    const confidence = typeof result?.confidence === 'number' ? Math.round(result.confidence * 100) : null;
    panel.querySelector('.meta').textContent =
      confidence === null
        ? 'Checked without a network lookup'
        : `${confidence}% confidence · risk ${result?.risk_score ?? '—'}/100`;

    this._qrClose(panel);
  },

  // -------------------------------------------------------------------------
  // Module 10 — held pastes
  // -------------------------------------------------------------------------

  /**
   * A paste has been blocked and is waiting on the user.
   *
   * This is the one panel in the product that is genuinely blocking, and it is
   * blocking because the alternative is worse: an advisory note shown *after*
   * an AWS key lands in a Discord box is a description of an incident, not a
   * prevention of one. The rule it still keeps is the important one — it is not
   * a modal, it does not steal focus, and the caret stays exactly where the
   * user left it, so "Cancel paste" costs one click and nothing else.
   *
   * Copy avoids the word "blocked". The paste is *held*: the user is being
   * asked, not overruled, and the button that completes it is right there.
   *
   * @param {{label: string, maskedPreview: string}} local  From the synchronous
   *        pre-filter. Deliberately not from the backend — this panel has to
   *        render with the network down.
   * @param {{onMask: Function, onCancel: Function, onPasteAnyway: Function}} handlers
   */
  showPaste(local, handlers) {
    this._ensureHost();
    this._active.get(PASTE_KEY)?.remove();

    const panel = document.createElement('div');
    panel.className = 'panel';
    panel.style.setProperty('--accent', '#fb923c');
    // Assertive: this one is interrupting an action the user started, so a
    // screen-reader user needs to hear it now rather than at the next pause.
    panel.setAttribute('role', 'alert');

    panel.innerHTML = `
      <div class="head">
        <span class="badge">!</span>
        <span class="title"></span>
        <span class="risk">Paste held</span>
      </div>
      <div class="preview"><span class="masked"></span></div>
      <div class="dest pending"></div>
      <div class="actions">
        <button class="primary" data-act="mask">Paste masked</button>
        <button data-act="cancel">Cancel paste</button>
        <button class="subtle" data-act="anyway">Paste anyway</button>
      </div>
    `;

    // textContent throughout: `maskedPreview` is derived from clipboard content
    // of entirely unknown origin.
    panel.querySelector('.title').textContent = `That looks like a ${local.label}`;
    panel.querySelector('.masked').textContent = local.maskedPreview;
    panel.querySelector('.dest').textContent = 'Checking where this is going…';

    const wire = (act, handler) => {
      panel.querySelector(`[data-act="${act}"]`).addEventListener('click', () => {
        this._dismiss(PASTE_KEY);
        handler?.();
      });
    };
    wire('mask', handlers.onMask);
    wire('cancel', handlers.onCancel);
    wire('anyway', handlers.onPasteAnyway);

    this._shadow.appendChild(panel);
    this._active.set(PASTE_KEY, panel);
  },

  /**
   * Fill in the destination line once the backend answers.
   *
   * A no-op when the panel is gone — the user was faster than the network,
   * which is the common case on a local backend and is fine.
   *
   * @param {string} sentence Authored server-side in `destinations.py`.
   * @param {string} fit      never | rarely | expected | unknown. Drives the
   *                          stripe colour only; the sentence carries the
   *                          meaning, because a colour is not a sentence.
   */
  setPasteDestination(sentence, fit) {
    const line = this._active.get(PASTE_KEY)?.querySelector('.dest');
    if (!line) return;
    const known = ['never', 'rarely', 'expected', 'unknown'].includes(fit) ? fit : 'unknown';
    line.className = `dest ${known}`;
    line.textContent = sentence;
  },

  /** Used when a paste completes itself — see the `expected` path in clipboard.js. */
  dismissPaste() {
    this._dismiss(PASTE_KEY);
  },

  // -------------------------------------------------------------------------
  // Module 11 — chat scams
  // -------------------------------------------------------------------------

  /** Guards against a spinner that never resolves, exactly as `_qrTimer` does. */
  _scamTimer: null,

  _scamPanel(accent, assertive) {
    this._ensureHost();
    clearTimeout(this._scamTimer);
    this._active.get(SCAM_KEY)?.remove();

    const panel = document.createElement('div');
    panel.className = 'panel';
    panel.style.setProperty('--accent', accent);
    panel.setAttribute('role', assertive ? 'alert' : 'status');

    this._shadow.appendChild(panel);
    this._active.set(SCAM_KEY, panel);
    return panel;
  },

  /** The right-click has been received. Only the selection path shows this —
   *  auto-watch runs unattended and has nobody waiting on a spinner. */
  showScamChecking() {
    const panel = this._scamPanel('#60a5fa', false);
    panel.innerHTML = `
      <div class="working">
        <span class="spinner"></span>
        <span class="label"></span>
      </div>
    `;
    panel.querySelector('.label').textContent = 'Reading this conversation…';

    this._scamTimer = setTimeout(() => {
      this.showScamUnavailable(
        'SentinelAI did not get an answer in time. These messages were not checked.',
      );
    }, 20000);
  },

  /**
   * The check did not happen.
   *
   * @param {string} message Written in background.js, never a raw error string.
   */
  showScamUnavailable(message) {
    const panel = this._scamPanel('#94a3b8', false);
    panel.innerHTML = `
      <div class="head">
        <span class="badge">?</span>
        <span class="title">These messages</span>
        <span class="risk">Not checked</span>
      </div>
      <div class="reason"></div>
      <div class="actions">
        <button class="primary" data-act="close">Close</button>
      </div>
    `;
    panel.querySelector('.reason').textContent =
      message || 'SentinelAI could not check these messages.';
    panel.querySelector('[data-act="close"]').addEventListener('click', () => {
      clearTimeout(this._scamTimer);
      this._dismiss(SCAM_KEY);
    });
  },

  /**
   * The verdict.
   *
   * Reading order is the argument, and it is different from the QR panel's. A QR
   * code leads with its destination because the destination is the hidden fact.
   * A conversation hides nothing — the user has read every word — so this panel
   * leads with **the pattern being named**: "This resembles a common OTP fraud"
   * is the thing they could not see, because recognising a script requires
   * having seen it before, which is precisely what a first-time victim has not.
   *
   * Then the quote, so the claim is anchored to a line they recognise. Then what
   * to do, authored in Python. Then the itemised reasons.
   *
   * @param {object} result   A ScamAnalyzeResponse from the backend.
   * @param {{source: string}} options `watch` for the observer path, `selection`
   *        for the right-click. Only changes the footnote — an unattended
   *        warning should say why it appeared unprompted.
   */
  showScam(result, options = {}) {
    const style = SCAM_STYLES[result?.verdict] || SCAM_STYLES.unknown;
    const assertive = result?.verdict === 'dangerous' || result?.verdict === 'suspicious';
    const panel = this._scamPanel(style.color, assertive);

    panel.innerHTML = `
      <div class="head">
        <span class="badge"></span>
        <span class="title"></span>
        <span class="risk"></span>
      </div>
      <div class="reason"></div>
      <div class="quote" hidden></div>
      <div class="why"></div>
      <ul class="signals"></ul>
      <div class="meta"></div>
      <div class="actions">
        <button class="primary" data-act="close">Close</button>
      </div>
    `;

    panel.querySelector('.badge').textContent = style.icon;
    panel.querySelector('.title').textContent = 'Message check';
    panel.querySelector('.risk').textContent = style.label;

    // The named pattern first when the AI tier answered, the deterministic
    // summary otherwise. Both are Python-authored strings looked up by key.
    const named = SCAM_TYPE_LABELS[result?.scam_type];
    panel.querySelector('.reason').textContent =
      named && assertive ? named : result?.summary || '';

    // The quote. Guaranteed by the backend to be a literal substring of the
    // messages that were sent — anything that was not is discarded there rather
    // than shown here. textContent, because it is attacker-authored by
    // definition: this is a stranger's message being rendered inside a security
    // warning, which is the highest-value injection target in the product.
    const evidence = (Array.isArray(result?.signals) ? result.signals : []).find(
      (s) => s?.weight === 'bad' && s?.evidence,
    );
    if (evidence) {
      const quote = panel.querySelector('.quote');
      quote.hidden = false;
      quote.textContent = `“${evidence.evidence}”`;
    }

    panel.querySelector('.why').textContent = result?.recommendation || '';

    const list = panel.querySelector('.signals');
    const signals = (Array.isArray(result?.signals) ? result.signals : []).slice(0, 4);
    for (const signal of signals) {
      const row = document.createElement('li');
      row.className = ['bad', 'unknown', 'good'].includes(signal?.weight)
        ? signal.weight
        : 'unknown';
      const dot = document.createElement('span');
      dot.className = 'dot';
      const text = document.createElement('span');
      text.textContent = signal?.detail || '';
      row.append(dot, text);
      list.appendChild(row);
    }

    // Two facts, both of which change how much the verdict is worth: how
    // confident it is, and whether the AI tier answered at all. The second is
    // stated in words rather than implied by its absence.
    const confidence =
      typeof result?.confidence === 'number' ? Math.round(result.confidence * 100) : null;
    const parts = [];
    if (confidence !== null) parts.push(`${confidence}% confidence`);
    parts.push(result?.heuristics_only ? 'pattern checks only' : 'pattern + AI reading');
    if (options.source === 'watch') parts.push('shown because chat watching is on');
    panel.querySelector('.meta').textContent = parts.join(' · ');

    panel.querySelector('[data-act="close"]').addEventListener('click', () => {
      clearTimeout(this._scamTimer);
      this._dismiss(SCAM_KEY);
    });
  },

  /**
   * Show the standing "this conversation is being watched" marker.
   *
   * Not dismissible, and that is the point. Auto-watch reads a third party's
   * messages; the user consented to it in the popup and can withdraw it there,
   * but they must not be able to hide the reminder while leaving the reading
   * switched on. A silent watcher is the thing this indicator exists to prevent
   * the product from becoming.
   */
  showChatWatch(surfaceLabel) {
    this._ensureHost();
    this._active.get(WATCH_KEY)?.remove();

    const pill = document.createElement('div');
    pill.className = 'watch';
    pill.setAttribute('role', 'status');

    const pip = document.createElement('span');
    pip.className = 'pip';
    const text = document.createElement('span');
    text.className = 'watch-label';

    // Kept on the element rather than in a closure: `setChatWatchOffline` has to
    // restore this exact sentence after an outage, and reconstructing it from
    // whatever the label currently says would mean parsing the offline text back
    // into a surface name.
    pill.dataset.surface = surfaceLabel;
    text.textContent = `SentinelAI is watching ${surfaceLabel} for scams`;

    pill.append(pip, text);
    this._shadow.appendChild(pill);
    this._active.set(WATCH_KEY, pill);
  },

  /** The backend stopped answering while watching. The indicator must stop
   *  implying that anything is being checked. */
  setChatWatchOffline(offline) {
    const pill = this._active.get(WATCH_KEY);
    if (!pill) return;
    pill.className = offline ? 'watch offline' : 'watch';
    pill.querySelector('.watch-label').textContent = offline
      ? 'SentinelAI is offline — these messages are not being checked'
      : `SentinelAI is watching ${pill.dataset.surface || 'this chat'} for scams`;
  },

  hideChatWatch() {
    this._dismiss(WATCH_KEY);
  },

  // -------------------------------------------------------------------------
  // Module 12 — screenshot uploads
  // -------------------------------------------------------------------------

  _uploadTimer: null,

  _uploadPanel(accent, assertive) {
    this._ensureHost();
    clearTimeout(this._uploadTimer);
    this._active.get(UPLOAD_KEY)?.remove();

    const panel = document.createElement('div');
    panel.className = 'panel';
    panel.style.setProperty('--accent', accent);
    panel.setAttribute('role', assertive ? 'alert' : 'status');

    this._shadow.appendChild(panel);
    this._active.set(UPLOAD_KEY, panel);
    return panel;
  },

  /**
   * Files have been chosen and are being read.
   *
   * Shown unconditionally, unlike most of this file, because OCR takes seconds:
   * starting the wasm engine is a two-to-four-second cost the first time. A
   * user who attached a screenshot and saw nothing happen would assume nothing
   * was happening, and the panel that eventually appeared would look like it had
   * come out of nowhere.
   *
   * @param {number} count How many images are being read.
   */
  showUploadChecking(count) {
    const panel = this._uploadPanel('#60a5fa', false);
    panel.innerHTML = `
      <div class="working">
        <span class="spinner"></span>
        <span class="label"></span>
      </div>
    `;
    panel.querySelector('.label').textContent =
      count === 1 ? 'Reading the text in this image…' : `Reading the text in ${count} images…`;

    // Same guard as the QR and scam spinners. The engine has its own timeouts,
    // but they are inside a different document — if that document dies the reply
    // never arrives and this is what stops the spinner from turning forever.
    this._uploadTimer = setTimeout(() => {
      this.showUploadUnavailable(
        'SentinelAI did not finish reading in time, so these images were not checked.',
      );
    }, 90000);
  },

  /**
   * The read did not happen, or did not finish.
   *
   * @param {string} message Written in background.js, never a raw error string.
   */
  showUploadUnavailable(message) {
    const panel = this._uploadPanel('#94a3b8', false);
    panel.innerHTML = `
      <div class="head">
        <span class="badge">?</span>
        <span class="title">This image</span>
        <span class="risk">Not checked</span>
      </div>
      <div class="reason"></div>
      <div class="caveat"></div>
      <div class="actions">
        <button class="primary" data-act="close">Close</button>
      </div>
    `;
    panel.querySelector('.reason').textContent =
      message || 'SentinelAI could not check this image.';
    panel.querySelector('.caveat').textContent = OCR_CAVEAT;
    panel.querySelector('[data-act="close"]').addEventListener('click', () => {
      clearTimeout(this._uploadTimer);
      this._dismiss(UPLOAD_KEY);
    });
  },

  /**
   * Something sensitive was found in a picture that is about to be uploaded.
   *
   * The reading order is the whole argument, and it is the reverse of the QR
   * panel's. A QR code leads with its destination because the destination is the
   * hidden fact. Here the hidden fact is **what is in the file** — the user knows
   * perfectly well where they are uploading it — so the masked value comes first,
   * quoted from the image, followed by which file it came out of.
   *
   * "Remove from upload" is the primary action and is honest about its scope: it
   * takes the file out of the field. On a site that uploads on a later button
   * press, which is nearly all of them, that prevents the upload outright. On a
   * site that uploads the instant a file is chosen, the bytes are already gone
   * and the panel is a notification. That asymmetry cannot be fixed from a
   * content script and is documented rather than papered over.
   *
   * @param {{findings: Array<object>, files: string[], poorRead: boolean,
   *          checkedCount: number, skippedCount: number}} summary
   * @param {{onRemove: Function, onKeep: Function}} handlers
   */
  showUpload(summary, handlers) {
    const findings = Array.isArray(summary?.findings) ? summary.findings : [];
    const worst = findings[0] || null;
    const style = RISK_STYLES[worst?.risk_level] || RISK_STYLES.high;
    const panel = this._uploadPanel(style.color, true);

    panel.innerHTML = `
      <div class="head">
        <span class="badge">!</span>
        <span class="title"></span>
        <span class="risk"></span>
      </div>
      <div class="preview"><span class="masked"></span></div>
      <div class="file" hidden></div>
      <div class="reason"></div>
      <ul class="signals"></ul>
      <div class="meta"></div>
      <div class="actions">
        <button class="primary" data-act="remove">Remove from upload</button>
        <button class="subtle" data-act="keep">Upload anyway</button>
      </div>
      <div class="caveat"></div>
    `;

    panel.querySelector('.title').textContent = worst
      ? `${worst.label} in this image`
      : 'Something sensitive in this image';
    panel.querySelector('.risk').textContent = style.label;
    // textContent, as everywhere: this string came out of a neural network
    // reading pixels the extension did not choose.
    panel.querySelector('.masked').textContent = worst?.masked_preview || '';

    const files = Array.isArray(summary?.files) ? summary.files.filter(Boolean) : [];
    if (files.length > 0) {
      const line = panel.querySelector('.file');
      line.hidden = false;
      line.textContent = files.length === 1 ? files[0] : files.join(', ');
    }

    panel.querySelector('.reason').textContent = worst?.explanation || worst?.reason || '';

    // Every distinct thing found, not just the worst. An Aadhaar card screenshot
    // carries a name, a date of birth and a number, and the user deciding whether
    // to send it needs the whole list — "one finding" would understate it.
    const list = panel.querySelector('.signals');
    const seen = new Set();
    for (const finding of findings) {
      if (seen.has(finding?.pii_type)) continue;
      seen.add(finding?.pii_type);
      if (seen.size > 4) break;
      const row = document.createElement('li');
      row.className = 'bad';
      const dot = document.createElement('span');
      dot.className = 'dot';
      const text = document.createElement('span');
      text.textContent = `${finding?.label || 'Sensitive data'} — ${finding?.masked_preview || ''}`;
      row.append(dot, text);
      list.appendChild(row);
    }

    // The three facts that qualify the verdict, each stated only when true.
    const parts = [];
    if (typeof worst?.confidence === 'number') {
      parts.push(`${Math.round(worst.confidence * 100)}% confidence`);
    }
    if (summary?.poorRead) parts.push('the image was hard to read');
    if (summary?.skippedCount > 0) {
      // The cap, said out loud. See MAX_IMAGES_PER_CHECK in background.js.
      parts.push(
        `checked the first ${summary.checkedCount} of ` +
          `${summary.checkedCount + summary.skippedCount} images`,
      );
    }
    panel.querySelector('.meta').textContent = parts.join(' · ');
    panel.querySelector('.caveat').textContent = OCR_CAVEAT;

    const wire = (act, handler) => {
      panel.querySelector(`[data-act="${act}"]`).addEventListener('click', () => {
        clearTimeout(this._uploadTimer);
        this._dismiss(UPLOAD_KEY);
        handler?.();
      });
    };
    wire('remove', handlers?.onRemove);
    wire('keep', handlers?.onKeep);
  },

  /**
   * Nothing was found, but the read was poor enough that saying so matters.
   *
   * The only "we found nothing" panel in the extension. Every other clean result
   * in this product is expressed as silence, and that is right, because silence
   * is the default state and therefore not a claim. This one is different: the
   * user attached a file and OCR produced a low-confidence transcript of it, so
   * an absence of warning would be read as an all-clear on evidence that does
   * not support one.
   */
  showUploadPoorRead() {
    const panel = this._uploadPanel('#94a3b8', false);
    panel.innerHTML = `
      <div class="head">
        <span class="badge">?</span>
        <span class="title">This image was hard to read</span>
        <span class="risk">Partly checked</span>
      </div>
      <div class="reason">
        SentinelAI found nothing sensitive, but the text in this image came out
        unclear — so that is not a clean bill of health.
      </div>
      <div class="caveat"></div>
      <div class="actions">
        <button class="primary" data-act="close">Close</button>
      </div>
    `;
    panel.querySelector('.caveat').textContent = OCR_CAVEAT;
    panel.querySelector('[data-act="close"]').addEventListener('click', () => {
      clearTimeout(this._uploadTimer);
      this._dismiss(UPLOAD_KEY);
    });
  },

  /** Used when the batch came back clean and legible — see upload.js. */
  dismissUpload() {
    clearTimeout(this._uploadTimer);
    this._dismiss(UPLOAD_KEY);
  },

  /** Shared one-per-page banner. */
  _notice(key, message) {
    this._ensureHost();
    if (this._active.has(key)) return;

    const banner = document.createElement('div');
    banner.className = 'offline';
    banner.textContent = message;
    this._shadow.appendChild(banner);
    this._active.set(key, banner);

    setTimeout(() => this._dismiss(key), 6000);
  },
};

globalThis.SentinelToast = SentinelToast;
