/**
 * Popup controller.
 *
 * The popup is a read-only status surface plus one write: un-muting a warning.
 * It never triggers a scan and never sends page content anywhere — it renders
 * what the content script and service worker already recorded.
 */

const VERDICT_COPY = {
  safe: 'No problems found',
  suspicious: 'Be careful here',
  dangerous: 'This site looks dangerous',
  // Phrased as a limitation of the tool, not a property of the site. "Unknown"
  // alone reads as vaguely accusatory about a site that may be perfectly fine.
  unknown: 'Not checked',
};

/** Human labels for pii_type. Kept here rather than fetched: the popup must
 *  render instantly and correctly even with the backend down. */
const TYPE_LABELS = {
  aadhaar: 'Aadhaar',
  pan: 'PAN',
  credit_card: 'Card number',
  bank_account: 'Bank account',
  ifsc: 'IFSC code',
  upi_id: 'UPI ID',
  passport: 'Passport',
  phone: 'Phone number',
  email: 'Email',
  dob: 'Date of birth',
  api_key: 'API key',
  jwt: 'Access token',
  password: 'Password',
  coordinates: 'Location',
};

function labelFor(piiType) {
  return TYPE_LABELS[piiType] || piiType;
}

// ---------------------------------------------------------------------------
// Backend status
// ---------------------------------------------------------------------------

async function renderStatus() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const tierNote = document.getElementById('tier-note');

  const health = await globalThis.SentinelAPI.health();

  if (health === null) {
    dot.className = 'dot offline';
    text.textContent = 'Backend offline';
    // Blunt on purpose. A user who thinks they are protected when they are not
    // is in a worse position than one who knows the tool is down.
    tierNote.textContent = 'Not protecting you right now';
    return;
  }

  dot.className = 'dot online';
  text.textContent = 'Protecting you';

  // health returns capability booleans only — never key values. See main.py,
  // which nests them under `tiers`. Reading `health.gemini_tier` here (as this
  // did) is silently undefined, so the popup reported "offline mode" even with
  // the semantic tier fully armed.
  tierNote.textContent = health.tiers?.gemini
    ? 'Pattern + AI context checks'
    : 'Pattern checks (offline mode)';
}

// ---------------------------------------------------------------------------
// Current site
// ---------------------------------------------------------------------------

/** Marker per reason weight. Glyphs, not colour alone — roughly 1 in 12 men has
 *  a colour vision deficiency, and red/green is the exact pair they lose. */
const WEIGHT_MARK = {
  bad: { glyph: '!', className: 'reason bad' },
  good: { glyph: '✓', className: 'reason good' },
  unknown: { glyph: '?', className: 'reason unknown' },
};

/**
 * Render the itemised reasons.
 *
 * Built with createElement + textContent throughout. The sentences originate in
 * the backend, but they describe a hostname the user navigated to, and an
 * attacker picks that hostname — so it is untrusted text and never becomes
 * innerHTML.
 */
function renderReasons(listEl, reasons) {
  listEl.replaceChildren();

  for (const reason of reasons) {
    const mark = WEIGHT_MARK[reason?.weight] || WEIGHT_MARK.unknown;

    const item = document.createElement('li');
    item.className = mark.className;

    const glyph = document.createElement('span');
    glyph.className = 'reason-mark';
    glyph.textContent = mark.glyph;
    glyph.setAttribute('aria-hidden', 'true');

    const detail = document.createElement('span');
    detail.className = 'reason-detail';
    detail.textContent = reason?.detail || '';

    item.append(glyph, detail);
    listEl.appendChild(item);
  }
}

async function renderSite() {
  const hostEl = document.getElementById('site-host');
  const verdictEl = document.getElementById('site-verdict');
  const reasonEl = document.getElementById('site-reason');
  const reasonsEl = document.getElementById('site-reasons');
  const confidenceEl = document.getElementById('site-confidence');

  const clear = () => {
    reasonsEl.replaceChildren();
    confidenceEl.textContent = '';
  };

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    hostEl.textContent = 'Browser page';
    verdictEl.textContent = 'Nothing to check here';
    verdictEl.className = 'verdict unknown';
    reasonEl.textContent = '';
    clear();
    return;
  }

  hostEl.textContent = new URL(tab.url).hostname;

  const stored = await chrome.storage.session.get(`verdict_${tab.id}`);
  const cached = stored[`verdict_${tab.id}`];

  // Guard against a stale verdict: the tab id is stable across navigations, so
  // without the URL check the popup would confidently show the previous site's
  // rating for the current one.
  if (!cached || cached.url !== tab.url) {
    verdictEl.textContent = VERDICT_COPY.unknown;
    verdictEl.className = 'verdict unknown';
    reasonEl.textContent = 'Reload the page to check this site.';
    clear();
    return;
  }

  verdictEl.textContent = VERDICT_COPY[cached.verdict] || VERDICT_COPY.unknown;
  verdictEl.className = `verdict ${cached.verdict}`;
  reasonEl.textContent = cached.summary || '';

  renderReasons(reasonsEl, Array.isArray(cached.reasons) ? cached.reasons : []);

  // Confidence is only mentioned when it is low enough to matter. Printing
  // "confidence: 100%" next to every clean site is noise that trains the user to
  // stop reading the line — so it stays silent until it has something to say.
  const skipped = (cached.reasons || []).filter((r) => r?.weight === 'unknown').length;
  confidenceEl.textContent = skipped > 0
    ? `Based on a partial check — ${skipped} of 3 checks could not run.`
    : '';
}

// ---------------------------------------------------------------------------
// Session stats
// ---------------------------------------------------------------------------

async function renderStats() {
  const stored = await chrome.storage.local.get('sentinel_session_stats');
  const stats = stored.sentinel_session_stats || {};
  document.getElementById('stat-detected').textContent = stats.detected || 0;
  document.getElementById('stat-masked').textContent = stats.masked || 0;
  document.getElementById('stat-allowlisted').textContent = stats.allowlisted || 0;
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

async function renderAllowlist() {
  const body = document.getElementById('allowlist-body');
  const allowlist = await globalThis.SentinelAllowlist.all();
  const entries = Object.entries(allowlist).filter(([, types]) => types.length > 0);

  body.replaceChildren();

  if (entries.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'Nothing muted. You will be warned everywhere.';
    body.appendChild(empty);
    return;
  }

  for (const [origin, types] of entries) {
    for (const piiType of types) {
      const row = document.createElement('div');
      row.className = 'mute-row';

      const typeEl = document.createElement('span');
      typeEl.className = 'mute-type';
      typeEl.textContent = labelFor(piiType);

      const originEl = document.createElement('span');
      originEl.className = 'mute-origin';
      // textContent, not innerHTML: the origin comes from whatever page the user
      // was on, and a hostile site should not get to inject markup into the
      // extension's own UI.
      originEl.textContent = origin.replace(/^https?:\/\//, '');

      const button = document.createElement('button');
      button.className = 'unmute';
      button.textContent = 'Unmute';
      button.addEventListener('click', async () => {
        await globalThis.SentinelAllowlist.revoke(origin, piiType);
        await renderAllowlist();
      });

      row.append(typeEl, originEl, button);
      body.appendChild(row);
    }
  }
}

// ---------------------------------------------------------------------------
// Chat scam watching (Module 11)
// ---------------------------------------------------------------------------

/**
 * Render the per-surface opt-in.
 *
 * Three states, and the third one is the reason this is not a single checkbox:
 *
 *   * On a supported chat host — a real toggle, unchecked unless the user
 *     turned it on before.
 *   * On any other page — no toggle, and a sentence saying the right-click
 *     check works here instead. A greyed-out switch would read as "this is
 *     broken"; naming the alternative turns a missing feature into a usable one.
 *   * Not on a web page at all — nothing to offer.
 *
 * The toggle is never checked by default and there is no "enable everywhere"
 * option anywhere in this file. Auto-watch reads messages written by a third
 * party, and a per-surface decision is the smallest one the user can make.
 */
async function renderWatch() {
  const body = document.getElementById('watch-body');
  body.replaceChildren();

  const say = (text, className = 'empty') => {
    const p = document.createElement('p');
    p.className = className;
    p.textContent = text;
    body.appendChild(p);
  };

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    say('Open a chat app to turn this on.');
    return;
  }

  const hostname = new URL(tab.url).hostname;
  const adapter = globalThis.SentinelChatAdapters.forHost(hostname);

  if (!adapter) {
    say(
      'Automatic watching is not available on this site. Select any message, ' +
        'right-click it, and choose "Check this message with SentinelAI" — that ' +
        'works everywhere.',
    );
    return;
  }

  const enabled = await globalThis.SentinelChatAdapters.isWatching(hostname);

  const row = document.createElement('label');
  row.className = 'watch-row';

  const box = document.createElement('input');
  box.type = 'checkbox';
  box.id = 'watch-toggle';
  box.checked = enabled;

  const text = document.createElement('span');
  text.className = 'watch-text';
  // textContent: the label comes from our own registry, but the habit is the
  // point — nothing in this popup is ever assembled as HTML.
  text.textContent = `Watch ${adapter.label} conversations for scams`;

  box.addEventListener('change', async () => {
    await globalThis.SentinelChatAdapters.setWatching(hostname, box.checked);
    // The content script is listening on chrome.storage.onChanged, so it starts
    // or stops on its own — including in other tabs of the same app. Nothing is
    // messaged directly, which means the state cannot get out of step with the
    // stored setting.
  });

  row.append(box, text);
  body.appendChild(row);
}

// ---------------------------------------------------------------------------
// Password check (Module 4) — k-anonymity
// ---------------------------------------------------------------------------

/**
 * SHA-1 the password in the browser and return the digest as uppercase hex.
 *
 * SHA-1 is chosen here despite being cryptographically broken, and that is not
 * an oversight: the Pwned Passwords corpus is indexed by SHA-1, so any other
 * algorithm cannot query it. It is being used as a lookup key against a public
 * dataset, not to protect anything — collision resistance is irrelevant when
 * the value it guards never leaves this function.
 *
 * @param {string} password
 * @returns {Promise<string>} 40 uppercase hex characters.
 */
async function sha1Hex(password) {
  const bytes = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** Render one line into the result box, with a state class. */
function setPasswordResult(state, lines) {
  const box = document.getElementById('pw-result');
  box.className = `pw-result ${state}`;
  box.hidden = false;
  box.replaceChildren();

  for (const [index, line] of lines.entries()) {
    const p = document.createElement('p');
    // First line is the verdict, the rest is reasoning. textContent throughout:
    // the strings come from our own backend, but the label inside them was typed
    // by the user and there is no reason for it to be parsed as markup.
    p.className = index === 0 ? 'pw-verdict' : 'pw-detail';
    p.textContent = line;
    box.appendChild(p);
  }
}

/**
 * The whole check, start to finish.
 *
 * Order matters here and is worth reading closely: the password is hashed, the
 * field is cleared, and only then does anything touch the network. If the
 * request fails, there is no password left anywhere to leak — not in the DOM,
 * not in a closure that outlives the click.
 */
async function runPasswordCheck() {
  const input = document.getElementById('pw-input');
  const labelInput = document.getElementById('pw-label');
  const button = document.getElementById('pw-check');

  const password = input.value;
  const label = labelInput.value.trim();

  if (!password) {
    setPasswordResult('warn', ['Type a password first.']);
    return;
  }

  button.disabled = true;
  setPasswordResult('busy', ['Checking…']);

  try {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    // Cleared before the first network call, not after it. The input is the only
    // place the plaintext exists, and it should stop existing at the earliest
    // possible moment rather than the most convenient one.
    input.value = '';

    const range = await globalThis.SentinelAPI.pwnedRange(prefix);
    // The match happens here, on the user's machine, against a list of ~800
    // candidates. The backend never learns which one — or whether any — matched.
    const breachCount = range.suffixes?.[suffix] || 0;

    const verdict = await globalThis.SentinelAPI.recordPasswordCheck({
      hashPrefix: prefix,
      breachCount,
      label,
    });

    setPasswordResult(verdict.breached ? 'bad' : 'good', [
      verdict.breached
        ? `Found in ${verdict.breach_count.toLocaleString()} breached accounts`
        : 'Not found in any known breach',
      verdict.reason,
      verdict.recommendation,
    ]);
  } catch (_error) {
    // "Could not check" — explicitly not "you are fine". Same invariant the site
    // badge and the risk engine enforce: a check that did not run never renders
    // as a clean result.
    setPasswordResult('warn', [
      'Could not check',
      'The breach database could not be reached, so this password was not checked. Nothing was sent.',
    ]);
  } finally {
    button.disabled = false;
  }
}

function wirePasswordCheck() {
  document.getElementById('pw-check').addEventListener('click', runPasswordCheck);
  document.getElementById('pw-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') runPasswordCheck();
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

wirePasswordCheck();

// Rendered concurrently: the health probe is the only slow step, and blocking
// the stats and allowlist on it would leave the popup blank for a second every
// time the backend is down.
Promise.all([renderStatus(), renderSite(), renderStats(), renderWatch(), renderAllowlist()]);
