/**
 * Sample-value chips for the test harness.
 *
 * Kept in a separate file rather than inline because the harness is loaded as a
 * normal web page, and getting into the habit of inline scripts is how an
 * inline script eventually ends up somewhere it breaks CSP.
 *
 * Every value here is fabricated. The Aadhaar and card numbers satisfy their
 * checksums so the detectors actually fire, but they are not issued to anyone.
 * Putting a real government ID in a test fixture is the exact mistake this
 * whole product exists to prevent.
 */

const SAMPLES = [
  { label: 'Aadhaar', value: '2345 6789 9014', note: 'Verhoeff-valid' },
  { label: 'Card', value: '4111 1111 1111 1111', note: 'Luhn-valid test Visa' },
  { label: 'PAN', value: 'ABCDE1234F' },
  { label: 'IFSC + account', value: 'IFSC HDFC0001234 account number 123456789012' },
  { label: 'Phone', value: '+91 98765 43210' },
  { label: 'Email', value: 'ravi.kumar@example.com' },
  { label: 'UPI', value: 'ravi@okhdfcbank' },
  { label: 'API key', value: 'sk-proj-AbCdEf0123456789AbCdEf0123456789AbCdEf01' },
  { label: 'Date of birth', value: 'my date of birth is 15/08/1998' },

  // The false-positive controls. These are the most important chips on the page:
  // a detector that fires on these is worse than one that misses, because it
  // trains the user to dismiss warnings without reading them.
  { label: 'Order ID (must stay silent)', value: 'order id 1234567890123456 shipped', control: true },
  { label: 'Meeting date (must stay silent)', value: 'the meeting is on 15/08/1998', control: true },
  { label: 'Ref number (must stay silent)', value: 'ref number 123456789012 for the parcel', control: true },
];

const container = document.getElementById('chips');

/**
 * Module 10 chips. Separate list because these are the only samples on the page
 * that must reach the clipboard to be tested at all — the feature under test is
 * a paste handler, and typing the value by hand exercises a different code path
 * entirely (the debounced scanner, which was already working).
 *
 * Shaped like real credentials, issued by nobody. Each one is the exact form the
 * synchronous pre-filter is anchored on, so if a chip stops holding the paste,
 * the pattern for that provider has regressed.
 */
const CREDENTIALS = [
  { label: 'AWS access key', value: 'AKIANOTAREALKEY01234', note: 'held instantly, offline' },
  { label: 'GitHub token', value: `ghp_${'N0tARealToken'.repeat(3)}`.slice(0, 40) },
  { label: 'Stripe secret', value: 'sk_live_N0tARealStripeKey1234' },
  { label: 'Slack bot token', value: 'xoxb-000000000000-N0tAReal' },
  {
    label: 'Session token (JWT)',
    value:
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  },

  // The control that matters most for this module. A pre-filter that holds this
  // makes every paste on the web feel broken, which is a far worse outcome than
  // missing one key.
  {
    label: 'Ordinary text (must paste normally)',
    value: 'Sounds good, I will send the invoice tomorrow morning.',
    control: true,
  },
];

function renderChips(samples, target) {
  if (!target) return;
  for (const sample of samples) {
    const chip = document.createElement('button');
    chip.className = sample.control ? 'chip control' : 'chip';
    chip.type = 'button';

    const label = document.createElement('span');
    label.className = 'chip-label';
    label.textContent = sample.label;

    const value = document.createElement('code');
    value.textContent = sample.value;

    chip.append(label, value);

    if (sample.note) {
      const note = document.createElement('span');
      note.className = 'chip-note';
      note.textContent = sample.note;
      chip.appendChild(note);
    }

    chip.addEventListener('click', async () => {
      await navigator.clipboard.writeText(sample.value);
      const previous = label.textContent;
      label.textContent = 'Copied';
      setTimeout(() => {
        label.textContent = previous;
      }, 1200);
    });

    target.appendChild(chip);
  }
}

/**
 * Module 11 scripts, written as they arrive.
 *
 * Two of the four are scams and two are not, and the two that are not are the
 * more important half of the fixture. Anything can flag an OTP request; the test
 * of whether this feature is shippable in India is whether a friend sharing a
 * UPI ID and a colleague chasing a deadline pass through it in silence.
 *
 * Every name, number, VPA and amount below is invented.
 */
const CHAT_SCRIPTS = [
  {
    title: 'OTP fraud',
    expect: 'dangerous',
    lines: [
      'Hello sir, I am calling from the bank. I will send you Rs 50,000 as a refund today.',
      'You will receive a 6 digit code on your phone. Just tell me the OTP so I can complete it.',
    ],
  },
  {
    title: 'Digital arrest',
    expect: 'dangerous',
    lines: [
      'This is Inspector Sharma from Mumbai Cyber Crime branch. A parcel in your name was seized with illegal items.',
      'A case has been registered against you. Do not tell anyone about this and stay on the video call until we verify.',
    ],
  },
  {
    title: 'A friend sharing their UPI ID',
    expect: 'no alarm',
    control: true,
    lines: [
      'That was fun yesterday, thanks for dinner!',
      'My upi is ravi@okhdfcbank if you need it later, no rush at all.',
    ],
  },
  {
    title: 'An ordinary work message',
    expect: 'no alarm',
    control: true,
    lines: [
      'Morning — could you please share the slides before the review tomorrow?',
      'The client meeting is at 10 and I want to read them first.',
    ],
  },
];

/**
 * Render one script as a selectable block.
 *
 * Deliberately plain text in a `<pre>` rather than chips with a copy button:
 * the interaction under test *is* selecting text with a mouse and right-clicking
 * it, so a button that copies to the clipboard would exercise Module 10 instead.
 */
function renderChatScripts(scripts, target) {
  if (!target) return;
  for (const script of scripts) {
    const block = document.createElement('figure');
    block.className = script.control ? 'chat-block control' : 'chat-block';

    const caption = document.createElement('figcaption');
    const title = document.createElement('span');
    title.className = 'chat-title';
    title.textContent = script.title;
    const expect = document.createElement('span');
    expect.className = 'chat-expect';
    expect.textContent = `expect: ${script.expect}`;
    caption.append(title, expect);

    const body = document.createElement('pre');
    body.className = 'chat-body';
    // textContent, and the lines joined with a real newline: the backend
    // guarantees its quote is a literal substring of what it was sent, and this
    // fixture is only a fair test of that if the text on screen is the text
    // that gets selected.
    body.textContent = script.lines.join('\n');

    block.append(caption, body);
    target.appendChild(block);
  }
}

/**
 * Module 12 fixtures, drawn rather than shipped.
 *
 * The plan for this module says there is to be no real ID in the repository,
 * and that is not squeamishness. A test fixture is the least-guarded file in a
 * project: it gets committed, cloned, attached to bug reports and pasted into
 * chat threads. A product whose entire argument is that photographs of identity
 * documents are dangerous to leave lying around cannot ship one.
 *
 * Drawing them on a canvas also removes the only dependency this harness would
 * otherwise have — no image library, no binary blobs, nothing to keep in sync
 * with a checksum file. The pixels are produced by the code below, so what the
 * recogniser reads is exactly what is written here.
 *
 * Every number is fabricated. The Aadhaar number is Verhoeff-valid and issued to
 * nobody; it is the same one the typing samples use, so a finding here and a
 * finding there are directly comparable.
 */

const SHOT_WIDTH = 760;
const SHOT_HEIGHT = 460;

/** Draw one line of text. Wrapped only to keep the fixtures below readable. */
function text(ctx, value, x, y, { size = 26, weight = 400, color = '#111827', spacing = '0px' } = {}) {
  ctx.save();
  ctx.fillStyle = color;
  ctx.font = `${weight} ${size}px "Segoe UI", Arial, sans-serif`;
  // Chrome-only, and deliberately unguarded: an engine that does not know this
  // property ignores the assignment, and the fixture is merely tighter. Widely
  // spaced digits are what an ID card actually looks like, and character
  // spacing is one of the things that changes how an optical reader segments.
  ctx.letterSpacing = spacing;
  ctx.fillText(value, x, y);
  ctx.restore();
}

/**
 * The Aadhaar fixture, with the twelve digits supplied by the caller.
 *
 * Parameterised because the two cards differ in exactly one respect and nothing
 * else: if the layout, the font or the contrast differed too, a difference in
 * the result would no longer isolate the thing under test.
 */
function drawAadhaar(ctx, digits) {
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, SHOT_WIDTH, SHOT_HEIGHT);

  ctx.fillStyle = '#f3f4f6';
  ctx.fillRect(0, 0, SHOT_WIDTH, 76);
  text(ctx, 'GOVERNMENT OF INDIA', 36, 50, { size: 30, weight: 700, spacing: '1px' });

  // Photo plate. Empty on purpose — there is no face to put in it, and a drawn
  // one would only invite someone to wonder whose it was.
  ctx.fillStyle = '#e5e7eb';
  ctx.fillRect(36, 108, 150, 180);
  text(ctx, 'PHOTO', 66, 208, { size: 22, color: '#9ca3af', weight: 600 });

  text(ctx, 'Ravi Kumar', 218, 152, { size: 36, weight: 700 });
  text(ctx, 'DOB: 15/08/1998', 218, 202, { size: 26, color: '#374151' });
  text(ctx, 'Male', 218, 244, { size: 26, color: '#374151' });

  text(ctx, digits, 36, 372, { size: 54, weight: 700, spacing: '4px' });

  ctx.fillStyle = '#f3f4f6';
  ctx.fillRect(0, 398, SHOT_WIDTH, 62);
  text(ctx, 'Aadhaar - Aam Aadmi ka Adhikaar', 36, 438, { size: 24, color: '#4b5563' });
}

function drawStatement(ctx) {
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, SHOT_WIDTH, SHOT_HEIGHT);

  text(ctx, 'EXAMPLE BANK OF INDIA', 36, 56, { size: 30, weight: 700 });
  text(ctx, 'Statement of Account', 36, 94, { size: 24, color: '#4b5563' });

  ctx.strokeStyle = '#d1d5db';
  ctx.beginPath();
  ctx.moveTo(36, 116);
  ctx.lineTo(SHOT_WIDTH - 36, 116);
  ctx.stroke();

  // "Account Number" is written out because the detector for it is context-
  // gated: twelve digits alone are a reference number, and this fixture is only
  // a fair test of the detector if it carries the words the detector needs.
  text(ctx, 'Account Number: 123456789012', 36, 168, { size: 28, weight: 600 });
  text(ctx, 'IFSC: HDFC0001234', 36, 214, { size: 28, weight: 600 });
  text(ctx, 'Email: ravi.kumar@example.com', 36, 260, { size: 26, color: '#374151' });

  text(ctx, '02 Aug   UPI/Groceries              1,240.00', 36, 322, { size: 24, color: '#374151' });
  text(ctx, '03 Aug   Salary credit             48,000.00', 36, 362, { size: 24, color: '#374151' });
  text(ctx, 'Closing balance                    62,410.00', 36, 412, { size: 24, weight: 600 });
}

function drawDeliveryNote(ctx) {
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, SHOT_WIDTH, SHOT_HEIGHT);

  text(ctx, 'EXAMPLE MART', 36, 58, { size: 32, weight: 700 });
  text(ctx, 'Delivery note', 36, 96, { size: 24, color: '#4b5563' });

  ctx.strokeStyle = '#d1d5db';
  ctx.beginPath();
  ctx.moveTo(36, 118);
  ctx.lineTo(SHOT_WIDTH - 36, 118);
  ctx.stroke();

  // Sixteen digits, twelve digits and a date — the shapes of a card number, a
  // bank account and a date of birth, none of them any of those things. This is
  // the single most valuable fixture on the page.
  text(ctx, 'Order id 1234567890123456 shipped', 36, 176, { size: 28, weight: 600 });
  text(ctx, 'Ref number 123456789012 for the parcel', 36, 226, { size: 26, color: '#374151' });
  text(ctx, 'Expected delivery on 12/09/2026', 36, 272, { size: 26, color: '#374151' });
  text(ctx, '1 x Steel water bottle, 1 litre', 36, 336, { size: 24, color: '#374151' });
  text(ctx, 'Paid online. No signature required.', 36, 380, { size: 24, color: '#374151' });
}

const SHOTS = [
  {
    file: 'aadhaar-card.png',
    title: 'An Aadhaar card',
    expect:
      'Expect two findings: the number as high, quoted XXXX XXXX 9014, and the date of birth beneath it. The digits are printed cleanly, so this is the ordinary detector reading ordinary text — the image is the only new part.',
    draw: (ctx) => drawAadhaar(ctx, '2345 6789 9014'),
  },
  {
    file: 'aadhaar-misread.png',
    title: 'The same card, misread',
    expect:
      'Printed as 234S 6789 9O14 on purpose. Waiting for a real misread would make this fixture a coin toss; printing the misread makes it repeatable, and the text reaching the backend is identical either way. Expect the same finding at 0.75 rather than 0.96, labelled a corrected read, with a reason naming both changes: S becomes 5, O becomes 0. If the recogniser reads the S as a 5 by itself you get the ordinary finding instead — also correct, and the reason line tells you which happened.',
    draw: (ctx) => drawAadhaar(ctx, '234S 6789 9O14'),
  },
  {
    file: 'bank-statement.png',
    title: 'A bank statement',
    expect:
      'Expect an account number, an IFSC code and an email address — three findings from one image, listed worst first.',
    draw: drawStatement,
  },
  {
    file: 'delivery-note.png',
    title: 'A delivery note (must stay silent)',
    control: true,
    expect:
      'Sixteen digits, twelve digits and a date, and not one of them sensitive. Nothing should appear. A panel here is a worse failure than a missed Aadhaar, because it is the failure that teaches people to stop reading the panels.',
    draw: drawDeliveryNote,
  },
];

/** The canvas as a PNG `File`, ready for a `DataTransfer` or a download. */
function toFile(canvas, name) {
  return new Promise((resolve) => {
    canvas.toBlob((blob) => {
      resolve(blob === null ? null : new File([blob], name, { type: 'image/png' }));
    }, 'image/png');
  });
}

/**
 * Put a generated file into the upload field as though the user had picked it.
 *
 * `input.files` is a read-only `FileList`; assigning a fresh `DataTransfer`'s
 * list is the only way to write to it. That is the same mechanism the
 * extension's own "Remove from upload" uses, from the other direction — which
 * makes this button a fair test of the real path rather than a simulation of it.
 */
async function attachTo(input, canvas, name, button) {
  const file = await toFile(canvas, name);
  if (file === null) {
    button.textContent = 'Could not build the file';
    return;
  }

  const transfer = new DataTransfer();
  transfer.items.add(file);
  input.files = transfer.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));

  const previous = button.textContent;
  button.textContent = 'Attached';
  setTimeout(() => {
    button.textContent = previous;
  }, 1400);
}

async function saveShot(canvas, name) {
  const file = await toFile(canvas, name);
  if (file === null) return;

  const url = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  // The click is synchronous, but the fetch of the blob is not on every engine,
  // so give it a turn before dropping the only reference to the data.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function renderShots(shots, target, input) {
  if (!target) return;

  for (const shot of shots) {
    const figure = document.createElement('figure');
    if (shot.control) figure.className = 'control';

    const canvas = document.createElement('canvas');
    canvas.width = SHOT_WIDTH;
    canvas.height = SHOT_HEIGHT;
    // A description of the fixture, not a transcript of it: reading the numbers
    // out to a screen reader would put the very values this page is careful not
    // to normalise into the one place nobody checks.
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', `Generated sample image: ${shot.title}`);

    const ctx = canvas.getContext('2d');
    if (ctx !== null) shot.draw(ctx);

    const caption = document.createElement('figcaption');
    const title = document.createElement('strong');
    title.textContent = shot.title;
    const expect = document.createElement('span');
    expect.textContent = shot.expect;
    caption.append(title, expect);

    const actions = document.createElement('div');
    actions.className = 'shot-actions';

    const attach = document.createElement('button');
    attach.type = 'button';
    attach.textContent = 'Attach';
    attach.addEventListener('click', () => void attachTo(input, canvas, shot.file, attach));

    const save = document.createElement('button');
    save.type = 'button';
    save.textContent = 'Save';
    save.title = 'Download the PNG, then drop it on the dashboard screenshot panel.';
    save.addEventListener('click', () => void saveShot(canvas, shot.file));

    actions.append(attach, save);
    figure.append(canvas, caption, actions);
    target.appendChild(figure);
  }
}

renderChips(SAMPLES, container);
renderChips(CREDENTIALS, document.getElementById('cred-chips'));
renderChatScripts(CHAT_SCRIPTS, document.getElementById('chat-scripts'));
renderShots(SHOTS, document.getElementById('shot-grid'), document.getElementById('f-upload'));
