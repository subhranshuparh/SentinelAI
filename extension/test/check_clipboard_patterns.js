// One-off verification harness for the Module 10 paste pre-filter.
//
// Not part of the extension and not loaded by it. It exists because the
// blocking patterns in content/clipboard.js decide whether a user's paste is
// interrupted, and "I read the regex and it looked right" is not a standard a
// security tool should hold itself to. Run with:  node extension/test/check_clipboard_patterns.js

const fs = require('fs');
const path = require('path');

const source = fs.readFileSync(
  path.join(__dirname, '..', 'content', 'clipboard.js'),
  'utf8',
);

// Evaluate the array literal itself rather than regex-matching its text. The
// point is to test the patterns the extension actually compiles, not a copy.
// The closing bracket is split on `\n  ];` rather than `]` because character
// classes inside the regexes contain brackets of their own.
const literal = `${source.split('const BLOCKING_PATTERNS = ')[1].split('\n  ];')[0]}\n]`;
const patterns = eval(literal);

const SAMPLES = {
  AKIA: 'AKIANOTAREALKEY01234',
  ASIA: 'ASIANOTAREALKEY01234',
  AIza: 'AIza' + 'B'.repeat(35),
  ghp_: 'ghp_' + 'c'.repeat(36),
  gho_: 'gho_' + 'c'.repeat(36),
  ghu_: 'ghu_' + 'c'.repeat(36),
  ghs_: 'ghs_' + 'c'.repeat(36),
  sk_l: 'sk_live_' + 'd'.repeat(24),
  sk_t: 'sk_test_' + 'd'.repeat(24),
  'sk-p': 'sk-proj-' + 'e'.repeat(32),
  'sk-': 'sk-' + 'f'.repeat(48),
  xoxb: 'xoxb-1234567890-abcdefghij',
  xoxp: 'xoxp-1234567890-abcdefghij',
  xoxa: 'xoxa-1234567890-abcdefghij',
  xoxs: 'xoxs-1234567890-abcdefghij',
  xoxo: 'xoxo-1234567890-abcdefghij',
  eyJ: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
};

// Things people paste all day. A single hit here would make the extension hold
// ordinary pastes, which is worse than missing a key: it is the failure that
// gets the extension uninstalled.
const NEGATIVES = [
  'hello, how are you?',
  'sk-short',
  'AKIAshort',
  'my email is someone@example.com',
  'xoxb-123',
  'https://github.com/org/repo/blob/main/README.md',
  'SELECT * FROM users WHERE id = 42;',
  'eyJ is how base64 JSON starts',
  '4111 1111 1111 1111',
];

let failures = 0;

if (patterns.length < 10) {
  console.log(`FAIL: parsed only ${patterns.length} patterns — extraction is broken`);
  process.exit(1);
}

for (const entry of patterns) {
  const sample = SAMPLES[entry.prefix];
  if (!sample) {
    console.log(`FAIL: no sample for prefix ${entry.prefix}`);
    failures++;
    continue;
  }
  if (!entry.re.test(`here you go: ${sample} thanks`)) {
    console.log(`FAIL: ${entry.prefix} did not match its own sample`);
    failures++;
  }
}

for (const text of NEGATIVES) {
  for (const entry of patterns) {
    if (entry.re.test(text)) {
      console.log(`FAIL: ${entry.prefix} fired on ordinary text: ${JSON.stringify(text)}`);
      failures++;
    }
  }
}

console.log(
  failures === 0
    ? `OK — ${patterns.length} patterns, ${NEGATIVES.length} negatives, no false positives`
    : `${failures} failure(s)`,
);
process.exit(failures === 0 ? 0 : 1);
