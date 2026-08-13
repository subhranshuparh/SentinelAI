/**
 * Module 12 — screenshot protection, page side.
 *
 * Every text detector in this product is blind to a picture. A photograph of an
 * Aadhaar card, a bank statement screenshot, a boarding pass — all of it walks
 * straight past `content.js`, past the clipboard guard, past the chat watcher,
 * because none of them ever sees a pixel. "Send a photo of your Aadhaar for
 * verification" is one of the most-reported fraud scripts in India and it takes
 * two taps to comply with.
 *
 * This file is the two taps.
 *
 * ## What it hooks, and why that is the right moment
 *
 * A delegated `change` listener on `input[type=file]`. That fires when the user
 * has picked a file and before nearly every site does anything with it — the
 * overwhelming majority upload on a later "Send" or "Attach" press. So removing
 * the file from the field at this point genuinely prevents the upload.
 *
 * The exception is honest and is stated in the panel's own wording: a site that
 * uploads the instant a file is chosen has already sent the bytes by the time
 * this handler's async OCR finishes. Nothing running in a content script can
 * change that — `change` cannot be usefully cancelled, and holding the event
 * would require blocking on a multi-second wasm read inside a DOM handler. For
 * those sites the panel is a notification rather than a prevention, which is
 * still worth having: the user learns immediately, rather than never.
 *
 * ## What never happens
 *
 * The image bytes do not leave this machine. They go from the `File` object to a
 * data URL to the extension's own offscreen document, where a local Tesseract
 * build reads them. The only thing that reaches the backend is the *text* — and
 * only the classification plus a masked preview of that is ever stored. A
 * version of this feature that posted the photograph to a cloud vision API would
 * be performing the exact act it exists to prevent.
 *
 * ## Where the decisions are not
 *
 * Here. This file reads files and renders a panel somebody else wrote. What
 * counts as sensitive is `services/pii/detectors.py`; whether a misread digit may
 * be corrected is `services/pii/ocr_normalise.py`; every sentence on screen is
 * authored in Python or in `toast.js`.
 */

(() => {
  /** Matches MAX_IMAGE_BYTES in the offscreen document and in qr.js. Above this
   *  the base64 string is larger than the message channel wants to carry, and a
   *  screenshot of a document is never this big. */
  const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

  /** Matches MAX_IMAGES_PER_CHECK in background.js. Enforced here as well so a
   *  fifty-file selection is not base64-encoded before being discarded. */
  const MAX_IMAGES = 3;

  /**
   * Inputs whose next `change` event this script synthesised.
   *
   * "Remove from upload" has to tell the host page that the field contents
   * changed, and the only way to do that is to dispatch a `change` event — which
   * this very listener would then pick up, re-read the surviving files, and
   * re-OCR them in a loop. A WeakSet rather than a flag because two file inputs
   * on one page can be mid-flight independently, and a WeakSet does not keep a
   * detached input alive.
   */
  const selfDispatched = new WeakSet();

  /**
   * Increments on every selection. Guards the async gap.
   *
   * OCR takes seconds. A user who picks the wrong file, cancels, and picks
   * another would otherwise get the first file's verdict rendered over the
   * second file's panel — a warning about a file they are no longer uploading,
   * which is worse than no warning at all.
   */
  let selectionToken = 0;

  /** Read one File into a data URL, or null. Never throws: a failure here is
   *  reported as "could not check", not as an exception in the page's console. */
  function readAsDataUrl(file) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : null);
      reader.onerror = () => resolve(null);
      reader.onabort = () => resolve(null);
      reader.readAsDataURL(file);
    });
  }

  /**
   * The images in a file input worth checking.
   *
   * MIME-gated on `file.type`, which the browser derives from the actual
   * selection rather than from anything a page said. A non-image — a PDF, a
   * zip, a spreadsheet — is ignored entirely rather than read and failed: this
   * module claims to read screenshots and nothing else, and a "could not check"
   * on every attached document would be noise that trains users to close the
   * panel unread.
   *
   * A file over the size cap is dropped with the same reasoning, and the drop is
   * counted so the panel can say the check was partial instead of implying it
   * was complete.
   */
  function imagesIn(input) {
    const files = Array.from(input.files || []);
    const images = files.filter((file) => (file.type || '').toLowerCase().startsWith('image/'));
    const small = images.filter((file) => file.size > 0 && file.size <= MAX_IMAGE_BYTES);
    return {
      candidates: small.slice(0, MAX_IMAGES),
      // Oversized images plus anything past the cap. Non-images are not counted:
      // they were never in scope, so calling them "skipped" would overstate what
      // this feature was ever going to look at.
      skipped: images.length - Math.min(small.length, MAX_IMAGES),
    };
  }

  /**
   * Rebuild a file input without the named files.
   *
   * `input.files` is a read-only `FileList` and there is exactly one way to
   * change it: assign a fresh `DataTransfer`'s own list. That is the entire
   * reason this function exists.
   *
   * Returns false when the browser refuses — some inputs with `capture` set, and
   * any input the page has since detached. Reported to the caller rather than
   * swallowed, because "Remove from upload" silently doing nothing would be the
   * worst possible outcome on this panel: the user would believe the file was
   * gone.
   */
  function removeFiles(input, doomed) {
    try {
      const transfer = new DataTransfer();
      for (const file of Array.from(input.files || [])) {
        if (!doomed.has(file)) transfer.items.add(file);
      }
      input.files = transfer.files;
    } catch (_error) {
      return false;
    }

    // Tell the page. Its own change handler already ran once with the original
    // selection — most sites only read `input.files` when they upload, so this
    // second event is what makes a framework-managed preview list agree with
    // what is actually in the field.
    selfDispatched.add(input);
    input.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }

  /**
   * Findings from one batch, worst first, with the file each came from.
   *
   * Sorted rather than concatenated because the panel leads with a single
   * masked value and that value has to be the most alarming one in the upload.
   * An email address quoted at the top of a panel that also found an Aadhaar
   * number would read as a tool that had not understood what it was looking at.
   */
  const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  function collate(results) {
    const findings = [];
    const filesWithFindings = new Set();
    let poorRead = false;
    let failure = null;
    let poorReadClean = false;

    for (const entry of results) {
      if (entry?.status === 'failed') {
        // First failure wins the sentence. Reporting three of them would fill
        // the panel with variations of the same non-answer.
        if (failure === null) failure = entry.message;
        continue;
      }
      if (entry?.status !== 'checked') continue;

      const found = Array.isArray(entry.scan?.findings) ? entry.scan.findings : [];
      if (found.length > 0) {
        if (entry.poorRead) poorRead = true;
        filesWithFindings.add(entry.name);
        for (const finding of found) findings.push({ ...finding, file: entry.name });
      } else if (entry.poorRead) {
        // Clean, but off a transcript the recogniser was not sure about. Tracked
        // separately: it is the one clean state this extension says out loud.
        poorReadClean = true;
      }
    }

    findings.sort(
      (a, b) =>
        (RISK_ORDER[a.risk_level] ?? 9) - (RISK_ORDER[b.risk_level] ?? 9) ||
        (b.confidence ?? 0) - (a.confidence ?? 0),
    );

    return { findings, filesWithFindings, poorRead, poorReadClean, failure };
  }

  // -------------------------------------------------------------------------
  // The handler
  // -------------------------------------------------------------------------

  async function checkSelection(input) {
    const { candidates, skipped } = imagesIn(input);
    if (candidates.length === 0) return;

    const token = ++selectionToken;
    const stillCurrent = () => token === selectionToken;

    globalThis.SentinelToast.showUploadChecking(candidates.length);

    const images = [];
    for (const file of candidates) {
      const dataUrl = await readAsDataUrl(file);
      if (dataUrl !== null) images.push({ name: file.name, dataUrl, file });
    }
    if (!stillCurrent()) return;

    if (images.length === 0) {
      globalThis.SentinelToast.showUploadUnavailable(
        'SentinelAI could not open that image, so it was not checked.',
      );
      return;
    }

    const origin = window.location.origin;
    const reply = await globalThis.SentinelAPI.ocrScan({
      images: images.map(({ name, dataUrl }) => ({ name, dataUrl })),
      origin,
      // "Always allow Aadhaar on this site" is a promise about a category of
      // data, not about the path it arrived by. A user who suppressed a type for
      // a site they legitimately upload documents to must not be re-warned here.
      suppressed: await globalThis.SentinelAllowlist.suppressedFor(origin),
    });

    if (!stillCurrent()) return;

    if (reply === null) {
      // The service worker never answered, or the backend is down. Either way
      // nothing was checked, and that is what the panel says. It does not close
      // quietly, because a closed panel is indistinguishable from a clean one.
      globalThis.SentinelToast.showUploadUnavailable(
        'SentinelAI could not reach its backend, so this image was not checked.',
      );
      return;
    }

    const summary = collate(Array.isArray(reply.results) ? reply.results : []);

    if (summary.findings.length === 0) {
      if (summary.failure !== null) {
        globalThis.SentinelToast.showUploadUnavailable(summary.failure);
      } else if (summary.poorReadClean) {
        globalThis.SentinelToast.showUploadPoorRead();
      } else {
        // Clean and legible. Silence — the same answer the typing scanner gives
        // for a message with nothing in it. Dismissing rather than replacing,
        // because the spinner is the only thing on screen and leaving a "nothing
        // found" card up for every attached photo is exactly the over-alerting
        // this UI is written against.
        globalThis.SentinelToast.dismissUpload();
      }
      return;
    }

    const doomed = new Set(
      images.filter(({ name }) => summary.filesWithFindings.has(name)).map(({ file }) => file),
    );

    globalThis.SentinelToast.showUpload(
      {
        findings: summary.findings,
        files: Array.from(summary.filesWithFindings).filter(Boolean),
        poorRead: summary.poorRead,
        checkedCount: typeof reply.checkedCount === 'number' ? reply.checkedCount : images.length,
        // The offscreen cap and this file's cap are the same number, so only one
        // of them can bite; taking the larger keeps the sentence true either way.
        skippedCount: Math.max(skipped, typeof reply.skippedCount === 'number' ? reply.skippedCount : 0),
      },
      {
        onRemove: () => {
          if (!removeFiles(input, doomed)) {
            globalThis.SentinelToast.showUploadUnavailable(
              'This page would not let SentinelAI remove the file. Clear the ' +
                'attachment yourself before sending.',
            );
          }
        },
        // Nothing to do. The file is already in the field and the user has said
        // they want it there; re-stating the warning would be the tool arguing
        // with a decision it asked for.
        onKeep: () => {},
      },
    );
  }

  /**
   * One delegated listener, capture phase.
   *
   * Capture for the same reason `clipboard.js` uses it: upload widgets routinely
   * attach their own `change` handler and several call `stopPropagation`, so a
   * bubble-phase listener would never run on the surfaces that matter most.
   */
  document.addEventListener(
    'change',
    (event) => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;

      if (selfDispatched.has(input)) {
        // Our own event, from removeFiles. Consume the marker and stop: re-reading
        // the surviving files would OCR them a second time and, on a selection
        // where every file was flagged, would loop.
        selfDispatched.delete(input);
        return;
      }

      // Not awaited: a `change` handler must return promptly, and there is
      // nothing about this event left to cancel. Errors are contained inside
      // checkSelection, which reports every failure as a panel.
      void checkSelection(input);
    },
    true,
  );
})();
