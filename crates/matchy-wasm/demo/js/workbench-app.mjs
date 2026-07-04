import {
  Database,
  ExtractorBuilder,
  initMatchyWasm,
  version,
} from "./wasm-loader.mjs";

import {
  applyLineScan,
  createScanState,
  normalizeFeedMetadata,
  shellQuote,
  splitCompleteLines,
  summarizeScan,
} from "./workbench-core.mjs";

const FEED_DB_URL = "./assets/demo-threats.mxy";
const FEED_METADATA_URL = "./assets/demo-threats.json";
const BATCH_RENDER_LINES = 250;

const app = {
  db: null,
  extractor: null,
  feedMetadata: normalizeFeedMetadata(),
  scanState: createScanState(),
  scanStartedAt: 0,
};

function text(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
}

function html(id, value) {
  const element = document.getElementById(id);
  if (element) element.innerHTML = value;
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = String(value);
  return div.innerHTML;
}

function renderFeedStatus() {
  text("feed-name", app.feedMetadata.name);
  text("feed-entry-count", app.feedMetadata.entryCount.toLocaleString());
  text("feed-generated", app.feedMetadata.generatedAt);
  text("matchy-version", version());
}

function renderWorkbenchStatus(message) {
  text("workbench-status", message);
}

function renderSummary(elapsedMs = 0) {
  const summary = summarizeScan(app.scanState, elapsedMs);
  text("summary-files", String(summary.filesScanned));
  text("summary-bytes", summary.bytesDisplay);
  text("summary-lines", summary.linesScanned.toLocaleString());
  text("summary-indicators", summary.indicatorsExtracted.toLocaleString());
  text("summary-unique", summary.uniqueIndicatorsQueried.toLocaleString());
  text("summary-matches", summary.matchesFound.toLocaleString());
}

function sortedHits() {
  return app.scanState.hits
    .slice()
    .sort((a, b) => b.count - a.count || a.indicator.localeCompare(b.indicator));
}

function renderHits() {
  if (app.scanState.hits.length === 0) {
    html(
      "hits-table-body",
      '<tr><td colspan="6" style="color: var(--text-dim);">No matches found yet.</td></tr>',
    );
    return;
  }

  const rows = sortedHits()
    .map((hit) => {
      const originalIndex = app.scanState.hits.indexOf(hit);
      return `
        <tr class="hit-row" data-hit-index="${originalIndex}">
          <td>${escapeHtml(hit.indicator)}</td>
          <td>${escapeHtml(hit.type)}</td>
          <td>${escapeHtml(hit.severity)}</td>
          <td>${escapeHtml(hit.source)}</td>
          <td>${escapeHtml(hit.malware || "")}</td>
          <td>${hit.count.toLocaleString()}</td>
        </tr>
      `;
    })
    .join("");

  html("hits-table-body", rows);

  document.querySelectorAll("[data-hit-index]").forEach((row) => {
    row.addEventListener("click", () => {
      const hit = app.scanState.hits[Number(row.dataset.hitIndex)];
      renderHitDetail(hit);
    });
  });
}

function highlightIndicator(lineText, indicator) {
  const escapedLine = escapeHtml(lineText);
  const escapedIndicator = escapeHtml(indicator);
  return escapedLine.replaceAll(
    escapedIndicator,
    `<span class="matched-indicator">${escapedIndicator}</span>`,
  );
}

function renderEvidenceLines() {
  if (app.scanState.evidenceLines.length === 0) {
    html(
      "evidence-lines",
      '<span style="color: var(--text-dim);">Matching source lines appear here.</span>',
    );
    return;
  }

  const lines = app.scanState.evidenceLines
    .slice(-100)
    .map(
      (line) => `
        <div class="evidence-line">
          <strong>${escapeHtml(line.fileName)}:${line.lineNumber}</strong>
          ${highlightIndicator(line.lineText, line.indicator)}
        </div>
      `,
    )
    .join("");

  html("evidence-lines", lines);
}

function renderHitDetail(hit) {
  if (!hit) {
    html("hit-detail", "Select a hit to inspect metadata and matching lines.");
    return;
  }

  const lineList = hit.lines
    .slice(0, 20)
    .map(
      (line) =>
        `${escapeHtml(line.fileName)}:${line.lineNumber} ${highlightIndicator(
          line.lineText,
          hit.indicator,
        )}`,
    )
    .join("\n");

  html(
    "hit-detail",
    `
      <strong>${escapeHtml(hit.indicator)}</strong>
      <pre>${escapeHtml(JSON.stringify(hit.metadata, null, 2))}</pre>
      <strong>Matching lines</strong>
      <pre>${lineList}</pre>
    `,
  );
}

function renderCliHandoff(files) {
  if (!files || files.length === 0) {
    html("cli-handoff", "After a scan, equivalent CLI commands appear here.");
    return;
  }

  const fileNames = Array.from(files)
    .map((file) => shellQuote(file.name))
    .join(" ");
  html(
    "cli-handoff",
    `<pre>matchy match demo-threats.mxy ${escapeHtml(fileNames)} --stats</pre>`,
  );
}

function renderAll(elapsedMs = 0) {
  renderSummary(elapsedMs);
  renderHits();
  renderEvidenceLines();
}

async function yieldToBrowser() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function loadBundledFeed() {
  const [metadataResponse, databaseResponse] = await Promise.all([
    fetch(FEED_METADATA_URL),
    fetch(FEED_DB_URL),
  ]);

  if (!metadataResponse.ok) {
    throw new Error(`Feed metadata failed to load: ${metadataResponse.status}`);
  }
  if (!databaseResponse.ok) {
    throw new Error(`Feed database failed to load: ${databaseResponse.status}`);
  }

  app.feedMetadata = normalizeFeedMetadata(await metadataResponse.json());
  const databaseBytes = new Uint8Array(await databaseResponse.arrayBuffer());
  app.db = new Database(databaseBytes);
}

function extractLineEntities(lineText) {
  try {
    return app.extractor.extract(lineText);
  } catch (error) {
    app.scanState.errors.push({
      indicator: "",
      message: error instanceof Error ? error.message : String(error),
    });
    return [];
  }
}

function scanLineBatch(fileName, startingLineNumber, lines) {
  let lineNumber = startingLineNumber;
  for (const lineText of lines) {
    const entities = extractLineEntities(lineText);
    applyLineScan(app.scanState, {
      fileName,
      lineNumber,
      lineText,
      entities,
      lookup: (indicator) => app.db.lookup(indicator),
    });
    lineNumber += 1;
  }
  return lineNumber;
}

async function scanPendingLines(fileName, lineNumber, pendingLines, force = false) {
  while (pendingLines.length >= BATCH_RENDER_LINES || (force && pendingLines.length > 0)) {
    const batch = pendingLines.splice(0, BATCH_RENDER_LINES);
    lineNumber = scanLineBatch(fileName, lineNumber, batch);
    renderAll(performance.now() - app.scanStartedAt);
    await yieldToBrowser();
  }
  return lineNumber;
}

async function scanFileWithText(file) {
  const textContent = await file.text();
  const split = splitCompleteLines("", textContent);
  const pendingLines = split.lines.concat(split.carry ? [split.carry] : []);
  await scanPendingLines(file.name, 1, pendingLines, true);
}

async function scanFileWithStream(file) {
  const decoder = new TextDecoder();
  const reader = file.stream().getReader();
  const pendingLines = [];
  let lineNumber = 1;
  let carry = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    const chunkText = decoder.decode(value, { stream: true });
    const split = splitCompleteLines(carry, chunkText);
    carry = split.carry;
    pendingLines.push(...split.lines);
    lineNumber = await scanPendingLines(file.name, lineNumber, pendingLines);
  }

  const finalText = decoder.decode();
  if (finalText) {
    const split = splitCompleteLines(carry, finalText);
    carry = split.carry;
    pendingLines.push(...split.lines);
  }
  if (carry) pendingLines.push(carry);

  await scanPendingLines(file.name, lineNumber, pendingLines, true);
}

async function scanFile(file) {
  app.scanState.filesScanned += 1;
  app.scanState.bytesScanned += file.size;

  if (file.stream && typeof file.stream === "function") {
    await scanFileWithStream(file);
  } else {
    await scanFileWithText(file);
  }
}

async function scanFiles(files) {
  const selectedFiles = Array.from(files || []);
  if (selectedFiles.length === 0) return;

  if (!app.db || !app.extractor) {
    renderWorkbenchStatus("Workbench feed is not ready. Advanced tools remain available below.");
    return;
  }

  app.scanState = createScanState();
  app.scanStartedAt = performance.now();
  renderWorkbenchStatus("Scanning locally...");
  renderHitDetail(null);
  renderCliHandoff(selectedFiles);
  renderAll(0);

  for (const file of selectedFiles) {
    try {
      await scanFile(file);
    } catch (error) {
      app.scanState.errors.push({
        indicator: "",
        message: `${file.name}: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  renderAll(performance.now() - app.scanStartedAt);
  renderWorkbenchStatus(
    `Scan complete. ${app.scanState.matchesFound.toLocaleString()} matches found locally.`,
  );
}

function openFilePicker(fileInput) {
  fileInput.value = "";
  fileInput.click();
}

function setupDropZone() {
  const dropZone = document.getElementById("evidence-drop-zone");
  const fileInput = document.getElementById("evidence-file-input");
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener("click", () => openFilePicker(fileInput));
  dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openFilePicker(fileInput);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) scanFiles(fileInput.files);
  });

  dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });
  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragover");
    if (event.dataTransfer.files.length > 0) scanFiles(event.dataTransfer.files);
  });
}

async function main() {
  try {
    renderWorkbenchStatus("Loading Matchy WASM...");
    await initMatchyWasm();
    app.extractor = new ExtractorBuilder().build();

    renderWorkbenchStatus("Loading bundled feed...");
    await loadBundledFeed();
    renderFeedStatus();
    setupDropZone();
    renderWorkbenchStatus("Ready. Drop a log file to scan locally.");
  } catch (error) {
    renderWorkbenchStatus(error instanceof Error ? error.message : String(error));
    html(
      "hits-table-body",
      '<tr><td colspan="6" style="color: var(--accent);">Workbench failed to initialize. Advanced tools may still work below.</td></tr>',
    );
  }
}

main();
