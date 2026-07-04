# Analyst Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-first browser analyst workbench where users drop log files, Matchy WASM extracts and matches IoCs against a bundled static `.mxy` database, and the page shows analyst-friendly hits without uploading evidence.

**Architecture:** Keep the existing WASM demo as the host page, but add testable browser modules for scan state, line chunking, feed metadata, and workbench UI wiring. The page loads a static `demo-threats.mxy` plus metadata, scans dropped files in line batches, and leaves the existing builder/import/query/extractor tools in an advanced section.

**Tech Stack:** Rust workspace, `matchy-wasm`, wasm-bindgen web target, browser File API, ES modules, Node built-in test runner for pure JavaScript tests, existing mdBook/README docs.

---

## File Structure

- Create `crates/matchy-wasm/demo/js/workbench-core.mjs`: pure JavaScript scan helpers for metadata normalization, line chunking, lookup de-duplication, hit aggregation, and display formatting.
- Create `crates/matchy-wasm/demo/js/workbench-core.test.mjs`: Node tests for the pure workbench helpers.
- Create `crates/matchy-wasm/demo/js/workbench-app.mjs`: browser-only UI module that initializes WASM, loads bundled feed assets, handles file drops, scans files incrementally, and renders workbench state.
- Create `crates/matchy-wasm/demo/assets/demo-threats.csv`: deterministic bundled demo feed source in Matchy CSV format.
- Create `crates/matchy-wasm/demo/assets/demo-threats.json`: feed metadata sidecar consumed by the browser UI.
- Generate `crates/matchy-wasm/demo/assets/demo-threats.mxy`: static database asset built from `demo-threats.csv`.
- Modify `crates/matchy-wasm/demo/index.html`: add the analyst workbench UI, load `workbench-app.mjs`, and move the existing tools under an advanced section.
- Modify `crates/matchy-wasm/demo/README.md`: document the workbench, static assets, and local scanning behavior.
- Modify `README.md`: link to the browser workbench near the top.
- Modify `book/src/introduction.md`: link to the browser workbench as the fastest way to try Matchy.
- Modify `.github/workflows/deploy-docs.yml`: rebuild the WASM demo and copy it into the GitHub Pages artifact under `/demo/`.

## Task 1: Add Pure Workbench Core

**Files:**
- Create: `crates/matchy-wasm/demo/js/workbench-core.test.mjs`
- Create: `crates/matchy-wasm/demo/js/workbench-core.mjs`

- [ ] **Step 1: Write failing tests for metadata, line chunking, de-duplication, and hit aggregation**

Create `crates/matchy-wasm/demo/js/workbench-core.test.mjs`:

```javascript
import test from "node:test";
import assert from "node:assert/strict";

import {
  applyLineScan,
  createScanState,
  formatBytes,
  normalizeFeedMetadata,
  splitCompleteLines,
  summarizeScan,
} from "./workbench-core.mjs";

test("normalizeFeedMetadata fills stable display defaults", () => {
  const metadata = normalizeFeedMetadata({
    name: "ThreatFox sample",
    generated_at: "2026-07-04T00:00:00Z",
    entry_count: 3,
    source: "abuse.ch ThreatFox",
    source_url: "https://threatfox.abuse.ch/",
  });

  assert.deepEqual(metadata, {
    name: "ThreatFox sample",
    generatedAt: "2026-07-04T00:00:00Z",
    entryCount: 3,
    source: "abuse.ch ThreatFox",
    sourceUrl: "https://threatfox.abuse.ch/",
    disclaimer: "Bundled demo feed sample",
  });
});

test("splitCompleteLines carries partial trailing lines across chunks", () => {
  const first = splitCompleteLines("", "alpha\nbravo part");
  assert.deepEqual(first, { lines: ["alpha"], carry: "bravo part" });

  const second = splitCompleteLines(first.carry, " two\r\ncharlie\n");
  assert.deepEqual(second, { lines: ["bravo part two", "charlie"], carry: "" });
});

test("applyLineScan de-duplicates lookups and aggregates repeated matches", () => {
  const state = createScanState();
  let lookupCalls = 0;
  const lookup = (indicator) => {
    lookupCalls += 1;
    if (indicator === "198.51.100.23") {
      return {
        severity: "high",
        confidence: 87,
        source: "Bundled demo feed",
        threat_type: "botnet_cc",
        malware: "demo-malware",
        first_seen: "2026-07-04",
      };
    }
    return null;
  };

  applyLineScan(state, {
    fileName: "auth.log",
    lineNumber: 10,
    lineText: "connect from 198.51.100.23 to vpn.example",
    entities: [{ type: "IPv4", value: "198.51.100.23" }],
    lookup,
  });

  applyLineScan(state, {
    fileName: "auth.log",
    lineNumber: 11,
    lineText: "second connection from 198.51.100.23",
    entities: [{ type: "IPv4", value: "198.51.100.23" }],
    lookup,
  });

  assert.equal(lookupCalls, 1);
  assert.equal(state.indicatorsExtracted, 2);
  assert.equal(state.uniqueIndicatorsQueried, 1);
  assert.equal(state.matchesFound, 2);
  assert.equal(state.hits.length, 1);
  assert.equal(state.hits[0].indicator, "198.51.100.23");
  assert.equal(state.hits[0].count, 2);
  assert.equal(state.hits[0].lines.length, 2);
});

test("summarizeScan and formatBytes provide stable display values", () => {
  const state = createScanState();
  state.filesScanned = 2;
  state.bytesScanned = 1536;
  state.linesScanned = 12;
  state.indicatorsExtracted = 4;
  state.uniqueIndicatorsQueried = 3;
  state.matchesFound = 1;

  assert.equal(formatBytes(1536), "1.5 KB");
  assert.deepEqual(summarizeScan(state, 42.125), {
    filesScanned: 2,
    bytesScanned: 1536,
    bytesDisplay: "1.5 KB",
    linesScanned: 12,
    indicatorsExtracted: 4,
    uniqueIndicatorsQueried: 3,
    matchesFound: 1,
    elapsedMs: 42.125,
  });
});
```

- [ ] **Step 2: Run tests to verify they fail because the module does not exist**

Run:

```bash
node --test crates/matchy-wasm/demo/js/workbench-core.test.mjs
```

Expected: FAIL with an error containing `Cannot find module` and `workbench-core.mjs`.

- [ ] **Step 3: Add the pure workbench core module**

Create `crates/matchy-wasm/demo/js/workbench-core.mjs`:

```javascript
const DEFAULT_FEED_DISCLAIMER = "Bundled demo feed sample";

export function normalizeFeedMetadata(raw = {}) {
  return {
    name: String(raw.name || "Bundled threat feed sample"),
    generatedAt: String(raw.generated_at || raw.generatedAt || "unknown"),
    entryCount: Number(raw.entry_count || raw.entryCount || 0),
    source: String(raw.source || "bundled static asset"),
    sourceUrl: String(raw.source_url || raw.sourceUrl || ""),
    disclaimer: String(raw.disclaimer || DEFAULT_FEED_DISCLAIMER),
  };
}

export function splitCompleteLines(carry, chunkText) {
  const combined = `${carry || ""}${chunkText || ""}`;
  const parts = combined.split(/\r?\n/);
  const nextCarry = parts.pop() ?? "";
  return { lines: parts, carry: nextCarry };
}

export function createScanState() {
  return {
    filesScanned: 0,
    bytesScanned: 0,
    linesScanned: 0,
    indicatorsExtracted: 0,
    uniqueIndicatorsQueried: 0,
    matchesFound: 0,
    lookupCache: new Map(),
    hitsByIndicator: new Map(),
    hits: [],
    evidenceLines: [],
    errors: [],
  };
}

export function normalizeIndicatorType(type) {
  const value = String(type || "Indicator");
  if (value === "IPv4" || value === "IPv6") return "IP";
  if (value.startsWith("SHA") || value === "MD5") return "Hash";
  return value;
}

export function indicatorCacheKey(entity) {
  return `${normalizeIndicatorType(entity.type)}:${String(entity.value).toLowerCase()}`;
}

export function readSeverity(metadata) {
  if (!metadata || typeof metadata !== "object") return "unknown";
  return String(
    metadata.severity ||
      metadata.threat_level ||
      metadata.confidence_level ||
      metadata.confidence ||
      "unknown",
  );
}

export function readSource(metadata) {
  if (!metadata || typeof metadata !== "object") return "bundled-feed";
  return String(metadata.source || metadata.feed || metadata.source_name || "bundled-feed");
}

export function readMalware(metadata) {
  if (!metadata || typeof metadata !== "object") return "";
  return String(metadata.malware || metadata.malware_printable || metadata.threat_type || "");
}

export function readFirstSeen(metadata) {
  if (!metadata || typeof metadata !== "object") return "";
  return String(metadata.first_seen || metadata.firstSeen || metadata.last_seen || "");
}

export function applyLineScan(state, { fileName, lineNumber, lineText, entities, lookup }) {
  state.linesScanned += 1;

  for (const entity of entities || []) {
    if (!entity || !entity.value) continue;

    state.indicatorsExtracted += 1;
    const cacheKey = indicatorCacheKey(entity);

    let lookupResult;
    if (state.lookupCache.has(cacheKey)) {
      lookupResult = state.lookupCache.get(cacheKey);
    } else {
      try {
        lookupResult = lookup(entity.value) || null;
      } catch (error) {
        state.errors.push({
          indicator: entity.value,
          message: error instanceof Error ? error.message : String(error),
        });
        lookupResult = null;
      }
      state.lookupCache.set(cacheKey, lookupResult);
      state.uniqueIndicatorsQueried += 1;
    }

    if (!lookupResult) continue;

    state.matchesFound += 1;
    const lineRecord = { fileName, lineNumber, lineText };
    let hit = state.hitsByIndicator.get(cacheKey);

    if (!hit) {
      hit = {
        indicator: String(entity.value),
        type: normalizeIndicatorType(entity.type),
        severity: readSeverity(lookupResult),
        source: readSource(lookupResult),
        malware: readMalware(lookupResult),
        firstSeen: readFirstSeen(lookupResult),
        count: 0,
        sampleLine: lineText,
        metadata: lookupResult,
        lines: [],
      };
      state.hitsByIndicator.set(cacheKey, hit);
      state.hits.push(hit);
    }

    hit.count += 1;
    hit.lines.push(lineRecord);
    state.evidenceLines.push({ ...lineRecord, indicator: entity.value, type: hit.type });
  }

  return state;
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function summarizeScan(state, elapsedMs) {
  return {
    filesScanned: state.filesScanned,
    bytesScanned: state.bytesScanned,
    bytesDisplay: formatBytes(state.bytesScanned),
    linesScanned: state.linesScanned,
    indicatorsExtracted: state.indicatorsExtracted,
    uniqueIndicatorsQueried: state.uniqueIndicatorsQueried,
    matchesFound: state.matchesFound,
    elapsedMs,
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
node --test crates/matchy-wasm/demo/js/workbench-core.test.mjs
```

Expected: PASS with all four tests succeeding.

- [ ] **Step 5: Commit the pure core**

Run:

```bash
git add crates/matchy-wasm/demo/js/workbench-core.mjs crates/matchy-wasm/demo/js/workbench-core.test.mjs
git commit -m "Add browser workbench scan core"
```

## Task 2: Add Bundled Demo Feed Assets

**Files:**
- Create: `crates/matchy-wasm/demo/assets/demo-threats.csv`
- Create: `crates/matchy-wasm/demo/assets/demo-threats.json`
- Generate: `crates/matchy-wasm/demo/assets/demo-threats.mxy`

- [ ] **Step 1: Add the deterministic demo feed source**

Create `crates/matchy-wasm/demo/assets/demo-threats.csv`:

```csv
entry,severity,confidence,source,feed,threat_type,malware,first_seen,reference
198.51.100.23,high,87,Bundled demo feed,Matchy demo feed,botnet_cc,demo-malware,2026-07-04,https://threatfox.abuse.ch/
203.0.113.77,medium,72,Bundled demo feed,Matchy demo feed,scanner,demo-scanner,2026-07-04,https://threatfox.abuse.ch/
192.0.2.44,critical,95,Bundled demo feed,Matchy demo feed,c2,demo-c2,2026-07-04,https://threatfox.abuse.ch/
malware.example.com,high,83,Bundled demo feed,Matchy demo feed,payload_host,demo-loader,2026-07-04,https://threatfox.abuse.ch/
*.bad-demo.example.com,medium,70,Bundled demo feed,Matchy demo feed,phishing,demo-phish,2026-07-04,https://threatfox.abuse.ch/
44d88612fea8a8f36de82e1278abb02f,high,80,Bundled demo feed,Matchy demo feed,malware_hash,eicar-demo,2026-07-04,https://threatfox.abuse.ch/
```

- [ ] **Step 2: Add the feed metadata sidecar**

Create `crates/matchy-wasm/demo/assets/demo-threats.json`:

```json
{
  "name": "Matchy bundled threat feed sample",
  "generated_at": "2026-07-04T00:00:00Z",
  "entry_count": 6,
  "source": "ThreatFox-shaped public feed sample",
  "source_url": "https://threatfox.abuse.ch/",
  "disclaimer": "Static demo feed bundled with the browser workbench"
}
```

- [ ] **Step 3: Build the static `.mxy` asset from the CSV**

Run:

```bash
cargo run -p matchy -- build crates/matchy-wasm/demo/assets/demo-threats.csv --output crates/matchy-wasm/demo/assets/demo-threats.mxy --input-format csv
```

Expected: command exits successfully and creates `crates/matchy-wasm/demo/assets/demo-threats.mxy`.

- [ ] **Step 4: Verify the generated database matches a known indicator**

Run:

```bash
cargo run -p matchy -- query crates/matchy-wasm/demo/assets/demo-threats.mxy 198.51.100.23
```

Expected: output includes `demo-malware` and `Bundled demo feed`.

- [ ] **Step 5: Commit the feed assets**

Run:

```bash
git add crates/matchy-wasm/demo/assets/demo-threats.csv crates/matchy-wasm/demo/assets/demo-threats.json crates/matchy-wasm/demo/assets/demo-threats.mxy
git commit -m "Add bundled browser demo threat feed"
```

## Task 3: Add the Analyst Workbench HTML Shell

**Files:**
- Modify: `crates/matchy-wasm/demo/index.html`

- [ ] **Step 1: Update the document title and header copy**

In `crates/matchy-wasm/demo/index.html`, replace:

```html
<title>Matchy Demo - IP & Pattern Matching</title>
```

with:

```html
<title>Matchy Analyst Workbench - Local IoC Matching</title>
```

Replace the current `<header>` block with:

```html
<header>
    <h1><span>Matchy</span> Analyst Workbench</h1>
    <p>Drop logs, extract indicators, and match threat intel locally in your browser.</p>
</header>
```

- [ ] **Step 2: Add workbench CSS before the closing `</style>` tag**

Insert this CSS before `</style>`:

```css
.privacy-banner {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: center;
    padding: 1rem;
    margin-bottom: 1.5rem;
    background: rgba(74, 222, 128, 0.08);
    border: 1px solid rgba(74, 222, 128, 0.35);
    border-radius: 8px;
}

.feed-status {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
}

.status-card,
.summary-card {
    background: var(--bg);
    border: 1px solid var(--primary);
    border-radius: 8px;
    padding: 0.85rem;
}

.status-card strong,
.summary-card strong {
    display: block;
    color: var(--text);
    font-size: 1.15rem;
}

.status-card span,
.summary-card span {
    color: var(--text-dim);
    font-size: 0.82rem;
}

.evidence-drop-zone {
    border: 2px dashed var(--primary);
    border-radius: 8px;
    padding: 2rem;
    text-align: center;
    background: var(--surface);
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
}

.evidence-drop-zone.dragover {
    border-color: var(--success);
    background: rgba(74, 222, 128, 0.08);
}

.summary-strip {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 0.75rem;
    margin: 1.5rem 0;
}

.hits-layout {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
    gap: 1rem;
}

.hits-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
}

.hits-table th,
.hits-table td {
    border-bottom: 1px solid var(--primary);
    padding: 0.6rem;
    text-align: left;
    vertical-align: top;
}

.hits-table th {
    color: var(--text-dim);
    font-weight: 600;
}

.hit-row {
    cursor: pointer;
}

.hit-row:hover {
    background: rgba(15, 52, 96, 0.45);
}

.evidence-lines {
    max-height: 320px;
    overflow: auto;
    white-space: pre-wrap;
}

.evidence-line {
    padding: 0.45rem 0;
    border-bottom: 1px solid rgba(15, 52, 96, 0.7);
}

.matched-indicator {
    color: #000;
    background: var(--warning);
    border-radius: 3px;
    padding: 0 0.15rem;
}

.advanced-tools {
    margin-top: 2rem;
}

@media (max-width: 900px) {
    .feed-status,
    .summary-strip,
    .hits-layout {
        grid-template-columns: 1fr;
    }
}
```

- [ ] **Step 3: Add the workbench markup immediately after `<div id="app" style="display: none;">`**

Insert this block before the existing `<div class="tabs">`:

```html
<section id="workbench" class="section">
    <div class="privacy-banner">
        <div>
            <strong>Local browser matching</strong>
            <div>Feed assets download to this page. Dropped files stay in this browser.</div>
        </div>
        <div id="workbench-status">Loading Matchy WASM and bundled feed...</div>
    </div>

    <div class="feed-status">
        <div class="status-card">
            <strong id="feed-name">Loading feed</strong>
            <span>Feed</span>
        </div>
        <div class="status-card">
            <strong id="feed-entry-count">0</strong>
            <span>Entries</span>
        </div>
        <div class="status-card">
            <strong id="feed-generated">unknown</strong>
            <span>Generated</span>
        </div>
        <div class="status-card">
            <strong id="matchy-version">unknown</strong>
            <span>Matchy version</span>
        </div>
    </div>

    <div id="evidence-drop-zone" class="evidence-drop-zone">
        <p><strong>Drop log files here to scan immediately</strong></p>
        <p>Text logs, JSONL, CSV, and copied evidence exports work best.</p>
        <input type="file" id="evidence-file-input" multiple style="display: none;">
    </div>

    <div class="summary-strip" id="scan-summary">
        <div class="summary-card"><strong id="summary-files">0</strong><span>Files</span></div>
        <div class="summary-card"><strong id="summary-bytes">0 B</strong><span>Scanned</span></div>
        <div class="summary-card"><strong id="summary-lines">0</strong><span>Lines</span></div>
        <div class="summary-card"><strong id="summary-indicators">0</strong><span>Indicators</span></div>
        <div class="summary-card"><strong id="summary-unique">0</strong><span>Unique queried</span></div>
        <div class="summary-card"><strong id="summary-matches">0</strong><span>Matches</span></div>
    </div>

    <div class="hits-layout">
        <div class="section">
            <h3>Hits</h3>
            <table class="hits-table">
                <thead>
                    <tr>
                        <th>Indicator</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Source</th>
                        <th>Malware / Threat</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody id="hits-table-body">
                    <tr><td colspan="6" style="color: var(--text-dim);">Drop a file to begin scanning.</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h3>Hit Detail</h3>
            <div id="hit-detail" class="results">Select a hit to inspect metadata and matching lines.</div>
        </div>
    </div>

    <div class="section">
        <h3>Evidence Lines</h3>
        <div id="evidence-lines" class="results evidence-lines">
            <span style="color: var(--text-dim);">Matching source lines appear here.</span>
        </div>
    </div>

    <div class="section">
        <h3>Run Locally</h3>
        <div id="cli-handoff" class="results">After a scan, equivalent CLI commands appear here.</div>
    </div>
</section>

<details class="advanced-tools">
    <summary>Advanced database builder, import, query, and extractor tools</summary>
```

- [ ] **Step 4: Close the advanced `<details>` after the existing extractor panel**

Add this closing tag immediately after the current extractor panel closing `</div>` and before the closing `</div>` for `#app`:

```html
</details>
```

- [ ] **Step 5: Load the workbench UI module**

Add this script before the existing inline `<script type="module">` block:

```html
<script type="module" src="./js/workbench-app.mjs"></script>
```

- [ ] **Step 6: Verify the static shell renders**

Run:

```bash
cd crates/matchy-wasm/demo
python3 -m http.server 8080
```

Expected: server starts on `http://0.0.0.0:8080/`. Open `http://localhost:8080/` in a browser. The page should show the local matching banner, feed status cards, drop zone, hits table, evidence section, CLI handoff, and a collapsed advanced tools section.

- [ ] **Step 7: Commit the HTML shell**

Stop the Python server, then run:

```bash
git add crates/matchy-wasm/demo/index.html
git commit -m "Add analyst workbench demo shell"
```

## Task 4: Wire Workbench Asset Loading and Incremental Scanning

**Files:**
- Create: `crates/matchy-wasm/demo/js/workbench-app.mjs`
- Modify: `crates/matchy-wasm/demo/index.html`

- [ ] **Step 1: Create the browser workbench UI module**

Create `crates/matchy-wasm/demo/js/workbench-app.mjs`:

```javascript
import init, { Database, ExtractorBuilder, version } from "../pkg/matchy_wasm.js";

import {
  applyLineScan,
  createScanState,
  normalizeFeedMetadata,
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

function renderHits() {
  if (app.scanState.hits.length === 0) {
    html("hits-table-body", '<tr><td colspan="6" style="color: var(--text-dim);">No matches found yet.</td></tr>');
    return;
  }

  const rows = app.scanState.hits
    .slice()
    .sort((a, b) => b.count - a.count || a.indicator.localeCompare(b.indicator))
    .map((hit) => {
      const originalIndex = app.scanState.hits.indexOf(hit);
      return `
      <tr class="hit-row" data-hit-index="${originalIndex}">
        <td>${escapeHtml(hit.indicator)}</td>
        <td>${escapeHtml(hit.type)}</td>
        <td>${escapeHtml(hit.severity)}</td>
        <td>${escapeHtml(hit.source)}</td>
        <td>${escapeHtml(hit.malware || "")}</td>
        <td>${hit.count}</td>
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
    html("evidence-lines", '<span style="color: var(--text-dim);">Matching source lines appear here.</span>');
    return;
  }

  const lines = app.scanState.evidenceLines
    .slice(-100)
    .map((line) => `
      <div class="evidence-line">
        <strong>${escapeHtml(line.fileName)}:${line.lineNumber}</strong>
        ${highlightIndicator(line.lineText, line.indicator)}
      </div>
    `)
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
    .map((line) => `${escapeHtml(line.fileName)}:${line.lineNumber} ${highlightIndicator(line.lineText, hit.indicator)}`)
    .join("\n");

  html("hit-detail", `
    <strong>${escapeHtml(hit.indicator)}</strong>
    <pre>${escapeHtml(JSON.stringify(hit.metadata, null, 2))}</pre>
    <strong>Matching lines</strong>
    <pre>${lineList}</pre>
  `);
}

function renderCliHandoff(files) {
  if (!files || files.length === 0) {
    html("cli-handoff", "After a scan, equivalent CLI commands appear here.");
    return;
  }

  const fileNames = Array.from(files).map((file) => file.name).join(" ");
  html("cli-handoff", `<pre>matchy match demo-threats.mxy ${escapeHtml(fileNames)} --stats</pre>`);
}

function renderAll(elapsedMs = 0) {
  renderSummary(elapsedMs);
  renderHits();
  renderEvidenceLines();
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

async function scanFile(file) {
  app.scanState.filesScanned += 1;
  app.scanState.bytesScanned += file.size;

  let lineNumber = 1;
  let carry = "";
  let pendingLines = [];
  const decoder = new TextDecoder();

  if (!file.stream) {
    const textContent = await file.text();
    const split = splitCompleteLines("", textContent);
    pendingLines = split.lines.concat(split.carry ? [split.carry] : []);
    lineNumber = scanLineBatch(file.name, lineNumber, pendingLines);
    renderAll(performance.now() - app.scanStartedAt);
    return;
  }

  const reader = file.stream().getReader();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    const chunkText = decoder.decode(value, { stream: true });
    const split = splitCompleteLines(carry, chunkText);
    carry = split.carry;
    pendingLines.push(...split.lines);

    while (pendingLines.length >= BATCH_RENDER_LINES) {
      const batch = pendingLines.splice(0, BATCH_RENDER_LINES);
      lineNumber = scanLineBatch(file.name, lineNumber, batch);
      renderAll(performance.now() - app.scanStartedAt);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  const finalText = decoder.decode();
  if (finalText) {
    const split = splitCompleteLines(carry, finalText);
    carry = split.carry;
    pendingLines.push(...split.lines);
  }
  if (carry) pendingLines.push(carry);
  if (pendingLines.length > 0) lineNumber = scanLineBatch(file.name, lineNumber, pendingLines);
  renderAll(performance.now() - app.scanStartedAt);
}

async function scanFiles(files) {
  if (!app.db || !app.extractor) return;

  app.scanState = createScanState();
  app.scanStartedAt = performance.now();
  renderWorkbenchStatus("Scanning locally...");
  renderCliHandoff(files);
  renderAll(0);

  for (const file of files) {
    await scanFile(file);
  }

  renderAll(performance.now() - app.scanStartedAt);
  renderWorkbenchStatus(`Scan complete. ${app.scanState.matchesFound.toLocaleString()} matches found locally.`);
}

function setupDropZone() {
  const dropZone = document.getElementById("evidence-drop-zone");
  const fileInput = document.getElementById("evidence-file-input");
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener("click", () => fileInput.click());
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
    await init();
    app.extractor = new ExtractorBuilder().build();

    renderWorkbenchStatus("Loading bundled feed...");
    await loadBundledFeed();
    renderFeedStatus();
    setupDropZone();
    renderWorkbenchStatus("Ready. Drop a log file to scan locally.");
  } catch (error) {
    renderWorkbenchStatus(error instanceof Error ? error.message : String(error));
    html("hits-table-body", '<tr><td colspan="6" style="color: var(--accent);">Workbench failed to initialize. Advanced tools may still work below.</td></tr>');
  }
}

main();
```

- [ ] **Step 2: Build the WASM package for the demo**

Run:

```bash
cd crates/matchy-wasm
wasm-pack build --target web --out-dir demo/pkg
```

Expected: command exits successfully and updates `crates/matchy-wasm/demo/pkg`.

- [ ] **Step 3: Serve the demo**

Run:

```bash
cd crates/matchy-wasm/demo
python3 -m http.server 8080
```

Expected: server starts on `http://0.0.0.0:8080/`.

- [ ] **Step 4: Verify a scan manually in the browser**

Create a temporary local file outside the repo, such as `/tmp/matchy-workbench-smoke.log`, with this content:

```text
2026-07-04T12:00:00Z vpn accepted connection from 198.51.100.23
2026-07-04T12:00:01Z proxy requested http://malware.example.com/payload
2026-07-04T12:00:02Z dns query for harmless.example
```

Open `http://localhost:8080/`, drop the file onto the workbench, and verify:

- Feed status shows `Matchy bundled threat feed sample`.
- Summary shows `1` file and at least `2` matches.
- Hits table contains `198.51.100.23` and `malware.example.com`.
- Evidence lines highlight the matching indicators.
- CLI handoff shows `matchy match demo-threats.mxy matchy-workbench-smoke.log --stats`.

- [ ] **Step 5: Commit the workbench wiring**

Stop the Python server, then run:

```bash
git add crates/matchy-wasm/demo/js/workbench-app.mjs crates/matchy-wasm/demo/pkg crates/matchy-wasm/demo/index.html
git commit -m "Wire browser analyst workbench"
```

## Task 5: Preserve Advanced Tools and Fix Import Drop Zone Copy

**Files:**
- Modify: `crates/matchy-wasm/demo/index.html`

- [ ] **Step 1: Update the advanced tools summary copy**

Find:

```html
<summary>Advanced database builder, import, query, and extractor tools</summary>
```

Replace it with:

```html
<summary>Advanced tools: build feeds, import data, query one indicator, or test extraction</summary>
```

- [ ] **Step 2: Update the existing import drop zone copy so it does not compete with the evidence drop zone**

Find the existing import panel drop zone text:

```html
<p>📁 Drop a CSV or JSON file here</p>
<p style="font-size: 0.85rem; margin-top: 0.5rem;">or click to browse</p>
```

Replace it with:

```html
<p>Drop a feed file here</p>
<p style="font-size: 0.85rem; margin-top: 0.5rem;">CSV, JSON, or text indicators</p>
```

- [ ] **Step 3: Run the JavaScript unit tests**

Run:

```bash
node --test crates/matchy-wasm/demo/js/workbench-core.test.mjs
```

Expected: PASS.

- [ ] **Step 4: Verify advanced builder still works manually**

Serve the demo, open the advanced tools, click `Load Samples`, click `Build Database`, switch to `Query`, query `test.evil.com`, and verify the query result shows a match for `*.evil.com`.

- [ ] **Step 5: Commit the advanced tools polish**

Run:

```bash
git add crates/matchy-wasm/demo/index.html
git commit -m "Polish advanced demo tools"
```

## Task 6: Link the Workbench From Public Docs

**Files:**
- Modify: `README.md`
- Modify: `book/src/introduction.md`
- Modify: `crates/matchy-wasm/demo/README.md`

- [ ] **Step 1: Add a browser workbench link to the README intro**

In `README.md`, after the opening command example block, add:

```markdown
## Try It in Your Browser

The [Matchy Analyst Workbench](https://matchylabs.github.io/matchy/demo/) loads a bundled `.mxy` threat database and scans dropped log files locally in your browser. It is the fastest way to feel the workflow before installing the CLI.
```

- [ ] **Step 2: Add the workbench to the book introduction**

In `book/src/introduction.md`, after the first paragraph, add:

```markdown
Want to try Matchy before installing anything? Open the [Matchy Analyst Workbench](https://matchylabs.github.io/matchy/demo/) to scan log files locally in your browser against a bundled demo threat database.
```

- [ ] **Step 3: Replace the demo README opening with the analyst workbench description**

In `crates/matchy-wasm/demo/README.md`, replace the first two paragraphs with:

```markdown
# Matchy Analyst Workbench

Interactive local-first browser workbench for Matchy WASM. The page loads a bundled `.mxy` threat database, lets users drop log files into the browser, extracts indicators, and matches them locally without uploading evidence.
```

- [ ] **Step 4: Add the static feed asset section to the demo README**

In `crates/matchy-wasm/demo/README.md`, after the feature list, add:

```markdown
## Bundled Feed Assets

The workbench loads these static assets from `demo/assets/`:

- `demo-threats.mxy` - Matchy database used by the default workbench flow
- `demo-threats.json` - metadata shown in the feed status cards
- `demo-threats.csv` - source CSV used to regenerate the database

Regenerate the database with:

```bash
cargo run -p matchy -- build crates/matchy-wasm/demo/assets/demo-threats.csv --output crates/matchy-wasm/demo/assets/demo-threats.mxy --input-format csv
```
```

- [ ] **Step 5: Commit docs links**

Run:

```bash
git add README.md book/src/introduction.md crates/matchy-wasm/demo/README.md
git commit -m "Point users to browser analyst workbench"
```

## Task 7: Publish the Demo With GitHub Pages Docs

**Files:**
- Modify: `.github/workflows/deploy-docs.yml`

- [ ] **Step 1: Extend the docs deployment trigger paths**

In `.github/workflows/deploy-docs.yml`, replace:

```yaml
    paths:
      - 'book/**'
      - '.github/workflows/deploy-docs.yml'
```

with:

```yaml
    paths:
      - 'book/**'
      - 'crates/matchy-wasm/**'
      - 'crates/matchy/**'
      - 'Cargo.toml'
      - 'Cargo.lock'
      - '.github/workflows/deploy-docs.yml'
```

- [ ] **Step 2: Install `wasm-pack` in the docs deployment job**

In `.github/workflows/deploy-docs.yml`, add this step immediately after `Install Rust (for preprocessors)`:

```yaml
      - name: Install wasm-pack
        run: cargo install wasm-pack
```

- [ ] **Step 3: Build and copy the demo into the Pages artifact**

In `.github/workflows/deploy-docs.yml`, add this step immediately after `Build book` and before `Upload artifact`:

```yaml
      - name: Build and copy browser demo
        run: |
          wasm-pack build crates/matchy-wasm --target web --out-dir demo/pkg
          rm -rf book/book/demo
          mkdir -p book/book/demo
          cp -R crates/matchy-wasm/demo/. book/book/demo/
```

- [ ] **Step 4: Verify the artifact layout locally**

Run:

```bash
cd book
mdbook build
cd ..
wasm-pack build crates/matchy-wasm --target web --out-dir demo/pkg
rm -rf book/book/demo
mkdir -p book/book/demo
cp -R crates/matchy-wasm/demo/. book/book/demo/
test -f book/book/demo/index.html
test -f book/book/demo/assets/demo-threats.mxy
test -f book/book/demo/pkg/matchy_wasm.js
```

Expected: all commands exit successfully.

- [ ] **Step 5: Commit deployment wiring**

Run:

```bash
git add .github/workflows/deploy-docs.yml
git commit -m "Publish browser demo with docs"
```

## Task 8: Final Verification

**Files:**
- No new files.

- [ ] **Step 1: Run JavaScript unit tests**

Run:

```bash
node --test crates/matchy-wasm/demo/js/workbench-core.test.mjs
```

Expected: PASS.

- [ ] **Step 2: Run Rust formatting check**

Run:

```bash
cargo fmt -- --check
```

Expected: PASS.

- [ ] **Step 3: Run focused WASM crate tests**

Run:

```bash
cargo test -p matchy-wasm
```

Expected: PASS.

- [ ] **Step 4: Run focused clippy**

Run:

```bash
cargo clippy -p matchy-wasm -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Build the browser package**

Run:

```bash
cd crates/matchy-wasm
wasm-pack build --target web --out-dir demo/pkg
```

Expected: PASS and generated package files in `crates/matchy-wasm/demo/pkg`.

- [ ] **Step 6: Run final browser smoke**

Serve the demo:

```bash
cd crates/matchy-wasm/demo
python3 -m http.server 8080
```

Open `http://localhost:8080/`, drop `/tmp/matchy-workbench-smoke.log`, and verify:

- Workbench initializes without console errors.
- Feed status cards show metadata.
- Dropping the file starts scanning without clicking another button.
- Hits, evidence lines, and CLI handoff render.
- Advanced tools expand and still build/query a sample database.

- [ ] **Step 7: Stop the local server and inspect git status**

Run:

```bash
git status --short
```

Expected: no unstaged implementation changes except unrelated pre-existing files the user already had in the workspace.
