# ThreatFox Pages Feed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate the deployed analyst console threat feed from ThreatFox recent CSV during GitHub Pages builds without storing rotating feed data in the repository.

**Architecture:** Keep the committed six-row feed as a local fallback. Add a Node-based normalizer that fetches or reads ThreatFox CSV, emits Matchy-compatible CSV plus feed metadata, and let the Pages workflow build the `.mxy` inside `book/book/console/assets` before upload. Add a scheduled workflow trigger so the deployed static artifact refreshes regularly.

**Tech Stack:** Node.js built-ins, GitHub Actions, existing `cargo run -p matchy -- build`, existing Pages artifact smoke script.

---

### Task 1: ThreatFox CSV Normalizer

**Files:**
- Create: `scripts/build-threatfox-recent-feed.mjs`
- Create: `scripts/build-threatfox-recent-feed.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `scripts/build-threatfox-recent-feed.test.mjs` with tests that import `parseThreatFoxCsv`, `normalizeThreatFoxRows`, and `buildFeedMetadata` from `scripts/build-threatfox-recent-feed.mjs`. The fixture must include a commented ThreatFox header, a domain row, an `ip:port` row, and a URL row with commas in tags.

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test scripts/build-threatfox-recent-feed.test.mjs`

Expected: FAIL because `scripts/build-threatfox-recent-feed.mjs` does not exist yet.

- [ ] **Step 3: Implement the normalizer**

Create `scripts/build-threatfox-recent-feed.mjs` with:
- A small CSV parser that supports quotes, escaped quotes, spaces after delimiters, comments, and CRLF.
- `parseThreatFoxCsv(text)` returning row objects using the commented ThreatFox header.
- `normalizeThreatFoxRows(rows)` returning Matchy CSV rows. It must keep the exact IoC and add extractor-friendly aliases for `ip:port` bare IPs and URL hostnames.
- `buildFeedMetadata({ entryCount, generatedAt })` returning deployed feed metadata.
- A CLI supporting `--input`, `--url`, `--output-csv`, and `--output-json`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test scripts/build-threatfox-recent-feed.test.mjs`

Expected: PASS.

### Task 2: Pages Workflow Feed Generation

**Files:**
- Modify: `.github/workflows/deploy-docs.yml`
- Modify: `scripts/smoke-pages-site.js`

- [ ] **Step 1: Add scheduled refresh**

Add `schedule` to the workflow trigger with a stable staggered cron such as `17 */6 * * *`.

- [ ] **Step 2: Generate feed only in the Pages artifact**

After copying `crates/matchy-wasm/demo/.` to `book/book/console/`, run:

```bash
node scripts/build-threatfox-recent-feed.mjs \
  --url https://threatfox.abuse.ch/export/csv/recent/ \
  --output-csv book/book/console/assets/demo-threats.csv \
  --output-json book/book/console/assets/demo-threats.json

cargo run -p matchy -- build book/book/console/assets/demo-threats.csv \
  --output book/book/console/assets/demo-threats.mxy \
  --input-format csv
```

- [ ] **Step 3: Extend the Pages smoke check**

Update `scripts/smoke-pages-site.js` to parse `console/assets/demo-threats.json` and require `source_url` to equal `https://threatfox.abuse.ch/export/csv/recent/`, `entry_count` to be a positive number, and `disclaimer` to mention local browser matching.

### Task 3: Docs And Verification

**Files:**
- Modify: `crates/matchy-wasm/demo/README.md`

- [ ] **Step 1: Document storage behavior**

Explain that committed assets are a tiny fallback, while GitHub Pages deploys a generated ThreatFox recent feed in the Pages artifact.

- [ ] **Step 2: Verify**

Run:

```bash
node --test scripts/build-threatfox-recent-feed.test.mjs
node --test crates/matchy-wasm/demo/js/workbench-core.test.mjs
node scripts/build-threatfox-recent-feed.mjs --input /tmp/threatfox-recent.csv --output-csv /tmp/demo-threats.csv --output-json /tmp/demo-threats.json
cargo run -p matchy -- build /tmp/demo-threats.csv --output /tmp/demo-threats.mxy --input-format csv
cargo run -p matchy -- inspect /tmp/demo-threats.mxy --json
```

Then assemble `book/book` locally, run `node scripts/smoke-pages-site.js book/book`, and run Rust formatting/lint/tests before completion.

---

## Self-Review

- Spec coverage: The plan keeps rotating ThreatFox data out of git, generates the deployed artifact during Pages builds, and adds scheduled updates.
- Placeholder scan: No placeholders or deferred decisions remain.
- Type consistency: The test and implementation names match across tasks.
