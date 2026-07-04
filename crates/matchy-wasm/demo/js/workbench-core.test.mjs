import test from "node:test";
import assert from "node:assert/strict";

import {
  applyLineScan,
  createScanState,
  formatBytes,
  normalizeFeedMetadata,
  shellQuote,
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

test("applyLineScan preserves indicator casing for case-sensitive lookups", () => {
  const state = createScanState();
  let lookupCalls = 0;
  const lookup = (indicator) => {
    lookupCalls += 1;
    if (indicator === "CaseSensitive.example") {
      return {
        severity: "medium",
        source: "case-sensitive feed",
      };
    }
    return null;
  };

  applyLineScan(state, {
    fileName: "dns.log",
    lineNumber: 20,
    lineText: "query casesensitive.example",
    entities: [{ type: "Domain", value: "casesensitive.example" }],
    lookup,
  });

  applyLineScan(state, {
    fileName: "dns.log",
    lineNumber: 21,
    lineText: "query CaseSensitive.example",
    entities: [{ type: "Domain", value: "CaseSensitive.example" }],
    lookup,
  });

  assert.equal(lookupCalls, 2);
  assert.equal(state.uniqueIndicatorsQueried, 2);
  assert.equal(state.matchesFound, 1);
  assert.equal(state.hits.length, 1);
  assert.equal(state.hits[0].indicator, "CaseSensitive.example");
});

test("summarizeScan and formatBytes provide stable display values", () => {
  const state = createScanState();
  state.filesScanned = 2;
  state.bytesScanned = 1536;
  state.linesScanned = 12;
  state.indicatorsExtracted = 4;
  state.uniqueIndicatorsQueried = 3;
  state.matchesFound = 1;
  state.errors.push({ indicator: "bad.example", message: "lookup failed" });

  assert.equal(formatBytes(1536), "1.5 KB");
  assert.deepEqual(summarizeScan(state, 42.125), {
    filesScanned: 2,
    bytesScanned: 1536,
    bytesDisplay: "1.5 KB",
    linesScanned: 12,
    indicatorsExtracted: 4,
    uniqueIndicatorsQueried: 3,
    matchesFound: 1,
    errorCount: 1,
    elapsedMs: 42.125,
  });
});

test("shellQuote renders copyable POSIX shell arguments", () => {
  assert.equal(shellQuote("plain.log"), "plain.log");
  assert.equal(shellQuote("auth log.csv"), "'auth log.csv'");
  assert.equal(shellQuote("bob's evidence.log"), "'bob'\\''s evidence.log'");
  assert.equal(shellQuote(""), "''");
});
