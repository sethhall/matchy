#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const THREATFOX_RECENT_CSV_URL =
  "https://threatfox.abuse.ch/export/csv/recent/";

const THREATFOX_COLUMNS = [
  "first_seen_utc",
  "ioc_id",
  "ioc_value",
  "ioc_type",
  "threat_type",
  "fk_malware",
  "malware_alias",
  "malware_printable",
  "last_seen_utc",
  "confidence_level",
  "is_compromised",
  "reference",
  "tags",
  "anonymous",
  "reporter",
];

const MATCHY_COLUMNS = [
  "entry",
  "severity",
  "confidence",
  "source",
  "feed",
  "threat_type",
  "malware",
  "first_seen",
  "last_seen",
  "reference",
  "tags",
  "ioc_id",
  "ioc_type",
  "original_ioc",
  "normalized_from",
];

function cleanValue(value) {
  const text = String(value ?? "").trim();
  return text === "None" ? "" : text;
}

function parseCsvRecords(text) {
  const records = [];
  let record = [];
  let field = "";
  let inQuotes = false;
  let fieldWasQuoted = false;

  function pushField() {
    record.push(fieldWasQuoted ? field.trimEnd() : field.trim());
    field = "";
    fieldWasQuoted = false;
  }

  function pushRecord() {
    pushField();
    if (record.some((value) => value !== "")) {
      records.push(record);
    }
    record = [];
  }

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (inQuotes) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"' && field.trim() === "") {
      inQuotes = true;
      fieldWasQuoted = true;
      field = "";
    } else if (char === ",") {
      pushField();
    } else if (char === "\n") {
      pushRecord();
    } else if (char === "\r") {
      if (text[index + 1] === "\n") index += 1;
      pushRecord();
    } else {
      field += char;
    }
  }

  if (inQuotes) {
    throw new Error("Unterminated quoted CSV field");
  }
  if (field !== "" || record.length > 0) {
    pushRecord();
  }

  return records;
}

function parseCommentedHeader(line) {
  const uncommented = line.replace(/^#\s*/, "").trim();
  if (!uncommented.includes("ioc_value")) return null;

  const [header] = parseCsvRecords(uncommented);
  return header?.length ? header.map(cleanValue) : null;
}

export function parseThreatFoxCsv(text) {
  let header = THREATFOX_COLUMNS;
  const dataLines = [];

  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "") continue;

    if (trimmed.startsWith("#")) {
      const parsedHeader = parseCommentedHeader(trimmed);
      if (parsedHeader) header = parsedHeader;
      continue;
    }

    dataLines.push(line);
  }

  return parseCsvRecords(dataLines.join("\n")).map((record) => {
    const row = {};
    header.forEach((column, index) => {
      row[column] = cleanValue(record[index]);
    });
    return row;
  });
}

function severityFromConfidence(confidence) {
  const score = Number(confidence);
  if (!Number.isFinite(score)) return "unknown";
  if (score >= 90) return "high";
  if (score >= 70) return "medium";
  if (score >= 40) return "low";
  return "info";
}

function isIp(value) {
  return (
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) ||
    /^[0-9a-f:]+$/i.test(value)
  );
}

function bareIpFromIpPort(value) {
  const ipv4 = value.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
  if (ipv4) return ipv4[1];

  const bracketedIpv6 = value.match(/^\[([0-9a-f:]+)\]:\d+$/i);
  if (bracketedIpv6) return bracketedIpv6[1];

  return "";
}

function hostnameFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

function baseEntryFromRow(row, entry, iocType, normalizedFrom = "") {
  const originalIoc = cleanValue(row.ioc_value);
  const confidence = cleanValue(row.confidence_level);
  const malware =
    cleanValue(row.malware_printable) ||
    cleanValue(row.fk_malware) ||
    cleanValue(row.malware_alias);

  return {
    entry,
    severity: severityFromConfidence(confidence),
    confidence,
    source: "abuse.ch ThreatFox",
    feed: "ThreatFox recent",
    threat_type: cleanValue(row.threat_type),
    malware,
    first_seen: cleanValue(row.first_seen_utc),
    last_seen: cleanValue(row.last_seen_utc),
    reference: cleanValue(row.reference),
    tags: cleanValue(row.tags),
    ioc_id: cleanValue(row.ioc_id),
    ioc_type: iocType,
    original_ioc: originalIoc,
    normalized_from: normalizedFrom,
  };
}

function shouldReplaceEntry(candidate, existing) {
  if (!candidate.normalized_from && existing.normalized_from) return true;

  const candidateConfidence = Number(candidate.confidence);
  const existingConfidence = Number(existing.confidence);
  if (Number.isFinite(candidateConfidence) && Number.isFinite(existingConfidence)) {
    if (candidateConfidence !== existingConfidence) {
      return candidateConfidence > existingConfidence;
    }
  }

  return candidate.first_seen > existing.first_seen;
}

export function normalizeThreatFoxRows(rows) {
  const entries = [];
  const seen = new Map();

  function add(entry) {
    if (!entry.entry) return;

    const existingIndex = seen.get(entry.entry);
    if (existingIndex === undefined) {
      seen.set(entry.entry, entries.length);
      entries.push(entry);
      return;
    }

    if (shouldReplaceEntry(entry, entries[existingIndex])) {
      entries[existingIndex] = entry;
    }
  }

  for (const row of rows) {
    const originalIoc = cleanValue(row.ioc_value);
    const originalType = cleanValue(row.ioc_type);
    if (!originalIoc) continue;

    add(baseEntryFromRow(row, originalIoc, originalType));

    if (originalType === "ip:port") {
      const bareIp = bareIpFromIpPort(originalIoc);
      if (bareIp && bareIp !== originalIoc) {
        add(baseEntryFromRow(row, bareIp, "ip", "ip:port"));
      }
    }

    if (originalType === "url") {
      const hostname = hostnameFromUrl(originalIoc);
      if (hostname && hostname !== originalIoc) {
        add(
          baseEntryFromRow(
            row,
            hostname,
            isIp(hostname) ? "ip" : "domain",
            "url",
          ),
        );
      }
    }
  }

  return entries;
}

function csvEscape(value) {
  const text = String(value ?? "");
  if (/[",\r\n]/.test(text)) {
    return `"${text.replaceAll('"', '""')}"`;
  }
  return text;
}

export function toMatchyCsv(entries) {
  const lines = [
    MATCHY_COLUMNS.join(","),
    ...entries.map((entry) =>
      MATCHY_COLUMNS.map((column) => csvEscape(entry[column])).join(","),
    ),
  ];
  return `${lines.join("\n")}\n`;
}

export function buildFeedMetadata({
  entryCount,
  generatedAt = new Date().toISOString(),
  sourceUrl = THREATFOX_RECENT_CSV_URL,
}) {
  return {
    name: "ThreatFox recent IOC feed",
    generated_at: generatedAt,
    entry_count: entryCount,
    source: "abuse.ch ThreatFox recent CSV",
    source_url: sourceUrl,
    disclaimer:
      "Static browser feed generated during GitHub Pages deployment. Matching runs locally in your browser; dropped files are not uploaded.",
  };
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      throw new Error(`Unexpected argument: ${arg}`);
    }

    const key = arg.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${arg}`);
    }
    options[key] = value;
    index += 1;
  }
  return options;
}

async function readInput({ input, url }) {
  if (input) {
    return fs.readFile(input, "utf8");
  }

  const feedUrl = url || THREATFOX_RECENT_CSV_URL;
  const response = await fetch(feedUrl);
  if (!response.ok) {
    throw new Error(`ThreatFox fetch failed: ${response.status} ${response.statusText}`);
  }
  return response.text();
}

async function writeFileEnsuringDirectory(filePath, contents) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, contents);
}

export async function run(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const outputCsv = options["output-csv"];
  const outputJson = options["output-json"];

  if (!outputCsv || !outputJson) {
    throw new Error("Both --output-csv and --output-json are required");
  }

  const sourceUrl = options.url || THREATFOX_RECENT_CSV_URL;
  const sourceText = await readInput({ input: options.input, url: options.url });
  const rows = parseThreatFoxCsv(sourceText);
  const entries = normalizeThreatFoxRows(rows);

  if (entries.length === 0) {
    throw new Error("ThreatFox feed produced no Matchy entries");
  }

  const generatedAt = options["generated-at"] || new Date().toISOString();
  const metadata = buildFeedMetadata({
    entryCount: entries.length,
    generatedAt,
    sourceUrl,
  });

  await writeFileEnsuringDirectory(outputCsv, toMatchyCsv(entries));
  await writeFileEnsuringDirectory(outputJson, `${JSON.stringify(metadata, null, 2)}\n`);

  console.log(
    `Generated ${entries.length} Matchy feed entries from ${rows.length} ThreatFox rows`,
  );
}

const isDirectRun =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  run().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
