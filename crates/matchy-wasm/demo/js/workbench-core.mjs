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
  return `${normalizeIndicatorType(entity.type)}:${String(entity.value)}`;
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
