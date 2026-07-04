import test from "node:test";
import assert from "node:assert/strict";

import {
  buildFeedMetadata,
  normalizeThreatFoxRows,
  parseThreatFoxCsv,
  toMatchyCsv,
} from "./build-threatfox-recent-feed.mjs";

const fixture = `################################################################\r
# ThreatFox IOCs: recent additions - CSV format                #\r
# Last updated: 2026-07-04 22:19:04 UTC                        #\r
#\r
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"\r
"2026-07-04 22:19:04", "1844855", "dazayse.hi-lo.bet", "domain", "payload_delivery", "js.clearfake", "None", "ClearFake", "", "100", "False", "None", "ClearFake,win-0x4679,windows", "1", "anonymous"\r
"2026-07-04 21:46:30", "1844853", "64.227.143.36:5555", "ip:port", "botnet_cc", "win.cobalt_strike", "Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "2026-07-04 22:46:23", "75", "False", "None", "CobaltStrike,drb-ra", "0", "abuse_ch"\r
"2026-07-04 19:15:03", "1844827", "https://drfitness.fit/path?q=a,b", "url", "payload_delivery", "win.vidar", "None", "Vidar", "", "75", "True", "None", "ClickFix,compromised,Vidar", "1", "anonymous"\r
# Number of entries: 3\r
`;

test("parseThreatFoxCsv reads commented headers and quoted rows", () => {
  const rows = parseThreatFoxCsv(fixture);

  assert.equal(rows.length, 3);
  assert.equal(rows[0].ioc_value, "dazayse.hi-lo.bet");
  assert.equal(rows[1].ioc_type, "ip:port");
  assert.equal(rows[1].malware_alias, "Agentemis,BEACON,CobaltStrike,cobeacon");
  assert.equal(rows[2].ioc_value, "https://drfitness.fit/path?q=a,b");
  assert.equal(rows[2].tags, "ClickFix,compromised,Vidar");
});

test("normalizeThreatFoxRows keeps exact IOCs and adds extractor aliases", () => {
  const entries = normalizeThreatFoxRows(parseThreatFoxCsv(fixture));

  assert.equal(entries.length, 5);
  assert.deepEqual(
    entries.map((entry) => entry.entry),
    [
      "dazayse.hi-lo.bet",
      "64.227.143.36:5555",
      "64.227.143.36",
      "https://drfitness.fit/path?q=a,b",
      "drfitness.fit",
    ],
  );

  const alias = entries.find((entry) => entry.entry === "64.227.143.36");
  assert.equal(alias.ioc_type, "ip");
  assert.equal(alias.original_ioc, "64.227.143.36:5555");
  assert.equal(alias.normalized_from, "ip:port");
  assert.equal(alias.severity, "medium");

  const host = entries.find((entry) => entry.entry === "drfitness.fit");
  assert.equal(host.ioc_type, "domain");
  assert.equal(host.original_ioc, "https://drfitness.fit/path?q=a,b");
  assert.equal(host.normalized_from, "url");
  assert.equal(host.malware, "Vidar");
});

test("toMatchyCsv emits stable headers and escapes metadata", () => {
  const csv = toMatchyCsv(normalizeThreatFoxRows(parseThreatFoxCsv(fixture)));
  const lines = csv.trimEnd().split("\n");

  assert.equal(
    lines[0],
    "entry,severity,confidence,source,feed,threat_type,malware,first_seen,last_seen,reference,tags,ioc_id,ioc_type,original_ioc,normalized_from",
  );
  assert.match(lines[3], /^64\.227\.143\.36,medium,75,/);
  assert.match(lines[4], /^"https:\/\/drfitness\.fit\/path\?q=a,b",medium,75,/);
});

test("buildFeedMetadata describes the generated public feed", () => {
  const metadata = buildFeedMetadata({
    entryCount: 5,
    generatedAt: "2026-07-04T22:30:00.000Z",
  });

  assert.deepEqual(metadata, {
    name: "ThreatFox recent IOC feed",
    generated_at: "2026-07-04T22:30:00.000Z",
    entry_count: 5,
    source: "abuse.ch ThreatFox recent CSV",
    source_url: "https://threatfox.abuse.ch/export/csv/recent/",
    disclaimer:
      "Static browser feed generated during GitHub Pages deployment. Matching runs locally in your browser; dropped files are not uploaded.",
  });
});
