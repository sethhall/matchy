#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const root = process.argv[2] || "book/book";

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertNoHomepageConsoleAssets(homepage) {
  const forbidden = [
    "matchy_wasm_bg.wasm",
    "matchy_wasm.js",
    "workbench-app.mjs",
    "workbench-core.mjs",
    "demo-threats.mxy",
    "demo-threats.json",
  ];

  for (const token of forbidden) {
    assert(!homepage.includes(token), `homepage must not reference ${token}`);
  }
}

function assertHomepageLocalLinks(homepage) {
  const hrefPattern = /href="([^"#][^"]*)"/g;
  const missing = [];

  for (const [, href] of homepage.matchAll(hrefPattern)) {
    if (/^[a-z][a-z0-9+.-]*:/.test(href) || href.startsWith("//")) {
      continue;
    }

    const target = href.endsWith("/") ? `${href}index.html` : href;
    if (!exists(target)) {
      missing.push(href);
    }
  }

  assert(
    missing.length === 0,
    `homepage local links must exist in artifact: ${missing.join(", ")}`,
  );
}

function main() {
  assert(exists("index.html"), "product homepage missing at artifact root");
  assert(exists("styles.css"), "homepage stylesheet missing at artifact root");
  assert(exists("console/index.html"), "analyst console missing at console/index.html");
  assert(exists("console/js/workbench-app.mjs"), "console workbench module missing");
  assert(exists("console/pkg/matchy_wasm.js"), "console wasm JS package missing");
  assert(exists("console/assets/demo-threats.mxy"), "console bundled .mxy feed missing");
  assert(exists("demo/index.html"), "demo compatibility route missing");
  assert(exists("docs/index.html"), "docs copy missing at docs/index.html");

  const homepage = read("index.html");
  assert(homepage.includes("Open Analyst Console"), "homepage CTA missing");
  assert(homepage.includes('href="console/"'), "homepage console link must be relative");
  assert(homepage.includes('href="docs/"'), "homepage docs link must be relative");
  assertNoHomepageConsoleAssets(homepage);
  assertHomepageLocalLinks(homepage);

  const stylesheet = read("styles.css");
  assert(stylesheet.includes(".console-preview"), "homepage console preview styles missing");

  const demoRedirect = read("demo/index.html");
  assert(demoRedirect.includes("url=../console/"), "demo route must redirect to console");
  assert(demoRedirect.includes('href="../console/"'), "demo redirect must include a fallback link");

  const consoleHtml = read("console/index.html");
  assert(consoleHtml.includes("Analyst Console"), "console title/header should use Analyst Console");
  assert(consoleHtml.includes("./js/workbench-app.mjs"), "console must load workbench app module");

  console.log(`Pages artifact smoke passed for ${root}`);
}

main();
