# Matchy Product Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a fast Matchy product homepage at the Pages root and keep the full WASM analyst console behind a separate route.

**Architecture:** Add a lightweight static homepage source under `crates/matchy-wasm/site/`, keep the existing WASM demo source as the analyst console implementation, and update the Pages workflow to compose one artifact with root homepage, `/console/`, `/demo/` compatibility redirect, and `/docs/`. Add a small Node smoke script that checks the built static artifact for route presence and verifies the homepage does not reference WASM, `.mxy`, or workbench modules.

**Tech Stack:** Static HTML/CSS, existing mdBook build, existing `wasm-pack` build, Node.js built-in modules for smoke checks, existing Rust/Cargo verification.

---

## File Structure

- Create `crates/matchy-wasm/site/index.html`
  - Lightweight product homepage source. It links to `console/`, `docs/`, install docs, and GitHub using relative or stable URLs.
- Create `crates/matchy-wasm/site/styles.css`
  - Homepage-only styling. No dependency on the console CSS, WASM package, or mdBook theme.
- Create `crates/matchy-wasm/site/demo-redirect.html`
  - Compatibility redirect copied to `book/book/demo/index.html`.
- Create `scripts/smoke-pages-site.js`
  - Static artifact checks for homepage, console route, demo redirect, docs copy, and homepage asset budget.
- Modify `.github/workflows/deploy-docs.yml`
  - Build mdBook, copy mdBook into `docs/`, copy homepage to root, build/copy console to `console/`, copy redirect to `demo/`.
- Modify `crates/matchy-wasm/demo/index.html`
  - Rename visible product language from “Analyst Workbench” to “Analyst Console” where it affects the page title and first screen.
- Modify `crates/matchy-wasm/demo/README.md`
  - Explain that this source powers the published console and the `/demo/` compatibility route.
- Modify `README.md`
  - Point users to the new product homepage and analyst console route.
- Modify `book/src/introduction.md`
  - Point docs readers to the product homepage and analyst console route.

## Task 1: Add Static Artifact Smoke Test

**Files:**
- Create: `scripts/smoke-pages-site.js`

- [ ] **Step 1: Create the failing smoke script**

Create `scripts/smoke-pages-site.js`:

```js
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
```

- [ ] **Step 2: Run the smoke script and verify it fails before implementation**

Run:

```bash
node scripts/smoke-pages-site.js
```

Expected: FAIL with `product homepage missing at artifact root` if `book/book` does not exist, or another missing-route error if a stale artifact exists.

- [ ] **Step 3: Commit the failing smoke script**

Run:

```bash
git add scripts/smoke-pages-site.js
git commit -m "Add Pages site smoke test"
```

## Task 2: Add Lightweight Product Homepage Source

**Files:**
- Create: `crates/matchy-wasm/site/index.html`
- Create: `crates/matchy-wasm/site/styles.css`
- Create: `crates/matchy-wasm/site/demo-redirect.html`

- [ ] **Step 1: Create the product homepage HTML**

Create `crates/matchy-wasm/site/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matchy - Local IoC Matching for Analysts</title>
    <meta name="description" content="Matchy scans logs locally for IPs, domains, hashes, literals, and patterns using fast browser and CLI IoC matching.">
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header class="site-header">
        <a class="brand" href="./" aria-label="Matchy home">
            <span class="brand-mark">M</span>
            <span>Matchy</span>
        </a>
        <nav class="nav-links" aria-label="Primary navigation">
            <a href="console/">Console</a>
            <a href="docs/">Docs</a>
            <a href="https://github.com/matchylabs/matchy">GitHub</a>
        </nav>
    </header>

    <main>
        <section class="hero">
            <div class="hero-copy">
                <p class="eyebrow">Local IoC matching</p>
                <h1>Open the console. Drop logs. Match intrusions. Keep evidence local.</h1>
                <p class="lede">
                    Matchy gives analysts and detection engineers a browser console for trying local IoC matching,
                    plus a fast CLI and Rust library for real workflows.
                </p>
                <div class="actions" aria-label="Primary actions">
                    <a class="button primary" href="console/">Open Analyst Console</a>
                    <a class="button secondary" href="docs/getting-started/installation.html">Install CLI</a>
                </div>
                <p class="privacy-note">The console downloads static demo assets. Dropped files stay in your browser.</p>
            </div>

            <aside class="console-preview" aria-label="Analyst console preview">
                <div class="preview-toolbar">
                    <span></span>
                    <span></span>
                    <span></span>
                    <strong>matchy console</strong>
                </div>
                <div class="preview-drop">Drop evidence in the console</div>
                <div class="preview-stats">
                    <div><strong>1</strong><span>file</span></div>
                    <div><strong>2.1 MB</strong><span>scanned</span></div>
                    <div><strong>18</strong><span>hits</span></div>
                    <div><strong>0</strong><span>uploads</span></div>
                </div>
                <div class="preview-table">
                    <div><span>198.51.100.23</span><b>high</b><em>demo-malware</em></div>
                    <div><span>malware.example.com</span><b>high</b><em>demo-loader</em></div>
                    <div><span>*.bad-demo.example.com</span><b>medium</b><em>demo-phish</em></div>
                </div>
            </aside>
        </section>

        <section class="proof-grid" aria-label="Why Matchy">
            <article>
                <h2>Local by design</h2>
                <p>The browser console matches evidence locally. It does not upload dropped files.</p>
            </article>
            <article>
                <h2>Built for messy evidence</h2>
                <p>Extract and match IPs, domains, hashes, exact strings, CIDRs, and glob patterns.</p>
            </article>
            <article>
                <h2>Path to real workflows</h2>
                <p>Try the console first, then move to the CLI, Rust API, or C API when you need automation.</p>
            </article>
        </section>

        <section class="terminal-band">
            <div>
                <p class="eyebrow">CLI handoff</p>
                <h2>Use the same matching engine outside the browser.</h2>
            </div>
            <pre><code>matchy build threats.csv --output threats.mxy --input-format csv
matchy match threats.mxy auth.log --stats</code></pre>
        </section>
    </main>
</body>
</html>
```

- [ ] **Step 2: Create the homepage stylesheet**

Create `crates/matchy-wasm/site/styles.css`:

```css
:root {
    color-scheme: dark;
    --bg: #0e1418;
    --panel: #142029;
    --panel-strong: #192b35;
    --text: #edf5f7;
    --muted: #9fb2bd;
    --line: #294351;
    --cyan: #5dd3ff;
    --green: #7ee787;
    --rose: #ff6b7d;
    --amber: #f8c555;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    line-height: 1.5;
}

a {
    color: inherit;
}

.site-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    width: min(1120px, calc(100% - 32px));
    margin: 0 auto;
    padding: 22px 0;
}

.brand,
.nav-links {
    display: flex;
    align-items: center;
    gap: 0.8rem;
}

.brand {
    text-decoration: none;
    font-weight: 800;
}

.brand-mark {
    display: inline-grid;
    place-items: center;
    width: 34px;
    height: 34px;
    border: 1px solid var(--line);
    border-radius: 7px;
    background: var(--panel);
    color: var(--cyan);
}

.nav-links a {
    color: var(--muted);
    font-size: 0.95rem;
    text-decoration: none;
}

.nav-links a:hover,
.nav-links a:focus-visible {
    color: var(--text);
}

main {
    width: min(1120px, calc(100% - 32px));
    margin: 0 auto;
}

.hero {
    display: grid;
    grid-template-columns: minmax(0, 0.95fr) minmax(360px, 1.05fr);
    align-items: center;
    gap: 44px;
    min-height: calc(100vh - 86px);
    padding: 24px 0 48px;
}

.eyebrow {
    margin: 0 0 12px;
    color: var(--cyan);
    font-size: 0.8rem;
    font-weight: 800;
    text-transform: uppercase;
}

h1,
h2,
p {
    margin-top: 0;
}

h1 {
    max-width: 780px;
    margin-bottom: 18px;
    font-size: clamp(2.4rem, 8vw, 5.4rem);
    line-height: 0.98;
}

.lede {
    max-width: 640px;
    color: var(--muted);
    font-size: 1.1rem;
}

.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin: 28px 0 14px;
}

.button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 46px;
    padding: 0 18px;
    border-radius: 7px;
    font-weight: 800;
    text-decoration: none;
}

.button.primary {
    background: var(--cyan);
    color: #051015;
}

.button.secondary {
    border: 1px solid var(--line);
    background: var(--panel);
    color: var(--text);
}

.privacy-note {
    color: var(--muted);
    font-size: 0.95rem;
}

.console-preview {
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
    background: var(--panel);
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.38);
}

.preview-toolbar {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--line);
    background: #101a20;
}

.preview-toolbar span {
    width: 10px;
    height: 10px;
    border-radius: 999px;
    background: var(--line);
}

.preview-toolbar span:nth-child(1) {
    background: var(--rose);
}

.preview-toolbar span:nth-child(2) {
    background: var(--amber);
}

.preview-toolbar span:nth-child(3) {
    background: var(--green);
}

.preview-toolbar strong {
    margin-left: auto;
    color: var(--muted);
    font-size: 0.82rem;
}

.preview-drop {
    margin: 18px;
    padding: 28px;
    border: 2px dashed #376074;
    border-radius: 8px;
    color: var(--text);
    text-align: center;
}

.preview-stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    padding: 0 18px 18px;
}

.preview-stats div,
.preview-table {
    border: 1px solid var(--line);
    border-radius: 7px;
    background: var(--panel-strong);
}

.preview-stats div {
    padding: 12px;
}

.preview-stats strong,
.preview-stats span {
    display: block;
}

.preview-stats span {
    color: var(--muted);
    font-size: 0.78rem;
}

.preview-table {
    margin: 0 18px 18px;
    overflow: hidden;
}

.preview-table div {
    display: grid;
    grid-template-columns: minmax(0, 1.3fr) 76px minmax(0, 1fr);
    gap: 10px;
    padding: 12px;
    border-bottom: 1px solid var(--line);
}

.preview-table div:last-child {
    border-bottom: 0;
}

.preview-table b {
    color: var(--amber);
}

.preview-table em {
    color: var(--muted);
    font-style: normal;
}

.proof-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    padding: 32px 0;
}

.proof-grid article,
.terminal-band {
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--panel);
}

.proof-grid article {
    padding: 22px;
}

.proof-grid h2,
.terminal-band h2 {
    margin-bottom: 8px;
    font-size: 1.2rem;
}

.proof-grid p,
.terminal-band p {
    color: var(--muted);
}

.terminal-band {
    display: grid;
    grid-template-columns: 0.85fr 1.15fr;
    gap: 24px;
    align-items: center;
    margin: 16px 0 56px;
    padding: 24px;
}

pre {
    margin: 0;
    overflow-x: auto;
    border-radius: 7px;
    background: #081015;
    color: var(--green);
    padding: 16px;
}

code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.9rem;
}

@media (max-width: 860px) {
    .site-header,
    .hero,
    .terminal-band {
        display: block;
    }

    .nav-links {
        margin-top: 14px;
    }

    .hero {
        min-height: auto;
        padding: 26px 0 40px;
    }

    .console-preview {
        margin-top: 30px;
    }

    .proof-grid {
        grid-template-columns: 1fr;
    }

    .terminal-band pre {
        margin-top: 16px;
    }
}
```

- [ ] **Step 3: Create the demo compatibility redirect source**

Create `crates/matchy-wasm/site/demo-redirect.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="0; url=../console/">
    <title>Opening Matchy Analyst Console</title>
    <link rel="canonical" href="../console/">
</head>
<body>
    <p>Opening the <a href="../console/">Matchy Analyst Console</a>.</p>
</body>
</html>
```

- [ ] **Step 4: Run a source-level check**

Run:

```bash
if rg -n "matchy_wasm|demo-threats|workbench-app" crates/matchy-wasm/site/index.html crates/matchy-wasm/site/styles.css; then
  echo "homepage source references console assets"
  exit 1
else
  echo "homepage source has no console asset references"
fi
```

Expected: `homepage source has no console asset references`.

- [ ] **Step 5: Commit the homepage source**

Run:

```bash
git add crates/matchy-wasm/site/index.html crates/matchy-wasm/site/styles.css crates/matchy-wasm/site/demo-redirect.html
git commit -m "Add lightweight Matchy homepage"
```

## Task 3: Publish Console, Demo Alias, and Docs Routes

**Files:**
- Modify: `.github/workflows/deploy-docs.yml`

- [ ] **Step 1: Update workflow artifact assembly**

Replace the `Build and copy browser demo` step in `.github/workflows/deploy-docs.yml` with:

```yaml
      - name: Build and assemble Pages site
        run: |
          wasm-pack build crates/matchy-wasm --target web --out-dir demo/pkg

          docs_tmp="$(mktemp -d)"
          cp -R book/book/. "$docs_tmp/"

          rm -rf book/book/docs
          mkdir -p book/book/docs
          cp -R "$docs_tmp"/. book/book/docs/
          rm -rf "$docs_tmp"

          cp crates/matchy-wasm/site/index.html book/book/index.html
          cp crates/matchy-wasm/site/styles.css book/book/styles.css

          rm -rf book/book/console
          mkdir -p book/book/console
          cp -R crates/matchy-wasm/demo/. book/book/console/

          rm -rf book/book/demo
          mkdir -p book/book/demo
          cp crates/matchy-wasm/site/demo-redirect.html book/book/demo/index.html

          node scripts/smoke-pages-site.js book/book
```

- [ ] **Step 2: Verify workflow syntax and route strings**

Run:

```bash
rg -n "Build and assemble Pages site|book/book/console|book/book/demo|smoke-pages-site" .github/workflows/deploy-docs.yml
```

Expected: all four strings are present.

- [ ] **Step 3: Commit the workflow update**

Run:

```bash
git add .github/workflows/deploy-docs.yml
git commit -m "Publish product homepage and console routes"
```

## Task 4: Reframe Workbench Source as Analyst Console

**Files:**
- Modify: `crates/matchy-wasm/demo/index.html`
- Modify: `crates/matchy-wasm/demo/README.md`

- [ ] **Step 1: Update visible console language**

In `crates/matchy-wasm/demo/index.html`, make these replacements:

```diff
-    <title>Matchy Analyst Workbench - Local IoC Matching</title>
+    <title>Matchy Analyst Console - Local IoC Matching</title>
@@
-        <h1><span>Matchy</span> Analyst Workbench</h1>
+        <h1><span>Matchy</span> Analyst Console</h1>
```

Leave function names like `renderWorkbenchStatus` alone in this task. They are internal implementation names and renaming them would add churn without improving the public route split.

- [ ] **Step 2: Update the demo README route explanation**

In `crates/matchy-wasm/demo/README.md`, change the title and the integration section to:

```markdown
# Matchy Analyst Console

Interactive local-first browser console for Matchy WASM. The page loads a bundled demo `.mxy` threat database, lets users drop log files into the browser, extracts indicators, and matches them locally without uploading the dropped files.
```

Replace the "Integrating with the Book" command block and route sentence with:

```markdown
The Pages workflow publishes this source in two places:

- `/console/` - primary analyst console route
- `/demo/` - compatibility redirect for existing links

From the repository root, the workflow builds the WASM package with:

```bash
wasm-pack build crates/matchy-wasm --target web --out-dir demo/pkg
```
```

- [ ] **Step 3: Verify public wording**

Run:

```bash
rg -n "Analyst Workbench|/demo/|Analyst Console|/console/" crates/matchy-wasm/demo/index.html crates/matchy-wasm/demo/README.md
```

Expected: `Analyst Console` is present in `index.html`; `/console/` and `/demo/` are described in `README.md`; no visible title/header still says `Analyst Workbench`.

- [ ] **Step 4: Commit the console wording update**

Run:

```bash
git add crates/matchy-wasm/demo/index.html crates/matchy-wasm/demo/README.md
git commit -m "Reframe browser demo as analyst console"
```

## Task 5: Update README and Book Links

**Files:**
- Modify: `README.md`
- Modify: `book/src/introduction.md`

- [ ] **Step 1: Update README browser section**

Replace the `## Try It in Your Browser` paragraph in `README.md` with:

```markdown
## Try It in Your Browser

Start at the [Matchy product page](https://matchylabs.github.io/matchy/) or open the [Matchy Analyst Console](https://matchylabs.github.io/matchy/console/) directly. The console loads a bundled demo `.mxy` threat database and scans dropped log files locally in your browser before you install the CLI.
```

- [ ] **Step 2: Update the book introduction link**

Replace the browser-demo paragraph in `book/src/introduction.md` with:

```markdown
Want to try Matchy before installing anything? Start at the [Matchy product page](https://matchylabs.github.io/matchy/) or open the [Matchy Analyst Console](https://matchylabs.github.io/matchy/console/) to scan log files locally in your browser against a bundled demo `.mxy` threat database.
```

- [ ] **Step 3: Verify no primary docs link still points directly to `/demo/`**

Run:

```bash
rg -n "matchylabs.github.io/matchy/demo|Matchy Analyst Workbench" README.md book/src/introduction.md
```

Expected: no matches.

- [ ] **Step 4: Commit link updates**

Run:

```bash
git add README.md book/src/introduction.md
git commit -m "Point users to Matchy homepage and console"
```

## Task 6: Build Artifact and Run Static Smoke

**Files:**
- Verify: `book/book/**` generated output, not committed

- [ ] **Step 1: Build the book**

Run:

```bash
cd book
mdbook build
```

Expected: PASS and `book/book/index.html` exists.

- [ ] **Step 2: Build the WASM package**

Run:

```bash
wasm-pack build crates/matchy-wasm --target web --out-dir demo/pkg
```

Expected: PASS and `crates/matchy-wasm/demo/pkg/matchy_wasm.js` exists.

- [ ] **Step 3: Assemble the Pages artifact locally**

Run these commands from the repository root:

```bash
docs_tmp="$(mktemp -d)"
cp -R book/book/. "$docs_tmp/"
rm -rf book/book/docs
mkdir -p book/book/docs
cp -R "$docs_tmp"/. book/book/docs/
rm -rf "$docs_tmp"
cp crates/matchy-wasm/site/index.html book/book/index.html
cp crates/matchy-wasm/site/styles.css book/book/styles.css
rm -rf book/book/console
mkdir -p book/book/console
cp -R crates/matchy-wasm/demo/. book/book/console/
rm -rf book/book/demo
mkdir -p book/book/demo
cp crates/matchy-wasm/site/demo-redirect.html book/book/demo/index.html
```

Expected: PASS and `book/book/console/index.html`, `book/book/demo/index.html`, and `book/book/docs/index.html` exist.

- [ ] **Step 4: Run the static smoke script**

Run:

```bash
node scripts/smoke-pages-site.js book/book
```

Expected: `Pages artifact smoke passed for book/book`.

- [ ] **Step 5: Verify generated output is ignored**

Run:

```bash
git status --short book/book
```

Expected: no tracked or untracked output from `book/book`.

## Task 7: Browser Smoke

**Files:**
- Verify: built static artifact under `book/book`

- [ ] **Step 1: Serve the built artifact locally**

Run from `book/book`:

```bash
node -e "const http=require('http');const fs=require('fs');const path=require('path');const root=process.cwd();const types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.mjs':'text/javascript','.wasm':'application/wasm','.json':'application/json','.mxy':'application/octet-stream'};const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://127.0.0.1');const pathname=url.pathname==='/'?'/index.html':url.pathname;const file=path.normalize(path.join(root,pathname));if(!file.startsWith(root)){res.writeHead(403);res.end('forbidden');return;}fs.readFile(file,(err,data)=>{if(err){res.writeHead(404);res.end('not found');return;}res.writeHead(200,{'content-type':types[path.extname(file)]||'application/octet-stream'});res.end(data);});});server.listen(8767,'127.0.0.1',()=>console.log('listening http://127.0.0.1:8767'));"
```

Expected: server prints `listening http://127.0.0.1:8767`.

- [ ] **Step 2: Verify homepage network budget in Chrome**

Open `http://127.0.0.1:8767/`.

Expected:

- Page title contains `Matchy - Local IoC Matching for Analysts`
- Network requests include `/index.html` and `/styles.css`
- Network requests do not include `.wasm`, `.mxy`, `workbench-app.mjs`, or `matchy_wasm.js`
- Primary CTA points to `/console/`

- [ ] **Step 3: Verify console route in Chrome**

Open `http://127.0.0.1:8767/console/`.

Expected:

- Page title contains `Matchy Analyst Console`
- Feed status reaches `Ready. Drop a log file to scan locally.`
- Network requests include `pkg/matchy_wasm.js`, `pkg/matchy_wasm_bg.wasm`, `assets/demo-threats.mxy`, and `assets/demo-threats.json`

- [ ] **Step 4: Verify console scan in Chrome**

Use a synthetic browser drop with this text:

```text
2026-07-04 src=198.51.100.23 host=malware.example.com hash=44d88612fea8a8f36de82e1278abb02f
```

Expected:

- Status starts with `Scan complete`
- Summary shows `3` matches or more if extraction finds additional matching entities
- Hits include `198.51.100.23`, `malware.example.com`, and `44d88612fea8a8f36de82e1278abb02f`

- [ ] **Step 5: Verify demo compatibility route**

Open `http://127.0.0.1:8767/demo/`.

Expected: browser navigates to or offers a link to `../console/`.

## Task 8: Final Verification and Review

**Files:**
- Verify entire branch

- [ ] **Step 1: Run formatting check**

Run:

```bash
cargo fmt -- --check
```

Expected: PASS.

- [ ] **Step 2: Run full Rust tests**

Run:

```bash
cargo test
```

Expected: PASS.

- [ ] **Step 3: Run full clippy**

Run:

```bash
cargo clippy -- -D warnings
```

Expected: PASS.

- [ ] **Step 4: Run JS/static smoke**

Run:

```bash
node --test crates/matchy-wasm/demo/js/workbench-core.test.mjs
node scripts/smoke-pages-site.js book/book
```

Expected: JS tests pass and static smoke prints `Pages artifact smoke passed for book/book`.

- [ ] **Step 5: Check git status**

Run:

```bash
git status --short
```

Expected: clean, except ignored generated output under `book/book` should not appear.

- [ ] **Step 6: Request final code review**

Use `superpowers:requesting-code-review` to review the full product site change against:

- `docs/superpowers/specs/2026-07-04-matchy-product-site-design.md`
- this implementation plan

Fix any Critical or Important findings before finishing.
