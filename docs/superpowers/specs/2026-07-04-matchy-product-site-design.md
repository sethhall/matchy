# Matchy Product Site Design

## Goal

Turn the GitHub Pages site served at `matchylabs.com/matchy/` into two Matchy-specific public surfaces for analysts and detection engineers:

- a small, fast product homepage
- a separate analyst console app

The homepage should not feel like generic project documentation. It should orient people quickly and send them to the console, CLI install path, or docs. The analyst console should be the useful surface where users drop evidence, scan it locally in the browser, and inspect matches.

## Public Positioning

The public story is only Matchy:

- Matchy browser workbench
- Matchy CLI and library
- Local browser matching
- Bundled static demo `.mxy` feed
- Documentation and GitHub

Do not mention FeedForge, internal feed generation, future internal products, or a broader Matchylabs product suite. If internal tooling later generates public feed artifacts, the site should describe only the generated static Matchy database and its metadata.

## Site Structure

The preferred public routes are:

- `/matchy/` - Matchy product homepage
- `/matchy/console/` - full browser analyst console
- `/matchy/demo/` - compatibility alias or redirect to the analyst console
- `/matchy/docs/` - mdBook documentation
- `/matchy/installation` or `/matchy/docs/getting-started/installation.html` - install path, linked from the homepage

The site should remain easy to move to a dedicated Matchy domain later. Links from the product homepage should be relative where practical, so the same artifact can work under `matchylabs.com/matchy/` and a future Matchy-specific domain.

To avoid breaking existing documentation links unnecessarily, the deployment may keep existing mdBook pages at their current root paths while also copying the book under `/docs/`. The product homepage should own the root `index.html`.

## First Impression

Use the "Quiet Analyst Console" direction:

- restrained, operational, analyst-native
- dark but not theatrical
- readable, calm, and tool-like
- enough visual interest to feel memorable, without cyber-drama

The homepage first viewport should communicate:

- "Open the console. Drop logs. Match intrusions. Keep evidence local."
- files are processed locally in the analyst console
- no account, setup, or upload is required for the browser console
- the full workbench and CLI are one click away

Primary CTA:

- `Open Analyst Console`

Secondary CTA:

- `Install CLI`

## Homepage Scope

The homepage should be intentionally small:

- static HTML/CSS with minimal JavaScript
- no WASM load
- no bundled feed download
- no file drop handling
- no IndexedDB handoff
- no console implementation hidden in the first page

This keeps the product page fast and dependable. Its job is to create confidence and route people into the correct next surface.

The homepage may include a visual console preview, but it should not be an active scanner.

## Analyst Console

The analyst console is the full browser app. It should load WASM, the bundled demo `.mxy` feed, and the workbench JavaScript only when the user opens the console route.

The console should remain the useful analyst surface:

- bundled feed status
- drop zone
- summary counters
- hits table
- hit detail
- evidence lines
- CLI handoff
- advanced tools below

Direct drag/drop scanning in the console remains the primary interaction. Dropping files on the homepage is not part of this iteration.

The existing single-flight scan guard should continue to prevent overlapping scans from corrupting console state.

The `/demo/` route should continue to work as an alias, redirect, or copy of the console so current links do not break.

## Content Below the Fold

The homepage should include compact proof sections after the first viewport:

- Local by design: files stay in the browser when using the analyst console.
- Built for analysts: match IPs, domains, hashes, literals, and patterns.
- Fast path to production use: analyst console first, CLI for local workflows, Rust/C API for integration.
- Static demo feed: bundled sample `.mxy` database with transparent metadata.

Keep these sections concise. The homepage should drive action, not become the book.

## Performance Budget

The homepage should not pay the console's load cost.

Current console-heavy assets include the WASM package, demo workbench HTML/JS, and bundled feed. Those should load on `/console/` or `/demo/`, not on `/matchy/`.

Homepage target:

- no `matchy_wasm_bg.wasm` request
- no `.mxy` feed request
- no workbench module request
- static HTML/CSS sized for a fast first paint

The console can optimize separately, but it is allowed to be heavier because the user has explicitly opened the tool.

## Deployment

The Pages workflow should build and publish a single artifact that includes:

- product homepage at the artifact root
- analyst console at `console/`
- compatibility demo route at `demo/`
- docs at `docs/`

The deployment should keep the demo path compatible with the current workbench route. The README and book introduction should point to the new product homepage and analyst console route; `/demo/` can remain as a compatibility route for existing links.

## Testing

Minimum verification:

- homepage loads from the built Pages artifact
- homepage CTA links resolve under the repository Pages base path
- homepage does not request WASM, `.mxy`, or workbench modules
- console route loads the analyst console
- direct console drag/drop works
- console route scans dropped files locally
- existing advanced demo tools still work
- compatibility demo route works
- `cargo test`
- `cargo clippy -- -D warnings`
- browser smoke for the built static artifact

## Non-Goals

- No FeedForge public mention.
- No account system.
- No server-side upload or processing.
- No live feed API.
- No database/backend selection.
- No dedicated Matchy domain in this iteration.
- No full redesign of the mdBook content.
- No homepage file-drop handoff in this iteration.
