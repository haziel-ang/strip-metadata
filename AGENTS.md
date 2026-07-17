# Project memory

## Purpose

`noMeta` analyzes and removes image metadata entirely in the browser. The
privacy promise is a product requirement: selected images and generated files
must never leave the user's device.

## Architecture

- `index.html` and `app.js` are the current stable, dependency-free UI.
- `react.html` and `src/` contain the incremental React/TypeScript migration.
- Move pure metadata logic into `src/metadata/` and cover it with tests before
  replacing equivalent legacy behavior.
- The application is static and has no backend, runtime secrets, analytics, or
  telemetry.

## Non-negotiable security constraints

- Keep image parsing and conversion local to the browser.
- Do not add network calls, remote APIs, CDNs, remote fonts, trackers, or
  runtime dependencies that fetch resources.
- Preserve the restrictive Content Security Policy, especially
  `connect-src 'none'` and `default-src 'none'`.
- Treat all metadata as untrusted input. Escape it before inserting it into the
  DOM and never introduce executable markup from image data.
- Keep SVG excluded from accepted uploads.
- Preserve file-size, pixel-count, metadata-size, and EXIF-string limits that
  protect against local denial of service.
- Keep JPEG post-processing that removes APP and COM markers reintroduced by
  browser encoding.
- Changes affecting privacy or hardening must remain consistent with
  `SECURITY.md` and the claims in `README.md`.

## Supported behavior

- Cleaning: JPEG, PNG, WebP, and HEIC (converted to JPEG).
- Metadata analysis: JPEG, PNG, and WebP; HEIC support is partial.
- AI-origin analysis uses metadata and provenance signals only. It does not
  inspect pixels and cannot detect pixel watermarks such as SynthID.
- Absence of metadata is not proof that an image is human-made.

## Development workflow

Use the repository scripts:

```sh
npm test
npm run build
npm run dev
```

Before considering a code change complete, run at least `npm test` and
`npm run build`. Add or update focused tests for changes to metadata parsers or
AI-origin classification.

The Vite build must remain deployable as static files with relative paths for
GitHub Pages. Do not require server-side code or environment variables.

## Documentation and releases

- Update `README.md` when supported formats, user-visible behavior, privacy
  guarantees, or development architecture changes.
- Update `SECURITY.md` when a security control or known limitation changes.
- Record user-visible releases in `CHANGELOG.md` and keep `package.json`
  versioning consistent with the release.
- Before committing or publishing a release, always ask the user for explicit
  confirmation. Also ask which changelog is required: technical or public.
- A technical changelog belongs only in `CHANGELOG.md`. A public changelog is
  shown in the in-app release popup and must be short, concrete, and free of
  implementation details. Do not silently turn one type into the other.

## Local-only paths

- `.codex/` is local Codex tooling configuration and is not project memory.
- `truck-map/` is a separate local project and is outside this repository's
  scope.
