# strip-metadata

A lightweight, 100% client-side web app to analyze images, strip metadata, and
export clean files. No image ever leaves your device.

## Why it's safe even though it runs in a browser

**EN —** A web page is just code your browser downloads **once**. From that
moment your photo is processed **entirely on your device**, in memory, using the
browser's built-in tools (Canvas). It is never sent anywhere. This isn't only a
promise: a strict security policy (`Content-Security-Policy: connect-src 'none'`)
**technically blocks the page from making any network request**, so it *cannot*
upload your image even if it wanted to. Proof: switch on airplane mode and it
still works; or open DevTools → Network and you'll see zero uploads.

**IT —** Una pagina web è solo codice che il browser scarica **una volta**. Da
quel momento la tua foto viene elaborata **interamente sul tuo dispositivo**, in
memoria, con gli strumenti integrati del browser (Canvas), e non viene mai
inviata. Non è solo una promessa: una policy di sicurezza rigida
(`Content-Security-Policy: connect-src 'none'`) **impedisce tecnicamente alla
pagina qualsiasi richiesta di rete**, quindi *non può* caricare la tua immagine
nemmeno volendo. Prova del nove: attiva la modalità aereo e funziona lo stesso;
oppure apri DevTools → Network e vedrai zero upload.

## Struttura

- `index.html` — markup + CSS (font incorporati in base64) e i controlli lingua/tema.
- `app.js` — tutta la logica (separata dall'HTML per una CSP più stretta).
- `SECURITY.md` — sintesi dell'hardening: ogni misura e *cosa evita*.
- `RESEARCH.md` — ricerca su provenienza AI, C2PA, IPTC, SynthID.

> Apertura locale: per via della CSP (`script-src 'self'`), apri tramite un piccolo
> server (`python3 -m http.server`) anziché con doppio clic su `file://`. Su GitHub
> Pages funziona direttamente.

## Lingua e tema

- **Doppia lingua IT/EN** con selettore in alto a destra (rilevamento automatico
  dalla lingua del browser, scelta salvata in `localStorage`).
- **Tema** Sistema / Chiaro / Scuro (di default segue il dispositivo).

## Features

- **Pulisci i metadati** — re-encodes the image via `<canvas>` to remove EXIF
  (GPS, camera, timestamp, software), XMP, IPTC, ICC and embedded **C2PA /
  Content Credentials** manifests.
- **Analizza origine AI** — reads the file's *metadata only* to look for
  AI-provenance signals: C2PA manifest, IPTC `DigitalSourceType`
  (`trainedAlgorithmicMedia`, …), XMP markers, and known AI generator names
  (Midjourney, DALL·E, Firefly, Gemini/Imagen, Stable Diffusion, …).
- **Popup analitico** — shows the cleaned/removed metadata and the AI-origin
  verdict in one place.

### Important limitation

The AI analysis inspects **metadata only**. It does **not** detect invisible
pixel-domain watermarks such as Google **SynthID** — those require Google's
official detector and cannot be verified in a browser. Absence of metadata does
not prove an image is not AI-generated.

See [`RESEARCH.md`](./RESEARCH.md) for the full research on AI image provenance,
C2PA, IPTC, SynthID, and watermark robustness.

## License

© 2026 **profxeni** — licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/):
you may copy and remix it, as long as you credit the author. See [`LICENSE`](./LICENSE).

## Ethics

Stripping metadata has strong legitimate privacy uses (protecting GPS/home
location, journalists, activists). Do **not** use it to pass AI content off as
real or to remove someone else's attribution; in some jurisdictions (e.g. the EU
AI Act) disclosure of AI origin is mandatory.
