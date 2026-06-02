# Sicurezza — sintesi dell'hardening (v1.3.0)

App **100% client-side**: l'immagine non viene mai caricata online, non c'è backend
né telemetria. Di seguito **ogni misura di sicurezza e cosa serve a evitare**.

## Riepilogo: misura → cosa evita

| # | Misura | Dove | Evita (minaccia) |
|---|--------|------|------------------|
| 1 | **Escape HTML di tutti i metadati non fidati** (`esc()`) prima di `innerHTML` | `app.js` | **XSS / HTML injection**: un'immagine con EXIF `Software=<img onerror=…>` non può eseguire codice |
| 2 | **JavaScript in file esterno** (`app.js`) + CSP `script-src 'self'` | `index.html`, `app.js` | **Esecuzione di script inline iniettati**: senza `'unsafe-inline'`, anche se venisse iniettato markup, il browser non eseguirebbe JS inline |
| 3 | **CSP `connect-src 'none'`** | `index.html` (meta) | **Esfiltrazione dei dati**: nessun `fetch`/XHR/`sendBeacon`/WebSocket può uscire dal dispositivo |
| 4 | **CSP `default-src 'none'`, `img-src 'self' data: blob:`, `font-src data:`, `style-src 'self' 'unsafe-inline'`** | `index.html` (meta) | **Caricamento di risorse esterne non previste**: nessun dominio di terze parti, niente tracker, nessun font remoto |
| 5 | **`base-uri 'none'`, `form-action 'none'`** | `index.html` (meta) | **Dirottamento via `<base>` e invio di form** verso destinazioni arbitrarie |
| 6 | **Anti-clickjacking**: **frame-buster JS** (e, se il sito è servito dietro Cloudflare con proxy attivo, una regola header `X-Frame-Options: DENY` / `frame-ancestors`) | `app.js` (+ Cloudflare) | **Clickjacking / UI redress**: la pagina non è utilizzabile dentro un `<iframe>` di terzi (`frame-ancestors` nel `<meta>` è ignorato dai browser, perciò va in un header lato CDN) |
| 7 | **`referrer: no-referrer`** | `index.html` (meta) | **Leak dell'URL** come header `Referer` verso origini esterne |
| 8 | **`window.open(..., "noopener,noreferrer")`** | `app.js` | **Tabnabbing**: la nuova scheda non può accedere a `window.opener` |
| 9 | **Allowlist tipi (`isAllowedType`)**: solo immagini raster, **SVG escluso** | `app.js` | **Payload attivi**: gli SVG possono contenere script; vengono rifiutati |
| 10 | **Tetto dimensione file (64 MB)** | `app.js` | **DoS in locale**: blocco/saturazione su file enormi |
| 11 | **Guardia "decompression bomb" (~80 MP)** prima di allocare il canvas | `app.js` | **Esaurimento memoria**: file piccolo che decodifica in un'immagine gigantesca |
| 12 | **Cap sui byte di metadati analizzati (2 MB)** e sulle stringhe EXIF (512 char) | `app.js` | **DoS / memoria**: segmenti di metadati abnormi |
| 13 | **`localStorage` in `try/catch`** (lingua/tema) | `app.js` | **Crash** dove lo storage è disabilitato (es. modalità privata) |

## Cosa NON protegge (limiti dichiarati)

- **Watermark nei pixel (es. Google SynthID)**: non sono né rilevabili né rimovibili
  lato browser. La pulizia rimuove i metadati, non i watermark di pixel.
- **`script-src 'unsafe-inline'` per gli stili**: gli stili inline restano ammessi
  (`style-src 'unsafe-inline'`). È un rischio molto inferiore rispetto agli script;
  i valori di stile non derivano da input utente.
- **Header HTTP** (`X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`,
  HSTS): non impostabili via `<meta>` e **non configurabili su GitHub Pages**. Per
  averli, servire il sito dietro un CDN che li inietta (es. **Cloudflare con proxy
  attivo** → Rules / Transform Rules → Response Headers).

## Nota su apertura locale (`file://`)

Con il JS in `app.js` e CSP `script-src 'self'`, alcuni browser (es. Chrome)
**bloccano lo script se la pagina è aperta con doppio clic** (`file://`), perché
l'origine `file://` non corrisponde a `'self'`. **Soluzione**: servire la cartella
con un piccolo server locale, ad esempio:

```
python3 -m http.server 8000   # poi apri http://localhost:8000
```

Su un server (anche GitHub Pages) funziona senza alcun accorgimento.
