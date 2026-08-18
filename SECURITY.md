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
| 12 | **Cap cumulativo sui metadati analizzati e decompressi (2 MB)** e sulle stringhe EXIF (512 char) | `app.js` | **DoS / memoria**: segmenti di metadati abnormi o testo PNG compresso espanso a dismisura |
| 13 | **`localStorage` in `try/catch`** (lingua/tema) | `app.js` | **Crash** dove lo storage è disabilitato (es. modalità privata) |
| 14 | **Cache PWA con allowlist chiusa dei soli asset statici** | `sw.js` | **Persistenza involontaria di dati utente**: immagini originali, anteprime e file puliti non entrano mai nella cache offline |

## Cosa NON protegge (limiti dichiarati)

- **Watermark nei pixel (es. Google SynthID)**: non sono né rilevabili né rimovibili
  lato browser. La pulizia rimuove i metadati, non i watermark di pixel.
- **Motore «senza ricodifica»**: è una scelta esplicita dell'utente e cambia il
  modello di garanzia. La ricodifica su canvas è una **whitelist** — sopravvivono
  solo i pixel, più i campi EXIF che noMeta riscrive lei stessa da valori già
  interpretati. Il taglio senza ricodifica è invece una **blacklist**: rimuove i
  segmenti che il parser riconosce (APP1-APP15 e COM nei JPEG; `eXIf`, `tEXt`,
  `iTXt`, `zTXt`, `tIME`, `iCCP`, `caBX` nei PNG; `EXIF`, `XMP `, `ICCP`, `C2PA`
  nei WebP) e copia il resto invariato, compreso ciò che non conosce — segmenti
  esotici, thumbnail dentro l'EXIF, byte accodati dopo la fine dei dati immagine.
  In cambio la qualità dell'immagine resta intatta. Il default resta la ricodifica.
- **«Usa la mia posizione»**: il pulsante chiama `navigator.geolocation`, che è
  un'API del browser e non una richiesta della pagina — la CSP `connect-src 'none'`
  non la intercetta e in DevTools continui a non vedere richieste. Su telefono la
  posizione arriva dal GPS ed è tutto locale; su computer però il browser può
  ricavarla **contattando un servizio di rete** con i dati di WiFi e celle. Non lo
  fa noMeta, ma succede sul dispositivo dell'utente: per questo il pulsante è
  facoltativo, accompagnato da una nota esplicita, e le coordinate si possono
  sempre scrivere a mano senza che nulla esca.
- **Voci conservate su richiesta**: se l'utente deseleziona una voce, quel dato
  resta nel file per sua scelta esplicita. Sono conservabili solo campi EXIF di
  base riscritti da noMeta (GPS, fotocamera, data, software, autore, copyright):
  ICC e C2PA non sono conservabili proprio per non reimmettere byte opachi.
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
