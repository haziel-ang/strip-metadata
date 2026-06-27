# Changelog

## v1.9.8 — 2026-06-27

- Info badge: cerchio pieno blu con `i` bianca.
- Fix z-index popup: i controlli lingua/tema non restano più sopra il popup
  su mobile.

## v1.9.7 — 2026-06-27

- Versione rimossa da header e footer: appare solo nell'intestazione del
  popup Info.

## v1.9.6 — 2026-06-27

- Versione spostata dal footer all'header, accanto ai badge.

## v1.9.5 — 2026-06-27

- Rimossi lucchetto e icona info dal footer: restano solo nell'header.

## v1.9.4 — 2026-06-27

- Header semplificato: badge `🔒 Elaborazione locale` + icona `ℹ`.
  Rimossi `100% nel tuo browser` e `Come funziona`.
- Versione mostrata nell'intestazione del popup Info.

## v1.9.3 — 2026-06-27

- IT: rinominato "Limiti onesti" → "Limiti reali".

## v1.9.2 — 2026-06-27

- Rimossi i testi lunghi da header e footer.
- Spostati nel popup Info: sicurezza (CSP, offline), HEIC, SynthID.
- Aggiunte sezioni "Sicurezza" e "SynthID" nel popup.

## v1.9.1 — 2026-06-27

- Aggiunta tagline riassuntiva sotto il sottotitolo: descrive la webapp
  in una riga.
- Icona `ℹ` accanto alla tagline: apre il popup Info con tutti gli
  approfondimenti.

## v1.9.0 — 2026-06-27

- Parsing migliorato dei metadati testuali PNG: supporto per blocchi
  tEXt, iTXt (compresso e non), zTXt (compresso).
- I blocchi compressi con keyword sospette (prompt, parameters, comfy,
  stable, generation) vengono segnalati come "compressed text metadata"
  nell'analisi AI.
- UI improvements.

## v1.8.0

- Caricamento multiplo (batch): seleziona più immagini, vengono pulite
  in serie una alla volta.
- Ogni immagine mostra miniatura, dimensione originale → pulita, badge
  AI se rilevato.
- Pulsante "Scarica tutte" per download sequenziale.
- Versione nel footer.

## v1.7.0

- Rilevamento provenienza AI nei file WebP: parsing del contenitore RIFF
  per chunk EXIF, XMP, ICCP, C2PA.
- Set di firme AI molto ampliato: oltre 40 generatori riconosciuti.

## v1.6.0

- Riga GPS cliccabile: apre un popup con le coordinate.
- Tre azioni: apri in OpenStreetMap, apri in Google Maps, copia
  coordinate.
- Privacy-safe: la mappa si apre in una nuova scheda solo su clic
  esplicito.

## v1.5.3

- Open Graph / Twitter cards per anteprime social.
- Immagine di preview `og.png`.

## v1.5.2

- Contatore locale in `localStorage`: "X immagini ripulite su questo
  dispositivo".
- Nessuna rete: il contatore è solo locale.

## v1.5.1

- Nuovo logo noMeta: diaframma SVG al posto della `o`, theme-adaptive.
- Favicon coordinata.

## v1.5.0

- Hero brand: logo SVG + wordmark "noMeta".
- Favicon, page title e description.

## v1.4.2

- Nota "Perché non rileva SynthID?" resa comprimibile (`<details>`).

## v1.4.1

- Pulizia JPEG idempotente: rimuove i marker APP/COM che il browser
  reinserisce dopo la codifica canvas. Il file esportato è pulito
  anche se ricaricato.

## v1.4.0

- Nuovo slogan, inglese + tema scuro come default, palette blu
  elettrico.
- Animazioni leggere (card, mesh, scan, float).

## v1.3.0

- JavaScript separato in `app.js` (CSP `script-src 'self'` senza
  `unsafe-inline`).
- Internazionalizzazione IT/EN con `data-i18n`.
- Tema chiaro/scuro/sistema.

## v1.2.0

- Hardening di sicurezza: CSP restrittiva, anti-XSS (`esc()` su tutti
  i metadati), anti-clickjacking.
- Font incorporati in base64 (pagina offline autosufficiente).

## v1.1.0

- Analisi origine AI basata sui metadati: C2PA, IPTC DigitalSourceType,
  nomi generatori, parametri di workflow.
- [`RESEARCH.md`](./RESEARCH.md) con la ricerca sulla provenienza AI.

## v1.0.0

- Upload immagine, parsing EXIF (GPS, fotocamera, data, software).
- Pulizia via `<canvas>` e download del file pulito.
- Supporto JPEG, PNG, HEIC.
