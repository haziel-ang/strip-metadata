# Changelog

## v1.13.0 — 2026-08-17

- Rimozione selettiva: ogni voce conservabile ha una casella nella modale di
  analisi, spuntata per default. Deselezionandola il dato resta nel file pulito.
  Il pulsante diretto «Pulisci i metadati» continua a rimuovere tutto.
- Voci conservabili: posizione GPS, fotocamera, data e ora, software, autore e
  copyright. ICC e C2PA restano sempre rimossi — un ICC reinserito falserebbe i
  colori dopo la ricodifica e un manifest C2PA sarebbe comunque invalido.
- Analisi estesa ai tag EXIF `Artist` (0x013B) e `Copyright` (0x8298), che prima
  non venivano letti né mostrati.
- Nuovo scrittore EXIF in `src/metadata/exif.ts`, coperto da test di round-trip
  contro il lettore gemello: GPS nei quattro emisferi, troncamento delle stringhe,
  ordinamento delle entry per tag, offset pari, nessun denominatore nullo.
  Gemello vanilla in `app.js`, come già per `ai.ts`.
- Due motori di pulizia selezionabili: ricodifica su canvas (default, whitelist —
  esce solo ciò che noMeta riscrive) e taglio senza ricodifica (blacklist —
  qualità intatta, ma sopravvive ciò che il parser non riconosce). Il motore
  senza ricodifica non è disponibile per HEIC, che va convertito.
- L'orientamento EXIF viene riportato dal motore senza ricodifica, così
  l'immagine non risulta ruotata dopo la pulizia; con la ricodifica non viene
  mai riscritto, perché la rotazione è già nei pixel.
- Corretto: il chunk `ICCP` inserito dall'encoder del browser sopravviveva alla
  pulizia dei WebP. Ora i contenitori PNG e WebP vengono sempre ricostruiti dopo
  la codifica, come già avveniva per i marker APP dei JPEG.
- Il caricamento multiplo (batch) resta invariato: rimuove tutto.

## v1.12.1 — 2026-07-17

- Corretto il rilevamento dell'origine AI nelle scansioni consecutive: ogni
  nuova selezione invalida in modo sicuro i risultati asincroni precedenti.
- Il formato reale viene ora riconosciuto dalla firma binaria, permettendo di
  analizzare correttamente anche immagini WebP salvate o nominate come PNG.
- Rafforzata l'analisi di metadati PNG, JPEG, WebP e C2PA con ricomposizione dei
  frammenti, limiti cumulativi e decompressione bounded contro input malevoli.
- Distinti i contenitori C2PA generici dagli indicatori forti associati a un
  generatore AI noto, riducendo i falsi positivi.
- Migliorato l'aggiornamento della cache PWA per distribuire subito la nuova
  versione online mantenendo il fallback offline.

## v1.12.0 — 2026-07-17

- Trasformata la webapp in PWA installabile con manifest e service worker.
- Aggiunto funzionamento offline tramite cache dei soli asset statici locali;
  le immagini dell'utente non vengono mai inserite nella cache.
- Aggiunto set coordinato di icone per favicon, iOS, Android/desktop e
  launcher adattivi (`maskable`).

## v1.11.0 — 2026-06-28

- Analisi AI PNG asincrona con decompressione locale dei chunk `zTXt` e
  `iTXt` compressi tramite `DecompressionStream`.
- Riconoscimento ampliato di generatori/frasi OpenAI, ChatGPT, GPT-4o e
  dichiarazioni come "edited with AI" / "powered by AI".
- Vista tecnica nella modale di analisi con chunk letti, decompressi/falliti
  ed estratto grezzo sanitizzato.
- Avviata migrazione conservativa React/TypeScript con core AI testabile,
  fixture Vitest per `tEXt`, `zTXt`, `iTXt` e shell `react.html`.

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
