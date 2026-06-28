# noMeta — strip image metadata

noMeta analizza e pulisce i metadati delle immagini **direttamente nel tuo
browser, sempre e solo in locale**. Non carica nulla su server remoti, non
usa API esterne, non raccoglie telemetria. Il file che scegli non lascia
mai il tuo dispositivo: viene letto in memoria, elaborato con le API
native del browser (Canvas, DataView, TextDecoder) e il risultato è un
Blob che puoi scaricare. Funziona anche offline.

Lo scopo è uno solo: **nessun dato deve poter uscire da questo ambiente**.
Ogni scelta tecnica — dalla Content Security Policy al design interno —
serve a garantirlo.

## Cosa fa

**Pulizia.** Ricodifica l'immagine tramite `<canvas>` e la riesporta senza
EXIF (GPS, fotocamera, data, software), XMP, IPTC, profilo colore ICC e
manifest **C2PA / Content Credentials**. Nei JPEG rimuove anche i marker
APP e COM che il browser reinserisce dopo la codifica, così il file
esportato è davvero pulito anche se lo ricarichi. I file HEIC vengono
convertiti in JPG. Supporta JPG, PNG, WebP, HEIC.

**Analisi AI.** Legge i metadati del file (non i pixel) e cerca segnali di
origine artificiale in quattro categorie:

1. **C2PA / Content Credentials** — manifest di provenienza incorporato
   nello standard C2PA (Adobe/CAI). Rileva il contenitore JUMBF nei
   JPEG/PNG/WebP e distingue azioni come `c2pa.created` (generata) e
   `c2pa.edited` / `c2pa.placed` (modificata con AI).

2. **IPTC DigitalSourceType** — etichetta standard per il giornalismo.
   Riconosce `trainedAlgorithmicMedia`, `compositeWithTrainedAlgorithmicMedia`,
   `compositeSynthetic` e `algorithmicMedia`.

3. **Software e generatori noti** — cerca nei metadati EXIF, XMP e blocchi
   testuali PNG/WebP i nomi di oltre 40 generatori: DALL·E, ChatGPT,
   Midjourney, Adobe Firefly, Gemini/Imagen, Stable Diffusion, ComfyUI,
   FLUX, Grok, Leonardo.Ai, Ideogram e molti altri.

4. **Parametri di workflow** — prompt, seed, sampler, model hash, CFG
   scale, steps, riferimenti a nodi ComfyUI. Più parametri coerenti
   compaiono insieme, più il segnale è affidabile.

Il verdetto è a tre livelli: **rilevato** (segnale forte, es. C2PA o
IPTC), **indizio** (tracce deboli), **nessun segnale** (metadati puliti).

## Cosa NON può fare (e perché)

**SynthID e watermark invisibili nei pixel.** Google ha sviluppato SynthID,
un watermark impercettibile codificato direttamente nei pixel delle
immagini generate da Gemini/Imagen. Rilevarlo richiede il detector
ufficiale di Google, che non è eseguibile in un browser. noMeta legge
solo i metadati: se un'immagine ha watermark nei pixel ma metadati puliti,
apparirà «nessun segnale». Per SynthID serve il [rilevatore
ufficiale](https://synthid.google.com).

**Metadati assenti ≠ immagine reale.** I metadati si rimuovono con
qualsiasi tool, incluso noMeta. L'assenza di segnali AI nei metadati
**non prova** che l'immagine sia umana.

**Metadati falsificabili.** Chi genera un'immagine AI può scrivere
EXIF fuorvianti (es. il modello di una fotocamera). Il verdetto è un
indizio tecnico, non una perizia forense.

**Niente analisi dei pixel.** Non usa reti neurali, non classifica il
contenuto visivo, non cerca artefatti di generazione. Solo metadati.

## Come funziona la sicurezza

Ogni elaborazione avviene **interamente in locale**, nel browser, senza
che alcun byte del file originale o dell'immagine pulita venga mai
inviato in rete. Questo vincolo non è una promessa: è imposto dal
browser stesso tramite una **Content Security Policy**.

La CSP dichiara `connect-src 'none'`: il browser **rifiuta a livello
di runtime** qualsiasi tentativo di connessione (fetch, XHR,
WebSocket, EventSource, beacon). Anche se codice malevolo provasse a
inviare dati, il browser lo bloccherebbe prima che il pacchetto esca
dalla macchina.

Il JavaScript è separato in `app.js` (`script-src 'self'` senza
`unsafe-inline`): questo impedisce l'esecuzione di script iniettati
nel markup, anche se qualcuno riuscisse a inserire HTML dannoso via
metadati. Ogni valore letto dal file passa attraverso una funzione di
escape prima di toccare il DOM.

Il flusso è: `File → ArrayBuffer → parsing EXIF/PNG/WebP (in memoria)
→ Canvas → Blob → download`. Il file originale non viene mai
caricato in rete — non c'è un `action` in un `<form>`, non c'è
nessuna chiamata HTTP.

Prova: attiva la **modalità aereo** e funziona comunque. Apri
DevTools → Network durante l'uso: vedrai **zero richieste**.

## Formati supportati

| Formato | Pulizia | Analisi AI | Note |
|---|---|---|---|
| JPEG | Sì | Sì | Rimuove anche marker APP/COM reinseriti dal browser |
| PNG | Sì | Sì | Legge blocchi tEXt, iTXt, zTXt (anche compressi) |
| WebP | Sì | Sì | Rileva EXIF, XMP, C2PA nel contenitore RIFF |
| HEIC | Sì (→JPG) | Parziale | Convertito in JPG; metadati rimossi |

## Privacy

Tutto ciò che accade, accade **solo sul tuo dispositivo, in locale**:

- **Il file che scegli** — viene aperto in memoria (ArrayBuffer), mai
  inviato a un server.
- **L'analisi dei metadati** — parsing binario diretto via DataView.
- **La pulizia** — ridisegno su Canvas, riesportazione come Blob.
- **Il contatore** (`localStorage`) — quante immagini hai ripulito su
  *questo* dispositivo. Nessun beacon, nessun analytics.
- **Lingua e tema** — salvati solo in `localStorage`. Nessun cookie.
- **Nessuna dipendenza runtime esterna**: niente Google Fonts, niente CDN,
  nessuna chiamata API. La versione stabile resta composta da file statici
  (`index.html` + `app.js`). Le dipendenze npm servono solo per build, test
  e migrazione React/TypeScript.

Il browser è l'ambiente, il browser è il limite. Niente esce, niente
entra.

## Etica

Rimuovere i metadati ha usi legittimi: proteggere il GPS di casa, il
modello del telefono, la data. Giornalisti, attivisti e chiunque voglia
privacy ne ha diritto.

**Non usarlo** per spacciare contenuti AI come reali o per rimuovere
l'attribuzione altrui. In molte giurisdizioni (es. EU AI Act) dichiarare
l'origine AI è obbligatorio.

## Licenza

© 2026 **profxeni** — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/):
puoi copiare e modificare, citando l'autore. Vedi [`LICENSE`](./LICENSE).

## File

| File | Contenuto |
|---|---|
| `index.html` | Markup, CSS (font in base64), controlli lingua/tema |
| `app.js` | Logica: parsing EXIF/PNG/WebP, pulizia, analisi AI, UI |
| `react.html` | Shell React/TypeScript separata per migrare senza sostituire la UI stabile |
| `src/metadata/ai.ts` | Primo core TypeScript testabile per analisi AI metadata |
| `src/metadata/ai.test.ts` | Fixture in memoria per PNG `tEXt`, `zTXt`, `iTXt` compressi |
| `SECURITY.md` | Hardening CSP, anti-XSS, anti-clickjacking |
| `RESEARCH.md` | Ricerca su provenienza AI, C2PA, IPTC, SynthID |
| `CHANGELOG.md` | Cronologia versioni |

## Sviluppo

La migrazione React/TypeScript procede in parallelo alla versione stabile:
prima si spostano le funzioni pure in `src/metadata/`, poi si coprono con
test, infine la UI React sostituirà gradualmente il DOM legacy.

Comandi utili:

```bash
npm test
npm run build
npm run dev
```

`npm run build` genera `dist/react.html` e asset statici: sono compatibili
con GitHub Pages perché non richiedono server, backend o variabili segrete.
GitHub Pages può ospitare la app finché tutto resta client-side; Python o
altro codice server richiederebbero invece un backend separato e romperebbero
la promessa "nessun upload", salvo uso puramente locale.
