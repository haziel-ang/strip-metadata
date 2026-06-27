# noMeta — strip image metadata

Una webapp che analizza e pulisce i metadati delle immagini direttamente
nel browser. Niente upload, niente server, niente telemetria. Funziona
offline.

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

La pagina carica una **Content Security Policy** che vieta qualsiasi
richiesta di rete (`connect-src 'none'`). Il JavaScript è in un file
separato (`app.js`) così la CSP può bloccare anche gli script inline
(`script-src 'self'`). L'immagine viene elaborata in memoria tramite
l'API Canvas del browser e il risultato è un Blob scaricabile.
Nessun dato esce dal dispositivo.

Prova: attiva la **modalità aereo** e funziona comunque.

## Formati supportati

| Formato | Pulizia | Analisi AI | Note |
|---|---|---|---|
| JPEG | Sì | Sì | Rimuove anche marker APP/COM reinseriti dal browser |
| PNG | Sì | Sì | Legge blocchi tEXt, iTXt, zTXt (anche compressi) |
| WebP | Sì | Sì | Rileva EXIF, XMP, C2PA nel contenitore RIFF |
| HEIC | Sì (→JPG) | Parziale | Convertito in JPG; metadati rimossi |

## Privacy

- **Contatore locale** in `localStorage`: quante immagini hai ripulito su
  *questo* dispositivo. Nessun dato esce dal browser.
- Lingua e tema salvati in `localStorage`, nessun cookie.
- Nessuna libreria esterna, nessun font da Google, nessun CDN.
  La pagina è un HTML + un JS autosufficienti.

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
| `SECURITY.md` | Hardening CSP, anti-XSS, anti-clickjacking |
| `RESEARCH.md` | Ricerca su provenienza AI, C2PA, IPTC, SynthID |
| `CHANGELOG.md` | Cronologia versioni |
