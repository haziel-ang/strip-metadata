# Metadati, provenienza e watermarking dell'AI nelle immagini

Report di ricerca per il progetto `strip-metadata` · giugno 2026.

> Nota sull'affidabilità: alcune fonti primarie (c2pa.org, deepmind.google,
> iptc.org, arxiv.org, nature.com) non sono state caricabili integralmente in
> fase di ricerca (HTTP 403); le citazioni derivano da ricerca web ristretta ai
> domini ufficiali e da fonti secondarie attendibili. Ogni affermazione riporta
> un livello di confidenza (alta/media/bassa).

## 0. In una frase

Esistono **due famiglie** di segnali che indicano l'origine di un'immagine: la
**provenienza nei metadati** (C2PA/Content Credentials, IPTC), che vive
nell'*header* del file ed è **fragile**, e il **watermark nei pixel** (Google
SynthID), che vive nel *contenuto* ed è **robusto**. Un'app che ricodifica
l'immagine via canvas rimuove la prima famiglia ma **non** la seconda. Questo è
il punto tecnico ed etico centrale.

## 1. Provenienza nei metadati: C2PA / Content Credentials e IPTC

- **C2PA** (Coalition for Content Provenance and Authenticity, derivata dalla
  CAI fondata da Adobe nel 2019) definisce un **manifest firmato
  crittograficamente** e *tamper-evident* incorporato nel file. [alta]
  - **Hard binding**: hash SHA-256 dei byte del contenuto incluso nel manifest;
    robusto a copia ma **si rompe a ogni ri-codifica**. [alta]
  - **Soft binding**: fingerprint percettivo o watermark invisibile come
    identificatore, per recuperare il manifest da un repository esterno (Soft
    Binding Resolution API) anche se i bit cambiano. [alta/media]
- **Dove sta nel file**: contenitore **JUMBF** (assertion in CBOR/JSON).
  - JPEG: marker **APP11** (`FFEB`), più segmenti contigui (≤64K ciascuno).
  - PNG: chunk privato **`caBX`** (non `iTXt`).
  - WebP: chunk `C2PA` nel container RIFF. [alta; WebP media]
- **IPTC "Digital Source Type"**: campo scritto nel pacchetto **XMP** per
  marcare media sintetici. Valore chiave **`trainedAlgorithmicMedia`** (AI
  generativa); altri: `compositeSynthetic`, `algorithmicMedia`. Standard IPTC
  Photo Metadata 2025.1 (nov 2025). Adottato anche dentro C2PA. [alta]

### Chi li legge/applica (2024–2026)

| Attore | Cosa fa | Conf. |
|---|---|---|
| Google | C2PA + SynthID in Search "About this image", Lens, Chrome; "dual-layer" annunciato 19 mag 2026 | alta |
| Meta | Label "AI Info"/"Made with AI" su FB/IG/Threads (da inizio 2024); legge C2PA e IPTC | alta |
| OpenAI | C2PA su DALL·E 3 (inizio 2024); esteso a GPT-image-1 e Sora 2 + SynthID (nov 2025) | alta |
| Adobe | Content Credentials automatiche su Firefly, Photoshop, Lightroom | alta |
| TikTok | Etichetta automatica "AI-generated" via C2PA (da gen 2025) | alta/media |
| Fotocamere | Leica M11-P (ott 2023, prima al mondo), Nikon Z9/Z8/Z6III, Sony Alpha — firma in-camera | media |

## 2. Il punto critico: cosa succede rimuovendo i metadati

- **C2PA non sopravvive allo stripping**: il blocco JUMBF è rimosso da
  screenshot, ri-codifica e dalle piattaforme social. Reporting 2026: stripping
  "di fatto 100%" su Instagram, X, LinkedIn, TikTok, Facebook, WhatsApp.
  [aiipprotection.org, tianpan.co — alta; cifra "100%" giornalistica → media]
- Lo **screenshot** crea un nuovo file di pixel → elimina ogni metadato. [alta]
- L'**hard binding** si rompe a ogni ri-codifica. [alta]
- Contromisura = **"Durable Content Credentials"** (Adobe/CAI): metadati firmati
  **+ watermark invisibile + fingerprint**; la credenziale si recupera dal cloud
  anche dopo strip o screenshot. [contentauthenticity.org 2024 — alta come claim]

> Conseguenza: rimuovere EXIF/XMP/IPTC/C2PA **non garantisce** che un'immagine AI
> diventi non tracciabile, perché restano watermark di pixel e fingerprint.

## 3. Google SynthID (watermark nei pixel)

- **Meccanismo**: watermark invisibile **nei pixel** (componenti in frequenza,
  distribuiti su tutta l'immagine), via due reti co-addestrate in modo
  avversariale. Lancio ago 2023. [deepmind.google/models/synthid — alta]
- **Robustezza dichiarata**: sopravvive a cropping, rotazione, compressione
  JPEG, ridimensionamento, cambi colore, filtri e **screenshot**. [alta]
- **Copertura**: testo (SynthID-Text, Nature ott 2024, open source), audio
  (Lyria), video (Veo). **SynthID Detector**: portale annunciato al Google I/O
  (20 mag 2025); >10 miliardi di contenuti marcati. [alta]
- **"Nano banana" = Gemini 2.5 Flash Image** (ago 2025): tutte le immagini
  includono SynthID, senza toggle ufficiale per disattivarlo. [media]
- **Limiti ammessi**: SynthID "not foolproof"; il watermark su **testo** è molto
  meno robusto. [mag 2025 — alta]

Differenza chiave: C2PA = dichiarazione firmata *negli header* (fragile);
SynthID = segnale *nei pixel* (robusto). Complementari ("defense-in-depth").

## 4. Robustezza e attacchi: letteratura accademica

La letteratura 2023–2025 è concorde: i watermark invisibili sono vulnerabili sia
a rimozione sia a contraffazione.

**Limiti teorici**
- *Watermarks in the Sand* (Zhang et al., ICML 2024,
  [arXiv 2311.04378](https://arxiv.org/abs/2311.04378)): un watermark "forte" è
  teoricamente impossibile. [alta]
- *Robustness of AI-Image Detectors* (Saberi et al., ICLR 2024,
  [arXiv 2310.00076](https://arxiv.org/abs/2310.00076)): trade-off fondamentale
  evasione/spoofing. [alta]

**Rimozione**
- *Invisible Image Watermarks Are Provably Removable* (Zhao et al., NeurIPS
  2024, [arXiv 2306.01953](https://arxiv.org/abs/2306.01953)): attacchi di
  rigenerazione rimuovono 93–99% dei watermark. [alta]
- *Leveraging Optimization for Adaptive Attacks* (Lukas et al., ICLR 2024,
  [arXiv 2309.16952](https://arxiv.org/abs/2309.16952)): rompe tutti i 5 schemi
  testati. [alta]
- **UnMarker** (Kassis & Hengartner, IEEE S&P 2025,
  [arXiv 2405.08363](https://arxiv.org/abs/2405.08363)): primo attacco
  universale; su SynthID immagini riduce la rilevazione da ~100% a ~21%. [alta
  sul fatto; media-alta sulla cifra]

**Spoofing/contraffazione**
- *DiffForge* ([arXiv 2503.22330](https://arxiv.org/abs/2503.22330), 2025):
  forgia watermark, inganna un'API commerciale Amazon >97%. [media]
- *Black-Box Forgery on Semantic Watermarks* (CVPR 2025,
  [arXiv 2412.03283](https://arxiv.org/abs/2412.03283)). [media-alta]

Maturità: la **rimozione è matura** (peer-reviewed, codice pubblico, vince
challenge); lo **spoofing cresce** ma con replicazione indipendente limitata. È
una corsa agli armamenti: i sistemi commerciali aggiornano le difese.

## 5. Il "hack di SynthID" e i repository GitHub

Esiste un **ecosistema** di tool. Va distinto il *watermark visibile* (il logo a
stella di Gemini) dal *watermark invisibile nei pixel* (il vero SynthID).

- **`aloshdenny/reverse-SynthID`** — <https://github.com/aloshdenny/reverse-SynthID>
  (mar 2026). Reverse-engineering del *detector* via analisi spettrale/Fourier
  (~123.000 immagini Gemini). Rivendica rilevamento ~90%. Caveat: validazione su
  ~20 immagini. Coperto da Medianama, byteiota, Stork.AI. [esistenza: alta;
  efficacia: media]
- **`wiltodelta/remove-ai-watermarks`** —
  <https://github.com/wiltodelta/remove-ai-watermarks> (~2.800★). Rimozione via
  rigenerazione a diffusione (SDXL img2img). Il README ammette che "SynthID è un
  bersaglio mobile" e perdita di qualità. [esistenza: alta; efficacia: media/bassa]
- **`00quebec/Synthid-Bypass`** — <https://github.com/00quebec/Synthid-Bypass>
  (~739★). Focalizzato su Nano Banana Pro, workflow ComfyUI. [replicabilità: alta]
- **Voce contraria autorevole — `allenk/GeminiWatermarkTool`** —
  <https://github.com/allenk/GeminiWatermarkTool> (~2.500★). Rimuove **solo il
  watermark visibile** e dichiara *"It does NOT remove SynthID"*; conclude che
  rimuovere SynthID a livello di pixel è **"attualmente non fattibile"** con
  strumenti pubblici. [alta]

**Verdetto onesto**: il "hack" è reale e documentato, ma la rimozione completa e
affidabile del watermark di pixel SynthID **resta non verificata in modo
indipendente e contestata** (campioni minimi, perdita di qualità, soglie che
Google sposta). Nessun takedown DMCA noto. Coerente con l'accademia: la rimozione
è *possibile* (UnMarker) ma richiede rigenerazione pesante, non un semplice strip.

Articoli: Medianama (apr 2026), TechBuzz.ai, byteiota, Stork.AI, Pasquale
Pillitteri, Medium dell'autore. Google avrebbe ridimensionato la cifra del 91%
(via The Verge). [esistenza articoli: alta; risposta Google: media]

## 6. Implicazioni per un'app che rimuove i metadati

Una pipeline `createImageBitmap → drawImage → canvas.toBlob` ricodifica i soli
pixel, quindi:

- ✅ **Rimuove** (header): EXIF (GPS, fotocamera, timestamp, software), XMP,
  IPTC `trainedAlgorithmicMedia`, ICC, **manifest C2PA/Content Credentials**.
- ❌ **NON rimuove** (pixel): watermark invisibili tipo **SynthID** e fingerprint
  percettivi → un'immagine AI resta potenzialmente rilevabile e ricollegabile al
  suo manifest "durevole".

### Cosa è possibile e lecito fare lato browser

- **Rilevare** la presenza di provenienza C2PA (APP11/JUMBF in JPEG, `caBX` in
  PNG), l'etichetta IPTC `DigitalSourceType`, marcatori XMP e nomi di software/
  generatori AI nei metadati. È una rilevazione **basata sui metadati**, onesta e
  trasparente.
- **NON è possibile** verificare il watermark SynthID nei pixel in un browser:
  serve il rilevatore proprietario di Google. Va dichiarato chiaramente.

### Considerazioni etiche / di disclosure

- Privacy by design: elaborazione 100% client-side, nessun upload.
- Dichiarare **cosa viene rimosso** e **cosa no** (watermark di pixel/SynthID).
- Avviso anti-abuso: non usare per spacciare contenuti AI come reali o per
  cancellare l'attribuzione altrui; in alcune giurisdizioni (es. EU AI Act, in
  vigore ~ago 2026) la divulgazione dell'origine AI è obbligatoria.
- Usi legittimi forti: protezione di posizione GPS/casa, giornalisti, attivisti,
  sopravvissuti ad abusi (cfr. EFF Surveillance Self-Defense).

## Fonti principali

C2PA/CAI: spec.c2pa.org, c2pa.org, contentauthenticity.org. IPTC: iptc.org,
cv.iptc.org. Google: deepmind.google/models/synthid, blog.google. OpenAI:
openai.com/index/advancing-content-provenance. Adobe: helpx.adobe.com,
blog.adobe.com. Accademia: arXiv 2311.04378, 2310.00076, 2306.01953, 2309.16952,
2405.08363, 2503.22330, 2412.03283, 2510.09263; Nature s41586-024-08025-4. Repo:
github.com/aloshdenny/reverse-SynthID, /wiltodelta/remove-ai-watermarks,
/00quebec/Synthid-Bypass, /allenk/GeminiWatermarkTool. Privacy: EFF SSD
(ssd.eff.org/module/attending-protest).
