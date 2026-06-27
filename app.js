/*!
 * Pulisci — Rimozione metadati & analisi origine AI
 * @version 1.10.0
 * @year    2026
 * @author  profxeni
 *
 * SICUREZZA — Perché il JS è in un file separato (e non inline)?
 * Con lo script esterno la CSP può usare `script-src 'self'` ed eliminare
 * `'unsafe-inline'`: anche se un attaccante riuscisse a iniettare markup nella
 * pagina (es. via un valore di metadati), il browser NON eseguirebbe alcuno
 * script inline. Difese correlate: tutti i valori non fidati passano per esc()
 * prima del DOM; nessuna richiesta di rete (connect-src 'none'); anti-clickjacking.
 *
 * Tutta l'elaborazione avviene nel browser: nessun upload, nessuna telemetria.
 */
(function(){
  "use strict";

  // SICUREZZA — Anti-clickjacking. La direttiva CSP `frame-ancestors` viene
  // ignorata in un <meta>, quindi qui impediamo l'incorporamento in un <iframe>.
  if(window.top!==window.self){
    try{ document.documentElement.textContent=""; }catch(e){}
    try{ window.top.location=window.self.location; }catch(e){}
    return;
  }

  const $=id=>document.getElementById(id);
  const APP_VERSION="1.9.5";

  // Limiti difensivi (anti-DoS in locale).
  const MAX_FILE_BYTES=64*1024*1024;   // 64 MB: tetto sul file in ingresso
  const MAX_META_CHARS=512;            // lunghezza massima mostrata per un valore
  const MAX_SCAN_BYTES=2*1024*1024;    // byte di metadati analizzati per l'AI scan
  const MAX_PIXELS=80*1000*1000;       // ~80 MP: guardia contro "decompression bomb"
  const MAX_JPEG_SEG=4096;             // tetto massimo segmenti JPEG (anti-DoS)

  // Solo immagini raster: gli SVG sono esclusi (possono contenere script).
  function isAllowedType(t){ return /^image\//.test(t) && t!=="image/svg+xml"; }

  /* SICUREZZA — Escape dei caratteri HTML speciali, da applicare a OGNI testo
     che deriva dal file dell'utente prima di inserirlo via innerHTML. */
  function esc(s){
    s=String(s==null?"":s).slice(0,MAX_META_CHARS);
    return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }

  /* ====================== INTERNAZIONALIZZAZIONE (IT / EN) ====================== */
  const I18N={
    it:{
      "ui.badge":"100% nel tuo browser",
      "ui.h1":"Pulisci i tuoi <em>scatti</em>",
      "ui.badgeInfo":"Come funziona",
      "ui.dropTitle":"Carica un'immagine",
      "ui.dropDesc":"Trascina una o più immagini, oppure tocca per sceglierle",
      "ui.choiceQ":"Cosa vuoi fare con questa immagine?",
      "ui.reset":"↺ Carica un'altra immagine",
      "ui.footerLock":"Elaborazione locale",
      "ui.cleanedOne":"🧹 1 immagine ripulita su questo dispositivo",
      "ui.cleanedMany":"🧹 {n} immagini ripulite su questo dispositivo",
      "batch.title":"{n} immagini","batch.processing":"Elaborazione…","batch.error":"Errore",
      "batch.save":"Scarica","batch.aiBadge":"AI","batch.downloadAll":"Scarica tutte ({n})",
      "geo.viewMap":"Mappa","geo.title":"Posizione GPS",
      "geo.openOSM":"Apri in OpenStreetMap","geo.openGoogle":"Apri in Google Maps",
      "geo.copy":"Copia coordinate","geo.copied":"Copiato ✓",
      "geo.note":"Il pulsante apre una mappa esterna in una nuova scheda: la posizione verrà condivisa con quel servizio. La pagina, di per sé, non invia nulla.",
      "btn.clean":"Pulisci i metadati","btn.analyze":"Analizza immagine","btn.aiInfo":"Info analisi AI",
      "btn.download":"Scarica immagine pulita","btn.share":"Condividi",
      "btn.saveShare":"Salva / Condividi","btn.fullscreen":"Apri a schermo intero",
      "chip.analyzing":"Analisi…","chip.cleaning":"Rimozione metadati…",
      "hint.detected":"Rilevati segnali di origine AI nei metadati.",
      "hint.maybe":"Possibili indizi AI nei metadati.",
      "hint.metaCount":"{n} metadato/i presenti · nessun segnale AI",
      "hint.none":"Nessun metadato evidente · nessun segnale AI",
      "err.fileTooLarge":"File troppo grande (max {mb} MB).",
      "err.pixels":"Immagine troppo grande da elaborare (oltre 80 megapixel).",
      "err.format":"Questo formato non è elaborabile in questo browser — prova con un JPG o PNG.",
      "modal.cleanTitle":"Immagine ripulita","modal.analyzeTitle":"Analisi origine AI",
      "modal.analyzeSub":"Lettura dei metadati dell'immagine caricata.",
      "modal.cleanSubGps":"Posizione GPS e altri dati eliminati.",
      "modal.cleanSubItems":"Dati nascosti eliminati con successo.",
      "modal.cleanSubNone":"Riesportata senza alcun metadato.",
      "meta.removedTitle":"Metadati rimossi","meta.presentTitle":"Metadati presenti nel file",
      "meta.removedPill":"rimosso","size.original":"Originale","size.cleaned":"Pulita",
      "empty.unknown":"Formato non analizzabile in dettaglio in questo browser.",
      "empty.analyzeNone":"Nessun metadato evidente presente nel file.",
      "empty.cleanNone":"Nessun metadato evidente era presente. L'immagine è stata comunque riesportata pulita.",
      "ios.secure":"Per salvarla nelle Foto: <b>tieni premuto</b> sull'immagine qui sopra → <b>Salva immagine</b>, oppure usa il pulsante qui sotto.",
      "ios.insecure":"⚠️ Il salvataggio con un tocco funziona solo aprendo questa pagina dal suo indirizzo <b>https://</b> (non dall'anteprima o da un file locale). Per ora: <b>tieni premuto</b> sull'immagine qui sopra → <b>Salva immagine</b>.",
      "meta.camera":"Fotocamera / dispositivo","meta.datetimeShot":"Data e ora dello scatto",
      "meta.datetime":"Data e ora","meta.software":"Software","meta.gps":"Posizione GPS",
      "meta.others":"Altri metadati incorporati","meta.text":"Testo incorporato","meta.lastmod":"Ultima modifica",
      "meta.c2pa":"Content Credentials (C2PA)",
      "val.gpsWhere":"dove è stata scattata","val.embeddedTimestamp":"timestamp incorporato","val.blocks":"blocco/i",
      "val.c2pa":"manifest di provenienza incorporato (spesso AI)",
      "extra.icc":"profilo colore","extra.iptc":"IPTC/Photoshop","extra.xmp":"XMP","extra.comment":"commenti",
      "verdict.detected.h":"Segnali di origine AI rilevati",
      "verdict.detected.p":"Nei metadati ci sono credenziali o etichette che indicano contenuto generato o modificato con AI.",
      "verdict.maybe.h":"Possibili indizi di AI",
      "verdict.maybe.p":"Trovati riferimenti a strumenti AI nei metadati. Indizio non conclusivo.",
      "verdict.clear.h":"Nessun segnale AI nei metadati",
      "verdict.clear.p":"Non risultano credenziali C2PA, etichette IPTC né nomi di generatori AI nei metadati del file.",
      "ai.pill.strong":"AI","ai.pill.weak":"indizio",
      "ai.c2pa.k":"Credenziali di provenienza C2PA",
      "ai.c2pa.v":"Manifest Content Credentials incorporato: dichiara origine/cronologia; diventa forte se contiene azioni o sorgenti AI",
      "ai.iptc.k":"Etichetta IPTC di origine digitale",
      "ai.dst.composite":"Composito con elementi generati da AI (IPTC)",
      "ai.dst.trained":"Generata da AI addestrata — IPTC trainedAlgorithmicMedia",
      "ai.dst.compositeSynthetic":"Composito sintetico (IPTC)",
      "ai.dst.algorithmic":"Media algoritmica (IPTC)",
      "ai.iptcPresent.k":"Campo IPTC DigitalSourceType presente",
      "ai.iptcPresent.v":"presente, ma con valore non riconosciuto come AI",
      "ai.gen.k":"Software/generatore AI nei metadati",
      "ai.workflow.k":"Workflow o parametri generativi",
      "ai.workflow.v":"prompt/seed/modello/sampler o workflow compatibili con generatori AI",
      "ai.compressed.k":"Metadati testuali compressi",
      "ai.compressed.v":"il file contiene un blocco testuale compresso con keyword sospetta; il browser lo segnala ma non lo decomprime offline",
      "ai.phrase.k":"Dichiarazione testuale nei metadati",
      "ai.action.k":"Azione dichiarata nel manifest C2PA",
      "ai.action.created":"immagine generata da AI (c2pa.created)",
      "ai.action.edited":"foto modificata/composita con AI (c2pa.edited / placed)",
      "ai.noteTitle":"Perché non rileva SynthID?",
      "ai.note":"Questa analisi legge solo i <b>metadati</b> del file. I <b>watermark invisibili nei pixel</b> (es. Google <b>SynthID</b> di Gemini/Imagen) <b>non sono verificabili in questo browser</b>: serve il rilevatore ufficiale di Google. I metadati inoltre possono essere stati rimossi, quindi la loro assenza <b>non prova</b> che un'immagine non sia generata da AI.",
      "info.title":"Cosa controlla davvero",
      "info.sub":"Lettura locale dei metadati: cerca prove tecniche, non giudica i pixel.",
      "info.detectTitle":"Rilevamento AI",
      "info.detect1":"C2PA / Content Credentials in JPEG, PNG e WebP, incluse azioni come c2pa.created e c2pa.edited.",
      "info.detect2":"IPTC DigitalSourceType, compresi trainedAlgorithmicMedia e compositeWithTrainedAlgorithmicMedia.",
      "info.detect3":"XMP, EXIF Software e blocchi testuali PNG/WebP con nomi di generatori o workflow.",
      "info.detect4":"Parametri tipici di Stable Diffusion, ComfyUI, A1111, Fooocus, InvokeAI, FLUX e simili: prompt, seed, sampler, model hash, CFG, steps.",
      "info.cleanTitle":"Pulizia",
      "info.clean1":"Riesporta i pixel via canvas e rimuove EXIF, XMP, IPTC, ICC e manifest C2PA quando il formato lo consente.",
      "info.clean2":"Nei JPEG elimina anche i marker APP/COM reinseriti dal browser, mantenendo il file scaricabile e pulito.",
      "info.clean3":"Con più immagini lavora in serie, una alla volta, senza zip e senza librerie esterne.",
      "info.limitsTitle":"Limiti reali",
      "info.limit1":"Non verifica watermark invisibili nei pixel come SynthID: servono rilevatori ufficiali esterni.",
      "info.limit2":"Metadati assenti o ripuliti non provano che l'immagine non sia AI.",
      "info.limit3":"I metadati possono essere falsificati: il verdetto è un indizio tecnico, non una perizia.",
      "info.privacyTitle":"Privacy",
      "info.privacy":"Tutto avviene nel browser. La CSP blocca le richieste di rete: l'immagine non viene caricata online.",
      "info.deepTitle":"Approfondimento",
      "info.deep":"La confidenza sale quando il file dichiara origine AI tramite C2PA/IPTC, quando compaiono generatori noti, o quando trova una combinazione coerente di prompt, seed, modello, sampler e passi. Un singolo campo generico pesa meno; più segnali indipendenti rendono il risultato più affidabile.",
      "alt.preview":"anteprima","alt.result":"immagine pulita",
      "theme.system":"Sistema","theme.light":"Chiaro","theme.dark":"Scuro",
      "ui.credit":"© 2026 <b>profxeni</b> · Licenza <a href=\"https://creativecommons.org/licenses/by/4.0/\" target=\"_blank\" rel=\"noopener noreferrer\">CC BY 4.0</a>: puoi copiarla e modificarla citando l'autore.",
      "info.safetyTitle":"Sicurezza",
      "info.safetyText":"Gira nel browser, ma non carica niente. La pagina si scarica <b>una volta</b>; da lì la foto è elaborata <b>solo sul tuo dispositivo</b>, in memoria. Una regola di sicurezza (<code>connect-src 'none'</code>) blocca ogni richiesta di rete, quindi l'immagine non può uscire nemmeno per errore. Prova del nove: attiva la <b>modalità aereo</b> e funziona lo stesso.",
      "info.heic":"*I file HEIC vengono convertiti in JPG durante la pulizia.",
      "info.synthTitle":"Perché non rileva SynthID?",
      "info.synthText":"L'analisi AI legge solo i <b>metadati</b> del file. I <b>watermark invisibili nei pixel</b> (es. Google <b>SynthID</b> di Gemini/Imagen) <b>non sono verificabili in questo browser</b>: serve il rilevatore ufficiale di Google. I metadati inoltre possono essere stati rimossi, quindi la loro assenza <b>non prova</b> che un'immagine non sia generata da AI. Non usare questo strumento per spacciare contenuti AI come reali o per rimuovere l'attribuzione altrui."
    },
    en:{
      "ui.badge":"100% in your browser",
      "ui.h1":"Clean your <em>shots</em>",
      "ui.badgeInfo":"How it works",
      "ui.dropTitle":"Upload an image",
      "ui.dropDesc":"Drag one or more images, or tap to choose",
      "ui.choiceQ":"What do you want to do with this image?",
      "ui.reset":"↺ Load another image",
      "ui.footerLock":"Local processing",
      "ui.cleanedOne":"🧹 1 image cleaned on this device",
      "ui.cleanedMany":"🧹 {n} images cleaned on this device",
      "batch.title":"{n} images","batch.processing":"Processing…","batch.error":"Error",
      "batch.save":"Download","batch.aiBadge":"AI","batch.downloadAll":"Download all ({n})",
      "geo.viewMap":"Map","geo.title":"GPS location",
      "geo.openOSM":"Open in OpenStreetMap","geo.openGoogle":"Open in Google Maps",
      "geo.copy":"Copy coordinates","geo.copied":"Copied ✓",
      "geo.note":"The button opens an external map in a new tab: the location will be shared with that service. The page itself sends nothing.",
      "btn.clean":"Clean metadata","btn.analyze":"Analyze image","btn.aiInfo":"AI analysis info",
      "btn.download":"Download clean image","btn.share":"Share",
      "btn.saveShare":"Save / Share","btn.fullscreen":"Open fullscreen",
      "chip.analyzing":"Analyzing…","chip.cleaning":"Removing metadata…",
      "hint.detected":"AI-origin signals found in metadata.",
      "hint.maybe":"Possible AI hints in metadata.",
      "hint.metaCount":"{n} metadata present · no AI signal",
      "hint.none":"No obvious metadata · no AI signal",
      "err.fileTooLarge":"File too large (max {mb} MB).",
      "err.pixels":"Image too large to process (over 80 megapixels).",
      "err.format":"This format can't be processed in this browser — try a JPG or PNG.",
      "modal.cleanTitle":"Image cleaned","modal.analyzeTitle":"AI origin analysis",
      "modal.analyzeSub":"Reading the uploaded image's metadata.",
      "modal.cleanSubGps":"GPS location and other data removed.",
      "modal.cleanSubItems":"Hidden data removed successfully.",
      "modal.cleanSubNone":"Re-exported without any metadata.",
      "meta.removedTitle":"Removed metadata","meta.presentTitle":"Metadata present in the file",
      "meta.removedPill":"removed","size.original":"Original","size.cleaned":"Cleaned",
      "empty.unknown":"Format not analyzable in detail in this browser.",
      "empty.analyzeNone":"No obvious metadata present in the file.",
      "empty.cleanNone":"No obvious metadata was present. The image was re-exported clean anyway.",
      "ios.secure":"To save to Photos: <b>press and hold</b> the image above → <b>Save Image</b>, or use the button below.",
      "ios.insecure":"⚠️ One-tap saving only works when opening this page from its <b>https://</b> address (not from a preview or local file). For now: <b>press and hold</b> the image above → <b>Save Image</b>.",
      "meta.camera":"Camera / device","meta.datetimeShot":"Capture date & time",
      "meta.datetime":"Date & time","meta.software":"Software","meta.gps":"GPS location",
      "meta.others":"Other embedded metadata","meta.text":"Embedded text","meta.lastmod":"Last modified",
      "meta.c2pa":"Content Credentials (C2PA)",
      "val.gpsWhere":"where it was taken","val.embeddedTimestamp":"embedded timestamp","val.blocks":"block(s)",
      "val.c2pa":"embedded provenance manifest (often AI)",
      "extra.icc":"color profile","extra.iptc":"IPTC/Photoshop","extra.xmp":"XMP","extra.comment":"comments",
      "verdict.detected.h":"AI-origin signals detected",
      "verdict.detected.p":"The metadata contains credentials or labels indicating AI-generated or AI-edited content.",
      "verdict.maybe.h":"Possible AI hints",
      "verdict.maybe.p":"References to AI tools were found in the metadata. Not conclusive.",
      "verdict.clear.h":"No AI signal in metadata",
      "verdict.clear.p":"No C2PA credentials, IPTC labels or AI generator names were found in the file's metadata.",
      "ai.pill.strong":"AI","ai.pill.weak":"hint",
      "ai.c2pa.k":"C2PA provenance credentials",
      "ai.c2pa.v":"Embedded Content Credentials manifest: declares origin/history; strong when it includes AI actions or sources",
      "ai.iptc.k":"IPTC digital source type label",
      "ai.dst.composite":"Composite with AI-generated elements (IPTC)",
      "ai.dst.trained":"Generated by trained AI — IPTC trainedAlgorithmicMedia",
      "ai.dst.compositeSynthetic":"Synthetic composite (IPTC)",
      "ai.dst.algorithmic":"Algorithmic media (IPTC)",
      "ai.iptcPresent.k":"IPTC DigitalSourceType field present",
      "ai.iptcPresent.v":"present, but with a value not recognized as AI",
      "ai.gen.k":"AI software/generator in metadata",
      "ai.workflow.k":"Generative workflow or parameters",
      "ai.workflow.v":"prompt/seed/model/sampler or workflow fields compatible with AI generators",
      "ai.compressed.k":"Compressed text metadata",
      "ai.compressed.v":"the file contains a compressed text block with a suspicious keyword; the browser flags it but does not decompress it offline",
      "ai.phrase.k":"Text declaration in metadata",
      "ai.action.k":"Declared action in the C2PA manifest",
      "ai.action.created":"AI-generated image (c2pa.created)",
      "ai.action.edited":"AI-edited / composite photo (c2pa.edited / placed)",
      "ai.noteTitle":"Why can't it detect SynthID?",
      "ai.note":"This analysis reads only the file's <b>metadata</b>. <b>Invisible pixel watermarks</b> (e.g. Google <b>SynthID</b> in Gemini/Imagen) <b>cannot be verified in this browser</b>: Google's official detector is required. Metadata may also have been stripped, so its absence <b>does not prove</b> an image is not AI-generated.",
      "info.title":"What it really checks",
      "info.sub":"A local metadata read: useful for technical evidence, not a pixel judgment.",
      "info.detectTitle":"AI detection",
      "info.detect1":"C2PA / Content Credentials in JPEG, PNG and WebP, including actions such as c2pa.created and c2pa.edited.",
      "info.detect2":"IPTC DigitalSourceType, including trainedAlgorithmicMedia and compositeWithTrainedAlgorithmicMedia.",
      "info.detect3":"XMP, EXIF Software and PNG/WebP text blocks containing generator names or workflows.",
      "info.detect4":"Stable Diffusion, ComfyUI, A1111, Fooocus, InvokeAI, FLUX-like parameters: prompt, seed, sampler, model hash, CFG, steps.",
      "info.cleanTitle":"Cleaning",
      "info.clean1":"Re-exports pixels through canvas and removes EXIF, XMP, IPTC, ICC and C2PA manifests when the format allows it.",
      "info.clean2":"For JPEG, it also strips APP/COM markers that the browser encoder may reinsert, while keeping the file downloadable and clean.",
      "info.clean3":"For multiple images, it works sequentially, one image at a time, with no zip file and no external library.",
      "info.limitsTitle":"Honest limits",
      "info.limit1":"It does not verify invisible pixel watermarks such as SynthID: official external detectors are required.",
      "info.limit2":"Missing or stripped metadata does not prove that an image is not AI-generated.",
      "info.limit3":"Metadata can be forged: the verdict is a technical clue, not a forensic ruling.",
      "info.privacyTitle":"Privacy",
      "info.privacy":"Everything runs in the browser. The CSP blocks network requests: the image is not uploaded online.",
      "info.deepTitle":"Deep dive",
      "info.deep":"Confidence rises when the file declares AI origin through C2PA/IPTC, when known generator names appear, or when it finds a coherent combination of prompt, seed, model, sampler and steps. A single generic field weighs less; multiple independent signals make the result more reliable.",
      "alt.preview":"preview","alt.result":"clean image",
      "theme.system":"System","theme.light":"Light","theme.dark":"Dark",
      "ui.credit":"© 2026 <b>profxeni</b> · Licensed <a href=\"https://creativecommons.org/licenses/by/4.0/\" target=\"_blank\" rel=\"noopener noreferrer\">CC BY 4.0</a>: copy and remix it with attribution.",
      "info.safetyTitle":"Safety",
      "info.safetyText":"It runs in your browser, but nothing is uploaded. The page is downloaded <b>once</b>; from then on your photo is processed <b>only on your device</b>, in memory. A security rule (<code>connect-src 'none'</code>) blocks every network request, so the image can't leave, even by mistake. Proof: turn on <b>airplane mode</b> and it still works.",
      "info.heic":"*HEIC files are converted to JPG during cleaning.",
      "info.synthTitle":"Why can't it detect SynthID?",
      "info.synthText":"The AI analysis reads only the file's <b>metadata</b>. <b>Invisible pixel watermarks</b> (e.g. Google <b>SynthID</b> in Gemini/Imagen) <b>cannot be verified in this browser</b>: Google's official detector is required. Metadata may also have been stripped, so its absence <b>does not prove</b> an image is not AI-generated. Do not use this tool to pass AI content off as real or to strip someone else's attribution."
    }
  };

  function readStore(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }
  function writeStore(k,v){ try{ localStorage.setItem(k,v); }catch(e){} }

  // Default: inglese (salvo scelta salvata dall'utente).
  let LANG = readStore("lang") || "en";
  // t(key, params): traduce e sostituisce eventuali segnaposto {x}.
  function t(key,params){
    const dict=I18N[LANG]||I18N.it;
    let s=(dict[key]!=null)?dict[key]:(I18N.it[key]!=null?I18N.it[key]:key);
    if(params) for(const p in params) s=s.replace("{"+p+"}",params[p]);
    return s;
  }

  /* ====================== TEMA (sistema / chiaro / scuro) ====================== */
  const THEME_ICON={system:"🖥",light:"☀",dark:"🌙"};
  const THEME_ORDER=["system","light","dark"];
  // Default: tema del dispositivo (sistema), salvo scelta salvata dall'utente.
  let THEME = readStore("theme") || "system";
  function applyTheme(){
    const root=document.documentElement;
    if(THEME==="system"){ root.removeAttribute("data-theme"); root.style.colorScheme="light dark"; }
    else{ root.setAttribute("data-theme",THEME); root.style.colorScheme=THEME; }
    const ico=$("themeIco"), txt=$("themeTxt");
    if(ico) ico.textContent=THEME_ICON[THEME];
    if(txt) txt.textContent=t("theme."+THEME);
  }
  function cycleTheme(){
    THEME=THEME_ORDER[(THEME_ORDER.indexOf(THEME)+1)%THEME_ORDER.length];
    writeStore("theme",THEME); applyTheme();
  }

  // Applica le stringhe statiche marcate con data-i18n / data-i18n-html.
  function applyStaticI18n(){
    document.documentElement.lang=LANG;
    document.querySelectorAll("[data-i18n]").forEach(el=>{ el.textContent=t(el.getAttribute("data-i18n")); });
    document.querySelectorAll("[data-i18n-html]").forEach(el=>{ el.innerHTML=t(el.getAttribute("data-i18n-html")); });
    const lt=$("langTxt"); if(lt) lt.textContent=LANG.toUpperCase();
    const lb=$("langBtn"); if(lb) lb.setAttribute("aria-label", LANG==="it"?"Lingua / Language":"Language / Lingua");
    if(preview) preview.alt=t("alt.preview");
    if(mImg) mImg.alt=t("alt.result");
    if(aiInfoBtn){ aiInfoBtn.setAttribute("aria-label",t("btn.aiInfo")); aiInfoBtn.title=t("btn.aiInfo"); }
    if(batchDownloadAll && !batchDownloadAll.disabled && batchItems.length)
      batchDownloadAll.textContent=t("batch.downloadAll",{n:batchItems.length});
    applyTheme(); // riallinea l'etichetta del tema nella lingua corrente
  }
  function setLang(l){
    LANG=l; writeStore("lang",l);
    applyStaticI18n();
    renderCount();
    // Aggiorna i contenuti dinamici già a schermo.
    if(stage.classList.contains("show")) setChoiceHint();
    if(modal.classList.contains("open")) populateModal();
  }

  /* ====================== ELEMENTI ====================== */
  const drop=$("drop"), fileInput=$("file"), stage=$("stage"), frame=$("frame"),
        preview=$("preview"), chip=$("chip"), chiptx=$("chiptx"),
        choice=$("choice"), actClean=$("actClean"), actAnalyze=$("actAnalyze"), aiInfoBtn=$("aiInfoBtn"),
        choiceHint=$("choiceHint"), reset=$("reset"),
        modal=$("modal"), backdrop=$("backdrop"), mClose=$("mClose"),
        mImg=$("mImg"), mTitle=$("mTitle"), mSub=$("mSub"), mSizes=$("mSizes"),
        mAITitle=$("mAITitle"), mAIWrap=$("mAIWrap"),
        mMetaTitle=$("mMetaTitle"), mMeta=$("mMeta"),
        mActions=$("mActions"), iosHint=$("iosHint"),
        langBtn=$("langBtn"), themeBtn=$("themeBtn"), statCleaned=$("statCleaned"),
        geoModal=$("geoModal"), geoBackdrop=$("geoBackdrop"), geoClose=$("geoClose"),
        geoTitle=$("geoTitle"), geoCoords=$("geoCoords"), geoActions=$("geoActions"), geoNote=$("geoNote"),
        infoModal=$("infoModal"), infoBackdrop=$("infoBackdrop"), infoClose=$("infoClose"),
        batch=$("batch"), batchList=$("batchList"), batchTitle=$("batchTitle"),
        batchDownloadAll=$("batchDownloadAll"), batchReset=$("batchReset"),
        headerInfoBtn=$("headerInfoBtn"),
        infoVersion=$("infoVersion");

  let batchItems=[], batchURLs=[];

  const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent) ||
                (navigator.platform==="MacIntel" && navigator.maxTouchPoints>1);

  let cleanedURL=null, cleanedFile=null, originalURL=null, currentFile=null,
      lastReport=null, lastSizes=null, lastAI=null, modalMode="clean";

  function fmtBytes(b){
    if(b<1024) return b+" B";
    if(b<1048576) return (b/1024).toFixed(1)+" KB";
    return (b/1048576).toFixed(2)+" MB";
  }
  function ext(type){ if(type==="image/png")return "png"; if(type==="image/webp")return "webp"; return "jpg"; }

  /* Contatore LOCALE (solo localStorage, nessuna rete): quante immagini sono
     state ripulite su QUESTO dispositivo. Rafforza la promessa privacy. */
  const COUNT_KEY="nm_cleaned";
  function getCount(){ const n=parseInt(readStore(COUNT_KEY)||"0",10); return isNaN(n)?0:n; }
  function renderCount(){
    const n=getCount();
    if(n>0){ statCleaned.textContent=t(n===1?"ui.cleanedOne":"ui.cleanedMany",{n}); statCleaned.hidden=false; }
    else statCleaned.hidden=true;
  }
  function incCount(){ writeStore(COUNT_KEY, String(getCount()+1)); renderCount(); }

  /* ====================== PARSING METADATI ====================== */
  // Legge la struttura TIFF/EXIF (Make, Model, Data, Software, GPS). Tutto è
  // racchiuso in try/catch: un header malformato non deve far crashare l'app.
  function parseTIFF(view, tiffStart){
    const out={};
    try{
      const little = view.getUint16(tiffStart)===0x4949;   // 0x4949='II' little-endian
      const u16=o=>view.getUint16(o,little), u32=o=>view.getUint32(o,little);
      if(view.getUint16(tiffStart+2,little)!==0x002A) return out;
      const TYPE_SIZE={1:1,2:1,3:2,4:4,5:8,7:1,9:4,10:8};
      // `count` arriva dal file: lo limitiamo (anti-DoS) per non leggere stringhe enormi.
      function readASCII(off,count){
        // SICUREZZA — Bound-check: non leggere fuori dal buffer.
        if(off<0 || off>=view.byteLength) return "";
        count=Math.min(count,MAX_META_CHARS,view.byteLength-off);let s="";for(let i=0;i<count;i++){const c=view.getUint8(off+i);if(c===0)break;s+=String.fromCharCode(c);}return s.trim();}
      function readRational(off){return u32(off)/u32(off+4);}
      function readIFD(dirStart){
        // SICUREZZA — Bound check: l'IFD non può puntare fuori dal buffer.
        if(dirStart<0 || dirStart+2>view.byteLength) return {};
        const entries=u16(dirStart);
        // SICUREZZA — Anti-DoS: un IFD malformato può dichiarare fino a 65535 entry.
        if(entries>512) return {};
        const tags={};
        for(let i=0;i<entries;i++){
          const e=dirStart+2+i*12;
          if(e+12>view.byteLength) break;
          const tag=u16(e), type=u16(e+2), count=u32(e+4);
          const sz=(TYPE_SIZE[type]||1)*count; let valOff=e+8;
          // SICUREZZA — Non seguire offset fuori dal buffer.
          if(sz>4){
            valOff=tiffStart+u32(e+8);
            if(valOff<0 || valOff+sz>view.byteLength) continue;
          }
          tags[tag]={type,count,valOff};
        }
        return tags;
      }
      const ifd0=readIFD(tiffStart+u32(tiffStart+4));
      if(ifd0[0x010F]) out.make=readASCII(ifd0[0x010F].valOff, ifd0[0x010F].count);
      if(ifd0[0x0110]) out.model=readASCII(ifd0[0x0110].valOff, ifd0[0x0110].count);
      if(ifd0[0x0132]) out.datetime=readASCII(ifd0[0x0132].valOff, ifd0[0x0132].count);
      if(ifd0[0x0131]) out.software=readASCII(ifd0[0x0131].valOff, ifd0[0x0131].count);
      if(ifd0[0x8769]){
        const exif=readIFD(tiffStart+view.getUint32(ifd0[0x8769].valOff,little));
        if(exif[0x9003]) out.dateOriginal=readASCII(exif[0x9003].valOff, exif[0x9003].count);
      }
      if(ifd0[0x8825]){
        const gps=readIFD(tiffStart+view.getUint32(ifd0[0x8825].valOff,little));
        function dms(t){const o=gps[t].valOff;return readRational(o)+readRational(o+8)/60+readRational(o+16)/3600;}
        if(gps[0x0002]&&gps[0x0004]){
          let lat=dms(0x0002), lon=dms(0x0004);
          const latRef=gps[0x0001]?readASCII(gps[0x0001].valOff,gps[0x0001].count):"N";
          const lonRef=gps[0x0003]?readASCII(gps[0x0003].valOff,gps[0x0003].count):"E";
          if(latRef==="S")lat=-lat; if(lonRef==="W")lon=-lon;
          out.gps={lat,lon};
        }
      }
    }catch(e){}
    return out;
  }

  function parseJPEG(buf){
    const view=new DataView(buf), res={items:[],bytes:0,gps:null};
    if(view.getUint16(0)!==0xFFD8) return null;
    let off=2; const seen={xmp:false,icc:false,iptc:false,comment:false,c2pa:false};
    // SICUREZZA — Anti-DoS: tetto massimo sui segmenti JPEG percorsi.
    let segCount=0;
    while(off<view.byteLength-1){
      if(view.getUint8(off)!==0xFF){off++;continue;}
      const marker=view.getUint16(off);
      if(marker===0xFFDA) break;
      if(marker>=0xFFD0 && marker<=0xFFD9){off+=2;continue;}
      // SICUREZZA — Se non ci sono abbastanza byte per leggere la lunghezza.
      if(off+4>view.byteLength) break;
      const len=view.getUint16(off+2);
      // SICUREZZA — Lunghezza minima per un segmento è 2 (include se stessa);
      // un valore <2 o overflow indica dati corrotti.
      if(len<2 || segCount++>MAX_JPEG_SEG) break;
      const segStart=off+4;
      if(marker===0xFFE1){
        let hdr="";const hdrEnd=Math.min(segStart+6,view.byteLength);for(let i=segStart;i<hdrEnd;i++)hdr+=String.fromCharCode(view.getUint8(i));
        res.bytes+=len;
        if(hdr.startsWith("Exif")){
          const exif=parseTIFF(view, segStart+6);
          if(exif.make||exif.model) res.items.push({ico:"📷",kKey:"meta.camera",v:[exif.make,exif.model].filter(Boolean).join(" ")});
          if(exif.dateOriginal||exif.datetime) res.items.push({ico:"📅",kKey:"meta.datetimeShot",v:(exif.dateOriginal||exif.datetime)});
          if(exif.software) res.items.push({ico:"🛠",kKey:"meta.software",v:exif.software});
          if(exif.gps) res.gps=exif.gps;
        }else seen.xmp=true;
      }
      else if(marker===0xFFE0) res.bytes+=len;
      else if(marker===0xFFE2){res.bytes+=len;seen.icc=true;}
      else if(marker===0xFFED){res.bytes+=len;seen.iptc=true;}
      else if(marker===0xFFEB){res.bytes+=len;seen.c2pa=true;}   // APP11 → C2PA (JUMBF)
      else if(marker>=0xFFE3&&marker<=0xFFEF){res.bytes+=len;seen.xmp=true;}
      else if(marker===0xFFFE){res.bytes+=len;seen.comment=true;}
      off+=2+len;
    }
    if(res.gps) res.items.unshift({warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5),suffixKey:"val.gpsWhere"});
    const extras=[];
    if(seen.icc)extras.push("extra.icc"); if(seen.iptc)extras.push("extra.iptc");
    if(seen.xmp)extras.push("extra.xmp"); if(seen.comment)extras.push("extra.comment");
    if(extras.length)res.items.push({ico:"🗂",kKey:"meta.others",parts:extras});
    if(seen.c2pa) res.items.push({ico:"🔏",kKey:"meta.c2pa",vKey:"val.c2pa"});
    return res;
  }

  function parsePNG(buf){
    const view=new DataView(buf), res={items:[],bytes:0,gps:null};
    const sig=[137,80,78,71,13,10,26,10];
    for(let i=0;i<8;i++) if(view.getUint8(i)!==sig[i]) return null;
    let off=8; const txt=[];
    while(off<view.byteLength){
      const len=view.getUint32(off);
      let type="";for(let i=0;i<4;i++)type+=String.fromCharCode(view.getUint8(off+4+i));
      if(["tEXt","iTXt","zTXt"].includes(type)){res.bytes+=len;txt.push(type);}
      else if(type==="eXIf"){res.bytes+=len;
        const exif=parseTIFF(view, off+8);
        if(exif.make||exif.model) res.items.push({ico:"📷",kKey:"meta.camera",v:[exif.make,exif.model].filter(Boolean).join(" ")});
        if(exif.dateOriginal||exif.datetime) res.items.push({ico:"📅",kKey:"meta.datetime",v:(exif.dateOriginal||exif.datetime)});
        if(exif.gps) res.gps=exif.gps;
      }
      else if(type==="tIME"){res.bytes+=len;res.items.push({ico:"📅",kKey:"meta.lastmod",vKey:"val.embeddedTimestamp"});}
      else if(type==="caBX"){res.bytes+=len;res.c2pa=true;}   // chunk privato C2PA
      if(type==="IEND")break;
      off+=12+len;
    }
    if(res.gps) res.items.unshift({warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5)});
    if(txt.length)res.items.push({ico:"🗂",kKey:"meta.text",blocks:{n:txt.length,types:[...new Set(txt)].join(", ")}});
    if(res.c2pa) res.items.push({ico:"🔏",kKey:"meta.c2pa",vKey:"val.c2pa"});
    return res;
  }

  // WebP (contenitore RIFF): legge i chunk EXIF, XMP, ICCP, C2PA.
  // Importante perché ChatGPT (web) salva spesso in WebP anche con estensione .png.
  function parseWEBP(buf){
    const view=new DataView(buf), res={items:[],bytes:0,gps:null};
    const cc=o=>{let s="";for(let i=0;i<4;i++)s+=String.fromCharCode(view.getUint8(o+i));return s;};
    if(view.byteLength<12 || cc(0)!=="RIFF" || cc(8)!=="WEBP") return null;
    let off=12; const seen={xmp:false,icc:false,c2pa:false};
    while(off+8<=view.byteLength){
      const id=cc(off), size=view.getUint32(off+4,true), ps=off+8;
      if(id==="EXIF"){
        // il payload EXIF inizia col TIFF (II/MM); alcuni encoder antepongono "Exif\0\0".
        let ts=ps;
        if(view.getUint8(ps)===0x45&&view.getUint8(ps+1)===0x78&&view.getUint8(ps+2)===0x69&&view.getUint8(ps+3)===0x66) ts=ps+6;
        const exif=parseTIFF(view, ts);
        if(exif.make||exif.model) res.items.push({ico:"📷",kKey:"meta.camera",v:[exif.make,exif.model].filter(Boolean).join(" ")});
        if(exif.dateOriginal||exif.datetime) res.items.push({ico:"📅",kKey:"meta.datetime",v:(exif.dateOriginal||exif.datetime)});
        if(exif.software) res.items.push({ico:"🛠",kKey:"meta.software",v:exif.software});
        if(exif.gps) res.gps=exif.gps;
      }
      else if(id==="XMP ") seen.xmp=true;
      else if(id==="ICCP") seen.icc=true;
      else if(id==="C2PA") seen.c2pa=true;
      off=ps+size+(size&1);   // padding a byte pari
    }
    if(res.gps) res.items.unshift({warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5)});
    const extras=[];
    if(seen.icc)extras.push("extra.icc"); if(seen.xmp)extras.push("extra.xmp");
    if(extras.length)res.items.push({ico:"🗂",kKey:"meta.others",parts:extras});
    if(seen.c2pa) res.items.push({ico:"🔏",kKey:"meta.c2pa",vKey:"val.c2pa"});
    return res;
  }

  function analyze(buf,type){
    try{
      if(type==="image/jpeg") return parseJPEG(buf);
      if(type==="image/png")  return parsePNG(buf);
      if(type==="image/webp") return parseWEBP(buf);
    }catch(e){}
    return {items:[],bytes:0,gps:null,unknown:true};
  }

  // Calcola la stringa-valore tradotta di un item di metadati.
  function itemValue(it){
    if(it.parts) return it.parts.map(k=>t(k)).join(", ");
    if(it.blocks) return it.blocks.n+" "+t("val.blocks")+" ("+it.blocks.types+")";
    let v = it.vKey ? t(it.vKey) : (it.v!=null?String(it.v):"");
    if(it.suffixKey) v += "  ·  "+t(it.suffixKey);
    return v;
  }

  /* === ANALISI ORIGINE AI (solo metadati) ===
     Legge SOLO i metadati/segmenti del file (non i pixel): manifest C2PA,
     etichetta IPTC DigitalSourceType, marcatori XMP e nomi di generatori AI.
     NON rileva i watermark invisibili nei pixel come Google SynthID. */
  function aiScan(buf,type){
    const view=new DataView(buf), parts=[];
    const flags={c2paBox:false,compressedTextKeys:[]};
    let scanned=0;
    function addText(s){
      if(!s) return;
      parts.push(String(s).slice(0,MAX_SCAN_BYTES));
    }
    function decodeBytes(u8){
      const out=[];
      function add(s){
        if(!s) return;
        // Tieni solo stringhe con una minima densità di caratteri leggibili.
        const readable=(s.match(/[A-Za-z0-9:_./ -]/g)||[]).length;
        if(readable>=3) out.push(s.replace(/\u0000/g," "));
      }
      try{ add(new TextDecoder("latin1").decode(u8)); }catch(e){}
      try{ add(new TextDecoder("utf-8").decode(u8)); }catch(e){}
      if(u8.length>3){
        try{ add(new TextDecoder("utf-16le").decode(u8)); }catch(e){}
        try{ add(new TextDecoder("utf-16be").decode(u8)); }catch(e){}
      }
      return out.join("\n");
    }
    function push(start,end){
      if(scanned>=MAX_SCAN_BYTES) return;
      start=Math.max(0,start); end=Math.min(end,view.byteLength);
      const take=Math.min(end-start,MAX_SCAN_BYTES-scanned);
      if(take<=0) return;
      addText(decodeBytes(new Uint8Array(buf,start,take)));
      scanned+=take;
    }
    function zero(start,end){ for(let i=start;i<end;i++) if(view.getUint8(i)===0) return i; return -1; }
    function textRange(start,end){ return decodeBytes(new Uint8Array(buf,start,Math.max(0,end-start))).trim(); }
    function readPngText(kind,ps,len){
      const end=Math.min(ps+len,view.byteLength), z=zero(ps,end);
      const key=z>ps ? textRange(ps,z).trim() : "";
      if(kind==="tEXt" && z>ps){ addText(key+" "+textRange(z+1,end)); return; }
      if(kind==="zTXt" && z>ps){
        if(/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) flags.compressedTextKeys.push(key);
        addText(key+" zTXt compressed text metadata");
        return;
      }
      if(kind==="iTXt" && z>ps && z+3<end){
        const compressed=view.getUint8(z+1)===1;
        let p=z+3; // compression flag + method
        const langEnd=zero(p,end); if(langEnd<0) return;
        p=langEnd+1;
        const translatedEnd=zero(p,end); if(translatedEnd<0) return;
        p=translatedEnd+1;
        if(compressed){
          if(/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) flags.compressedTextKeys.push(key);
          addText(key+" iTXt compressed text metadata");
        }else addText(key+" "+textRange(p,end));
      }
    }
    try{
      if(type==="image/jpeg"){
        let off=2;
        // SICUREZZA — Anti-DoS: tetto segmenti come in parseJPEG.
        let segCount=0;
        while(off<view.byteLength-1){
          if(view.getUint8(off)!==0xFF){off++;continue;}
          const marker=view.getUint16(off);
          if(marker===0xFFDA||marker===0xFFD9) break;
          if(marker>=0xFFD0&&marker<=0xFFD9){off+=2;continue;}
          // SICUREZZA — Bound-check: servono 4 byte per leggere la lunghezza.
          if(off+4>view.byteLength) break;
          const len=view.getUint16(off+2);
          if(len<2 || segCount++>MAX_JPEG_SEG) break;
          if((marker>=0xFFE0&&marker<=0xFFEF)||marker===0xFFFE){
            push(off+4, off+2+len);
            if(marker===0xFFEB) flags.c2paBox=true; // APP11 → contenitore JUMBF/C2PA
          }
          off+=2+len;
        }
      }else if(type==="image/png"){
        let off=8;
        while(off+12<=view.byteLength){
          const len=view.getUint32(off);
          let tt="";for(let i=0;i<4;i++)tt+=String.fromCharCode(view.getUint8(off+4+i));
          const ps=off+8;
          if(["tEXt","iTXt","zTXt"].includes(tt)) readPngText(tt,ps,len);
          else if(["eXIf","iCCP","caBX"].includes(tt)) push(ps, ps+len);
          if(tt==="caBX") flags.c2paBox=true; // chunk privato C2PA
          if(tt==="IEND") break;
          off+=12+len;
        }
      }else if(type==="image/webp"){
        const cc=o=>{let s="";for(let i=0;i<4;i++)s+=String.fromCharCode(view.getUint8(o+i));return s;};
        if(view.byteLength>=12 && cc(0)==="RIFF" && cc(8)==="WEBP"){
          let off=12;
          while(off+8<=view.byteLength){
            const id=cc(off), size=view.getUint32(off+4,true), ps=off+8;
            if(id==="EXIF"||id==="XMP "||id==="ICCP"||id==="C2PA") push(ps, ps+size);
            if(id==="C2PA") flags.c2paBox=true;   // manifest C2PA in WebP
            off=ps+size+(size&1);
          }
        }
      }
    }catch(e){}
    const text=parts.join("\n");
    return {text, lower:text.toLowerCase(), flags};
  }

  function analyzeAI(buf,type){
    const scan=aiScan(buf,type), lower=scan.lower, signals=[];
    let strong=false, maybe=false;

    // 1) Manifest C2PA / Content Credentials (anche WebP). Distingue generata vs modificata.
    const hasC2PA = scan.flags.c2paBox || lower.includes("c2pa") || lower.includes("contentauth")
                 || lower.includes("content credential") || lower.includes("contentcredentials");
    if(hasC2PA){
      const c2paEdited=lower.includes("c2pa.edited") || lower.includes("c2pa.placed");
      const c2paCreated=lower.includes("c2pa.created");
      const c2paStrong=c2paEdited||c2paCreated;
      if(c2paStrong) strong=true; else maybe=true;
      signals.push({strong:c2paStrong,ico:"🔏",kKey:"ai.c2pa.k",vKey:"ai.c2pa.v"});
      if(c2paEdited)
        signals.push({strong:true,ico:"✏️",kKey:"ai.action.k",vKey:"ai.action.edited"});
      else if(c2paCreated)
        signals.push({strong:true,ico:"✨",kKey:"ai.action.k",vKey:"ai.action.created"});
    }

    // 2) Etichetta IPTC DigitalSourceType (URI o token finale, anche snake_case di Google Merchant).
    const dst=[
      ["compositewithtrainedalgorithmicmedia","ai.dst.composite"],
      ["composite_with_trained_algorithmic_media","ai.dst.composite"],
      ["trainedalgorithmicmedia","ai.dst.trained"],
      ["trained_algorithmic_media","ai.dst.trained"],
      ["compositesynthetic","ai.dst.compositeSynthetic"],
      ["algorithmicmedia","ai.dst.algorithmic"]
    ];
    let dstHit=null;
    for(const [tok,vk] of dst){ if(lower.includes(tok)){ dstHit=vk; break; } }
    if(dstHit){ strong=true; signals.push({strong:true,ico:"🏷️",kKey:"ai.iptc.k",vKey:dstHit}); }
    else if(lower.includes("digitalsourcetype")){ maybe=true; signals.push({ico:"🏷️",kKey:"ai.iptcPresent.k",vKey:"ai.iptcPresent.v"}); }

    // 3) Nomi di software/generatori AI nei metadati (substring, come fanno i detector reali) → segnale forte.
    const gens=[
      ["azure openai","Azure OpenAI"],["chatgpt","ChatGPT (OpenAI)"],["openai","OpenAI"],
      ["dall·e","DALL·E"],["dall-e","DALL·E"],["dalle","DALL·E"],["gpt-image","GPT-image (OpenAI)"],["gpt-4o","GPT-4o (OpenAI)"],["sora","Sora (OpenAI)"],
      ["google c2pa","Google (C2PA)"],["made with google ai","Google AI"],["nano banana","Gemini 2.5 Flash Image (nano banana)"],["gemini","Google Gemini"],["imagen","Google Imagen"],
      ["adobe firefly","Adobe Firefly"],["firefly","Adobe Firefly"],
      ["bing image creator","Bing Image Creator"],["microsoft designer","Microsoft Designer"],
      ["midjourney","Midjourney"],["nijijourney","NijiJourney"],
      ["stable diffusion","Stable Diffusion"],["stablediffusion","Stable Diffusion"],["sdxl","Stable Diffusion XL"],["sd3","Stable Diffusion 3"],
      ["automatic1111","Stable Diffusion (A1111)"],["a1111","Stable Diffusion (A1111)"],["forge webui","Stable Diffusion WebUI Forge"],
      ["comfyui","ComfyUI"],["fooocus","Fooocus"],["invokeai","InvokeAI"],["invoke ai","InvokeAI"],["sdnext","SD.Next"],
      ["leonardo.ai","Leonardo.Ai"],["leonardo ai","Leonardo.Ai"],["ideogram","Ideogram"],["nightcafe","NightCafe"],["recraft","Recraft"],["novelai","NovelAI"],["nai diffusion","NovelAI"],
      ["flux.1","FLUX"],["black forest labs","FLUX (Black Forest Labs)"],["stability ai","Stability AI"],["stability.ai","Stability AI"],
      ["grok","Grok (xAI)"],["qwen image","Qwen Image"],["seedream","Seedream"],["krea ai","Krea AI"],["canva magic media","Canva Magic Media"],["playground ai","Playground AI"]
    ];
    const foundGens=[];
    for(const [tok,label] of gens){ if(lower.includes(tok)&&!foundGens.includes(label)) foundGens.push(label); }
    // Parametri di generazione tipici (tEXt/iTXt/XMP) di Stable Diffusion / ComfyUI.
    if((lower.includes("sampler:") && lower.includes("steps:")) || (lower.includes("cfg scale") && lower.includes("seed:")))
      if(!foundGens.includes("Stable Diffusion")) foundGens.push("Stable Diffusion");
    if((lower.includes('"class_type"')||lower.includes('"workflow"')||lower.includes("comfyui")) && !foundGens.includes("ComfyUI")) foundGens.push("ComfyUI");
    if(foundGens.length){ strong=true; signals.push({strong:true,ico:"🤖",kKey:"ai.gen.k",vRaw:foundGens.join(", ")}); }

    const workflowHits=[];
    function addHit(label,tests){ if(tests.some(x=>lower.includes(x))&&!workflowHits.includes(label)) workflowHits.push(label); }
    addHit("prompt",["prompt:","negative prompt","positive prompt",'"prompt"',"parameters"]);
    addHit("seed",["seed:"," seed ","seed=",'"seed"']);
    addHit("sampler",["sampler:","sampler_name",'"sampler"']);
    addHit("model",["model hash","model_hash","model:","model_name",'"checkpoint"',".safetensors"]);
    addHit("steps",["steps:","num_inference_steps",'"steps"']);
    addHit("cfg",["cfg scale","cfg_scale","guidance_scale"]);
    addHit("workflow",['"class_type"','"workflow"',"comfyui","node graph"]);
    const hasPrompt=workflowHits.includes("prompt");
    const hasGenerationParams=workflowHits.some(x=>["seed","sampler","model","steps","cfg","workflow"].includes(x));
    if((hasPrompt&&hasGenerationParams) || workflowHits.includes("workflow") || (workflowHits.includes("sampler")&&workflowHits.includes("steps"))){
      strong=true;
      signals.push({strong:true,ico:"🧩",kKey:"ai.workflow.k",vRaw:workflowHits.join(", ") || t("ai.workflow.v")});
    }else if(scan.flags.compressedTextKeys.length){
      maybe=true;
      signals.push({ico:"🗜️",kKey:"ai.compressed.k",vKey:"ai.compressed.v"});
    }

    // 4) Dichiarazioni testuali esplicite.
    const phrases=[["made with ai","“Made with AI”"],["ai generated","“AI generated”"],["generated by ai","“Generated by AI”"],["created with ai","“Created with AI”"],["ai generated image","“AI Generated Image”"]];
    const foundPhr=[];
    for(const [tok,label] of phrases){ if(lower.includes(tok)&&!foundPhr.includes(label)) foundPhr.push(label); }
    if(foundPhr.length){ strong=true; signals.push({strong:true,ico:"💬",kKey:"ai.phrase.k",vRaw:foundPhr.join(", ")}); }

    return { level: strong?"detected":(maybe?"maybe":"clear"), signals };
  }

  const AI_ICON={detected:"🤖",maybe:"❓",clear:"✓"};
  function renderAI(ai){
    mAIWrap.innerHTML="";
    const banner=document.createElement("div");
    banner.className="ai-verdict "+ai.level;
    banner.innerHTML='<div class="ic">'+AI_ICON[ai.level]+'</div><div class="tx"><h4>'+esc(t("verdict."+ai.level+".h"))+'</h4><p>'+esc(t("verdict."+ai.level+".p"))+'</p></div>';
    mAIWrap.appendChild(banner);
    if(ai.signals.length){
      const list=document.createElement("div"); list.className="ai-list";
      ai.signals.forEach(s=>{
        const val = s.vKey ? t(s.vKey) : (s.vRaw||"");
        const pill = s.strong ? t("ai.pill.strong") : t("ai.pill.weak");
        const el=document.createElement("div"); el.className="m-row"+(s.strong?" warn":"");
        el.innerHTML='<div class="ic">'+esc(s.ico)+'</div><div class="tx">'+
          '<div class="k">'+esc(t(s.kKey))+'<span class="pill '+(s.strong?'':'ai')+'">'+esc(pill)+'</span></div>'+
          '<div class="v" style="text-decoration:none">'+esc(val)+'</div></div>';
        list.appendChild(el);
      });
      mAIWrap.appendChild(list);
    }
    // Nota a scomparsa (stesso stile di "Perché è sicura?" nel footer).
    const note=document.createElement("details"); note.className="why ai-why";
    note.innerHTML='<summary>'+esc(t("ai.noteTitle"))+'</summary>'+
      '<p>'+t("ai.note")+'</p>';  // ai.note è una stringa interna fidata (HTML)
    mAIWrap.appendChild(note);
  }

  /* ====================== PULIZIA ====================== */
  /* Rende la pulizia "idempotente": dopo la ricodifica su canvas il browser
     reinserisce comunque dei segmenti nel JPEG (profilo colore ICC, marcatori
     Adobe/Photoshop). Qui li rimuoviamo, tenendo solo l'essenziale (APP0/JFIF +
     tabelle + dati immagine), così il file salvato è davvero senza metadati e
     reimportandolo non risulta più alcun "metadato incorporato". */
  function stripJpegMarkers(buf){
    const v=new DataView(buf), src=new Uint8Array(buf);
    if(v.getUint16(0)!==0xFFD8) return buf;            // non è JPEG: lascia com'è
    const parts=[src.subarray(0,2)];                   // SOI
    let off=2;
    // SICUREZZA — Anti-DoS: tetto massimo sui segmenti percorsi.
    let segCount=0;
    while(off<v.byteLength){
      if(src[off]!==0xFF){ parts.push(src.subarray(off)); break; }
      const marker=v.getUint16(off);
      if(marker===0xFFDA){ parts.push(src.subarray(off)); break; }   // SOS: copia dati+EOI così come sono
      if(marker>=0xFFD0&&marker<=0xFFD9){ parts.push(src.subarray(off,off+2)); off+=2; continue; }
      if(off+4>v.byteLength){ parts.push(src.subarray(off)); break; }
      const len=v.getUint16(off+2);
      // SICUREZZA — len minimo 2, altrimenti dati corrotti.
      if(len<2 || segCount++>MAX_JPEG_SEG) break;
      const segEnd=off+2+len;
      // Scarta APP1..APP15 (EXIF/XMP/ICC/IPTC/Adobe) e i commenti (COM); tiene APP0/JFIF.
      const drop=(marker>=0xFFE1&&marker<=0xFFEF)||marker===0xFFFE;
      if(!drop) parts.push(src.subarray(off,segEnd));
      off=segEnd;
    }
    let total=0; parts.forEach(p=>total+=p.length);
    const res=new Uint8Array(total); let p=0;
    parts.forEach(seg=>{res.set(seg,p);p+=seg.length;});
    return res.buffer;
  }

  async function cleanImage(file){
    // Disegna i soli pixel su <canvas> e li ricodifica: il file in uscita non
    // contiene metadati. NB: i watermark nei pixel (es. SynthID) restano.
    let bitmap;
    try{ bitmap=await createImageBitmap(file,{imageOrientation:"from-image"}); }
    catch(e){ bitmap=await createImageBitmap(file); }
    // Guardia anti "decompression bomb": un file piccolo può decodificare in
    // un'immagine enorme e saturare la memoria del canvas.
    if(bitmap.width*bitmap.height > MAX_PIXELS){
      bitmap.close&&bitmap.close();
      throw new Error("Immagine troppo grande in pixel");
    }
    const canvas=document.createElement("canvas");
    canvas.width=bitmap.width; canvas.height=bitmap.height;
    canvas.getContext("2d").drawImage(bitmap,0,0);
    bitmap.close&&bitmap.close();
    const outType=(file.type==="image/png"||file.type==="image/webp")?file.type:"image/jpeg";
    const quality=outType==="image/jpeg"?0.92:undefined;
    let blob=await new Promise(r=>canvas.toBlob(r,outType,quality));
    // Per i JPEG, togli i segmenti APP/commenti reintrodotti dall'encoder del browser.
    if(outType==="image/jpeg" && blob){
      try{ blob=new Blob([stripJpegMarkers(await blob.arrayBuffer())],{type:"image/jpeg"}); }catch(e){}
    }
    return {blob,type:outType,w:canvas.width,h:canvas.height};
  }
  function renameClean(name,type){
    // SICUREZZA — Previene path traversal: prende solo l'ultimo componente del nome
    // (dopo l'ultimo / o \), rimuove .. e caratteri non sicuri.
    name=name.replace(/^.*[\\/]/,"").replace(/^[.]+/,"").replace(/[^a-z0-9_.() -]/gi,"_")||"image";
    return name.replace(/\.[^.]+$/,"")+"-pulita."+ext(type);
  }

  // Riepilogo sotto i pulsanti di scelta, ricalcolato (anche al cambio lingua).
  function setChoiceHint(){
    if(!lastAI){ choiceHint.textContent=""; return; }
    if(lastAI.level==="detected") choiceHint.textContent=t("hint.detected");
    else if(lastAI.level==="maybe") choiceHint.textContent=t("hint.maybe");
    else choiceHint.textContent=(lastReport&&lastReport.items.length)
      ? t("hint.metaCount",{n:lastReport.items.length})
      : t("hint.none");
  }

  // Punto di ingresso: valida il file, poi analizza i metadati. La pulizia
  // avviene solo su richiesta dell'utente (doClean).
  async function handleFile(file){
    if(!file || !isAllowedType(file.type)) return;   // solo immagini raster (no SVG)
    if(file.size>MAX_FILE_BYTES){
      drop.classList.add("hidden"); stage.classList.add("show");
      frame.classList.remove("scanning"); chip.classList.remove("show");
      choice.style.visibility="visible";
      choiceHint.textContent=t("err.fileTooLarge",{mb:MAX_FILE_BYTES/1048576});
      return;
    }
    drop.classList.add("hidden"); stage.classList.add("show");
    choice.style.visibility="hidden";
    chip.classList.add("show"); chiptx.textContent=t("chip.analyzing"); frame.classList.add("scanning");

    if(originalURL) URL.revokeObjectURL(originalURL);
    originalURL=URL.createObjectURL(file);
    preview.src=originalURL;
    currentFile=file;

    const buf=await file.arrayBuffer();
    lastReport=analyze(buf,file.type);
    lastAI=analyzeAI(buf,file.type);
    await new Promise(r=>setTimeout(r,650));

    frame.classList.remove("scanning"); chip.classList.remove("show");
    setChoiceHint();
    choice.style.visibility="visible";
  }

  /* ====================== CARICAMENTO MULTIPLO (BATCH) ====================== */
  // 1 file → flusso dettagliato (pulizia/analisi); 2+ file → pulizia in serie.
  function handleFiles(fileList){
    const list=[...fileList].filter(f=>isAllowedType(f.type) && f.size<=MAX_FILE_BYTES);
    if(!list.length) return;
    if(list.length===1) handleFile(list[0]); else handleBatch(list);
  }

  async function handleBatch(list){
    drop.classList.add("hidden"); stage.classList.remove("show"); batch.classList.add("show");
    batchTitle.textContent=t("batch.title",{n:list.length});
    batchList.innerHTML="";
    batchURLs.forEach(u=>URL.revokeObjectURL(u)); batchURLs=[]; batchItems=[];
    batchDownloadAll.disabled=true; batchDownloadAll.textContent=t("batch.processing");
    list.forEach(file=>{
      const row=document.createElement("div"); row.className="brow";
      row.innerHTML='<div class="bthumb"><span class="spin"></span></div>'+
        '<div class="bmeta"><div class="bname"></div><div class="bsize">'+esc(t("batch.processing"))+'</div></div>'+
        '<div class="bact"></div>';
      row.querySelector(".bname").textContent=file.name;   // textContent: nome file non fidato
      batchList.appendChild(row);
      batchItems.push({file,row});
    });
    // Elaborazione in serie per non saturare la memoria (un canvas alla volta).
    for(const it of batchItems){ await processBatchItem(it); }
    const ready=batchItems.filter(x=>x.url).length;
    batchDownloadAll.disabled = ready===0;
    batchDownloadAll.textContent=t("batch.downloadAll",{n:ready});
  }

  async function processBatchItem(it){
    const {file,row}=it;
    const thumb=row.querySelector(".bthumb"), size=row.querySelector(".bsize"),
          act=row.querySelector(".bact"), name=row.querySelector(".bname");
    try{
      const buf=await file.arrayBuffer();
      const ai=analyzeAI(buf,file.type);
      const cleaned=await cleanImage(file);
      const cf=new File([cleaned.blob], renameClean(file.name,cleaned.type), {type:cleaned.type});
      const url=URL.createObjectURL(cleaned.blob); batchURLs.push(url);
      it.cleanedFile=cf; it.url=url;
      const img=document.createElement("img"); img.alt=""; img.src=url;
      thumb.innerHTML=""; thumb.appendChild(img);
      size.textContent=fmtBytes(file.size)+" → "+fmtBytes(cleaned.blob.size);
      if(ai.level==="detected"){
        const b=document.createElement("span"); b.className="bbadge ai"; b.textContent=t("batch.aiBadge"); name.appendChild(b);
      }
      incCount();
      const d=document.createElement("button"); d.className="bdl"; d.textContent=t("batch.save");
      d.onclick=()=>{ const a=document.createElement("a"); a.href=url; a.download=cf.name; document.body.appendChild(a); a.click(); a.remove(); };
      act.appendChild(d);
    }catch(e){
      thumb.innerHTML="⚠️"; size.textContent=t("batch.error");
    }
  }

  function batchClear(){
    batch.classList.remove("show"); drop.classList.remove("hidden");
    fileInput.value="";
    batchURLs.forEach(u=>URL.revokeObjectURL(u)); batchURLs=[]; batchItems=[];
    batchList.innerHTML="";
  }

  async function doClean(){
    if(!currentFile) return;
    choice.style.visibility="hidden";
    chip.classList.add("show"); chiptx.textContent=t("chip.cleaning"); frame.classList.add("scanning");
    let cleaned;
    try{ cleaned=await cleanImage(currentFile); }
    catch(e){
      frame.classList.remove("scanning"); chip.classList.remove("show");
      choice.style.visibility="visible";
      choiceHint.textContent=/pixel/.test(e&&e.message) ? t("err.pixels") : t("err.format");
      return;
    }
    await new Promise(r=>setTimeout(r,400));
    frame.classList.remove("scanning"); chip.classList.remove("show");

    cleanedFile=new File([cleaned.blob], renameClean(currentFile.name,cleaned.type), {type:cleaned.type});
    if(cleanedURL)URL.revokeObjectURL(cleanedURL);
    cleanedURL=URL.createObjectURL(cleaned.blob);
    preview.src=cleanedURL;
    lastSizes={orig:currentFile.size, clean:cleaned.blob.size, w:cleaned.w, h:cleaned.h};
    choice.style.visibility="visible";
    incCount();   // +1 immagine ripulita su questo dispositivo (solo locale)

    modalMode="clean";
    populateModal();
    openModal();
  }

  function showAnalysis(){
    if(!currentFile) return;
    modalMode="analyze";
    populateModal();
    openModal();
  }

  function populateModal(){
    const analyzeOnly = modalMode==="analyze";
    mImg.src = analyzeOnly ? originalURL : cleanedURL;

    if(analyzeOnly){
      mTitle.textContent=t("modal.analyzeTitle");
      mSub.textContent=t("modal.analyzeSub");
      mSizes.style.display="none";
      mMetaTitle.textContent=t("meta.presentTitle");
    }else{
      mTitle.textContent=t("modal.cleanTitle");
      if(lastReport && lastReport.gps) mSub.textContent=t("modal.cleanSubGps");
      else if(lastReport && lastReport.items.length) mSub.textContent=t("modal.cleanSubItems");
      else mSub.textContent=t("modal.cleanSubNone");
      mSizes.style.display="";
      mSizes.innerHTML='<span>'+esc(t("size.original"))+' <b>'+esc(fmtBytes(lastSizes.orig))+'</b></span>'+
        '<span class="arrow">→</span>'+
        '<span>'+esc(t("size.cleaned"))+' <b>'+esc(fmtBytes(lastSizes.clean))+'</b> · '+lastSizes.w+'×'+lastSizes.h+'</span>';
      mMetaTitle.textContent=t("meta.removedTitle");
    }
    mAITitle.textContent=t("modal.analyzeTitle");

    renderAI(lastAI);

    mMeta.innerHTML="";
    if(lastReport && lastReport.items.length){
      lastReport.items.forEach(it=>{
        const el=document.createElement("div");
        el.className="m-row"+(it.warn?" warn":"");
        const pill = analyzeOnly ? "" : '<span class="pill">'+esc(t("meta.removedPill"))+'</span>';
        // esc(): il valore può contenere stringhe arbitrarie lette dall'EXIF → XSS.
        el.innerHTML='<div class="ic">'+esc(it.ico)+'</div><div class="tx">'+
          '<div class="k">'+esc(t(it.kKey))+pill+'</div>'+
          '<div class="v"'+(analyzeOnly?' style="text-decoration:none"':'')+'>'+esc(itemValue(it))+'</div></div>';
        // La riga GPS è cliccabile e apre il popup mappa.
        if(it.kKey==="meta.gps" && lastReport.gps){
          el.classList.add("geo-row"); el.setAttribute("role","button"); el.tabIndex=0;
          const k=el.querySelector(".k");
          if(k){ const m=document.createElement("span"); m.className="maplink"; m.textContent="🗺 "+t("geo.viewMap"); k.appendChild(m); }
          const go=()=>openGeo(lastReport.gps.lat, lastReport.gps.lon);
          el.addEventListener("click",go);
          el.addEventListener("keydown",e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); go(); } });
        }
        mMeta.appendChild(el);
      });
    }else{
      const e=document.createElement("div"); e.className="m-empty";
      e.textContent=(lastReport&&lastReport.unknown) ? t("empty.unknown")
        : (analyzeOnly ? t("empty.analyzeNone") : t("empty.cleanNone"));
      mMeta.appendChild(e);
    }

    buildActions(analyzeOnly);
  }

  function buildActions(analyzeOnly){
    mActions.innerHTML="";
    if(analyzeOnly){
      iosHint.classList.remove("show");
      const c=document.createElement("button");
      c.className="btn btn-primary";
      c.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21l4-1 11-11-3-3L4 17l-1 4z"/><path d="M14 6l3 3"/></svg>'+esc(t("btn.clean"));
      c.onclick=()=>{ closeModal(); doClean(); };
      mActions.appendChild(c);
      return;
    }
    let canShare=false; try{ canShare=navigator.canShare&&cleanedFile&&navigator.canShare({files:[cleanedFile]}); }catch(e){}
    const secure = window.isSecureContext;
    if(isIOS){
      iosHint.classList.add("show");
      iosHint.innerHTML = secure ? t("ios.secure") : t("ios.insecure");
      if(canShare){
        const b=document.createElement("button");
        b.className="btn btn-primary"; b.innerHTML=iconShare()+esc(t("btn.saveShare"));
        b.onclick=shareFile; mActions.appendChild(b);
      }
      const d=document.createElement("button");
      d.className="btn "+(canShare?"btn-ghost":"btn-primary"); d.innerHTML=iconDl()+esc(t("btn.fullscreen"));
      d.onclick=openFullscreen; mActions.appendChild(d);
    }else{
      iosHint.classList.remove("show");
      const d=document.createElement("button");
      d.className="btn btn-primary"; d.innerHTML=iconDl()+esc(t("btn.download"));
      d.onclick=downloadFile; mActions.appendChild(d);
      if(canShare){
        const s=document.createElement("button");
        s.className="btn btn-ghost"; s.innerHTML=iconShare()+esc(t("btn.share"));
        s.onclick=shareFile; mActions.appendChild(s);
      }
    }
  }
  async function shareFile(){
    try{ await navigator.share({files:[cleanedFile], title:cleanedFile.name}); }
    catch(e){ if(e&&e.name!=="AbortError"){ isIOS?openFullscreen():downloadFile(); } }
  }
  function downloadFile(){
    const a=document.createElement("a");
    a.href=cleanedURL; a.download=cleanedFile.name;
    document.body.appendChild(a); a.click(); a.remove();
  }
  // `noopener,noreferrer` impedisce alla nuova scheda di accedere a window.opener.
  function openFullscreen(){ window.open(cleanedURL,"_blank","noopener,noreferrer"); }
  function iconDl(){return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v12M12 16l-4-4M12 16l4-4"/><path d="M4 20h16"/></svg>';}
  function iconShare(){return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7"/><path d="M12 3v13M12 3l-4 4M12 3l4 4"/></svg>';}

  function openModal(){ modal.classList.add("open"); modal.setAttribute("aria-hidden","false"); document.body.classList.add("lock"); }
  function closeModal(){
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden","true");
    if(!geoModal.classList.contains("open") && !infoModal.classList.contains("open")) document.body.classList.remove("lock");
  }

  /* Popup mappa GPS: mostra le coordinate e offre l'apertura di una mappa
     ESTERNA in una nuova scheda (solo su clic). La pagina non fa richieste. */
  function openGeo(lat,lon){
    const c=lat.toFixed(6)+", "+lon.toFixed(6);
    geoTitle.textContent=t("geo.title");
    geoCoords.textContent=c;
    geoNote.textContent=t("geo.note");
    geoActions.innerHTML="";
    function linkBtn(cls,label,url){
      const b=document.createElement("button"); b.className="btn "+cls;
      b.textContent=label;
      b.onclick=()=>window.open(url,"_blank","noopener,noreferrer");
      geoActions.appendChild(b);
    }
    linkBtn("btn-primary", t("geo.openOSM"),
      "https://www.openstreetmap.org/?mlat="+lat+"&mlon="+lon+"#map=15/"+lat+"/"+lon);
    linkBtn("btn-outline", t("geo.openGoogle"),
      "https://www.google.com/maps?q="+lat+","+lon);
    const cp=document.createElement("button"); cp.className="btn btn-ghost"; cp.textContent=t("geo.copy");
    cp.onclick=()=>{ try{ navigator.clipboard && navigator.clipboard.writeText(c); cp.textContent=t("geo.copied"); }catch(e){} };
    geoActions.appendChild(cp);
    geoModal.classList.add("open"); geoModal.setAttribute("aria-hidden","false"); document.body.classList.add("lock");
  }
  function closeGeo(){
    geoModal.classList.remove("open");
    geoModal.setAttribute("aria-hidden","true");
    if(!modal.classList.contains("open") && !infoModal.classList.contains("open")) document.body.classList.remove("lock");
  }

  function openInfo(){
    if(infoVersion) infoVersion.textContent="v"+APP_VERSION;
    infoModal.classList.add("open");
    infoModal.setAttribute("aria-hidden","false");
    document.body.classList.add("lock");
  }
  function closeInfo(){
    infoModal.classList.remove("open");
    infoModal.setAttribute("aria-hidden","true");
    if(!modal.classList.contains("open") && !geoModal.classList.contains("open")) document.body.classList.remove("lock");
  }

  function doReset(){
    closeModal();
    stage.classList.remove("show"); drop.classList.remove("hidden");
    fileInput.value="";
    if(cleanedURL){URL.revokeObjectURL(cleanedURL);cleanedURL=null;}
    if(originalURL){URL.revokeObjectURL(originalURL);originalURL=null;}
    cleanedFile=null; currentFile=null; lastReport=null; lastSizes=null; lastAI=null;
  }

  /* ====================== EVENTI ====================== */
  drop.addEventListener("click",()=>fileInput.click());
  fileInput.addEventListener("change",e=>{ if(e.target.files.length) handleFiles(e.target.files); });
  reset.addEventListener("click",doReset);
  batchReset.addEventListener("click",batchClear);
  batchDownloadAll.addEventListener("click",async()=>{
    // "Scarica tutte": download in sequenza (nessuno zip, nessuna libreria esterna).
    for(const it of batchItems){
      if(it.url && it.cleanedFile){
        const a=document.createElement("a"); a.href=it.url; a.download=it.cleanedFile.name;
        document.body.appendChild(a); a.click(); a.remove();
        await new Promise(r=>setTimeout(r,300));
      }
    }
  });
  actClean.addEventListener("click",doClean);
  actAnalyze.addEventListener("click",showAnalysis);
  headerInfoBtn.addEventListener("click",openInfo);
  aiInfoBtn.addEventListener("click",openInfo);
  mClose.addEventListener("click",closeModal);
  backdrop.addEventListener("click",closeModal);
  geoClose.addEventListener("click",closeGeo);
  geoBackdrop.addEventListener("click",closeGeo);
  infoClose.addEventListener("click",closeInfo);
  infoBackdrop.addEventListener("click",closeInfo);
  document.addEventListener("keydown",e=>{
    if(e.key!=="Escape") return;
    if(infoModal.classList.contains("open")) closeInfo();
    else if(geoModal.classList.contains("open")) closeGeo();
    else if(modal.classList.contains("open")) closeModal();
  });
  langBtn.addEventListener("click",()=>setLang(LANG==="it"?"en":"it"));
  themeBtn.addEventListener("click",cycleTheme);

  ["dragenter","dragover"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add("over");}));
  ["dragleave","drop"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove("over");}));
  drop.addEventListener("drop",e=>{ if(e.dataTransfer.files.length) handleFiles(e.dataTransfer.files); });
  window.addEventListener("paste",e=>{ const f=e.clipboardData&&e.clipboardData.files&&e.clipboardData.files[0]; if(f&&isAllowedType(f.type)) handleFile(f); });

  /* ====================== AVVIO ====================== */
  applyTheme();
  applyStaticI18n();
  renderCount();
})();
