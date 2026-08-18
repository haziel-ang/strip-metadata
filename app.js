/*!
 * Pulisci — Rimozione metadati & analisi origine AI
 * @version 1.14.0
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
  const APP_VERSION="1.14.0";
  // Il popup pubblico avanza solo quando viene pubblicato un changelog pubblico.
  const PUBLIC_RELEASE_VERSION="1.14.0";
  const swAllowed = location.protocol === "https:" ||
    location.hostname === "localhost" || location.hostname === "127.0.0.1";
  if ("serviceWorker" in navigator && swAllowed) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./sw.js").catch(() => {});
    });
  }

  // Limiti difensivi (anti-DoS in locale).
  const MAX_FILE_BYTES=64*1024*1024;   // 64 MB: tetto sul file in ingresso
  const MAX_META_CHARS=512;            // lunghezza massima mostrata per un valore
  const MAX_SCAN_BYTES=2*1024*1024;    // byte di metadati analizzati per l'AI scan
  const MAX_AI_DEBUG_CHARS=1800;        // estratto grezzo mostrato nella vista tecnica
  const MAX_PIXELS=80*1000*1000;       // ~80 MP: guardia contro "decompression bomb"
  const MAX_JPEG_SEG=4096;             // tetto massimo segmenti JPEG (anti-DoS)
  const MAX_META_CHUNKS=4096;           // tetto chunk PNG/WebP percorsi (anti-DoS)

  // Solo immagini raster: gli SVG sono esclusi (possono contenere script).
  function normalizedMime(t){ return String(t||"").toLowerCase().split(";",1)[0].trim(); }
  function isAllowedType(t){ t=normalizedMime(t); return /^image\//.test(t) && t!=="image/svg+xml"; }
  function isAllowedFile(file){
    if(!file) return false;
    if(isAllowedType(file.type)) return true;
    const type=normalizedMime(file.type);
    return (type==="" || type==="application/octet-stream") && /\.(?:jpe?g|png|webp|heic|heif)$/i.test(file.name||"");
  }

  // Il MIME di File deriva spesso dall'estensione/OS e non dai byte reali.
  // I download di ChatGPT, in particolare, possono chiamarsi .png ma contenere
  // un RIFF/WebP. La firma binaria ha quindi sempre precedenza sul MIME.
  function sniffImageType(buf,declaredType){
    try{
      const view=new DataView(buf);
      if(view.byteLength>=8){
        const png=[137,80,78,71,13,10,26,10];
        if(png.every((b,i)=>view.getUint8(i)===b)) return "image/png";
      }
      if(view.byteLength>=3 && view.getUint8(0)===0xFF && view.getUint8(1)===0xD8 && view.getUint8(2)===0xFF)
        return "image/jpeg";
      if(view.byteLength>=12){
        const cc=o=>String.fromCharCode(view.getUint8(o),view.getUint8(o+1),view.getUint8(o+2),view.getUint8(o+3));
        if(cc(0)==="RIFF" && cc(8)==="WEBP") return "image/webp";
      }
    }catch(e){}
    return "";
  }

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
      "ui.dropDesc":"Trascina qui le immagini. Oppure tocca per sceglierle.",
      "ui.choiceQ":"Vuoi pulirla o capire cosa raccontano i suoi dati?",
      "ui.reset":"↺ Carica un'altra immagine",
      "ui.footerLock":"Elaborazione locale",
      "ui.cleanedOne":"🧹 1 immagine ripulita su questo dispositivo",
      "ui.cleanedMany":"🧹 {n} immagini ripulite su questo dispositivo",
      "batch.title":"{n} immagini","batch.processing":"Elaborazione…","batch.error":"Errore",
      "batch.save":"Scarica","batch.aiBadge":"AI","batch.aiMaybeBadge":"AI?","batch.downloadAll":"Scarica tutte ({n})",
      "geo.viewMap":"Mappa","geo.title":"Posizione GPS",
      "geo.openOSM":"Apri in OpenStreetMap","geo.openGoogle":"Apri in Google Maps",
      "geo.copy":"Copia coordinate","geo.copied":"Copiato ✓",
      "geo.note":"Se apri una mappa, queste coordinate saranno inviate al servizio scelto. noMeta non le invia da sola.",
      "btn.clean":"Rimuovi tutti i metadati","btn.choose":"Scegli cosa conservare","btn.applyClean":"Pulisci con queste scelte","btn.analyze":"Analizza immagine","btn.aiInfo":"Info analisi AI",
      "btn.download":"Scarica immagine pulita","btn.share":"Condividi",
      "btn.saveShare":"Salva / Condividi","btn.fullscreen":"Apri a schermo intero",
      "chip.analyzing":"Analisi…","chip.cleaning":"Rimozione metadati…",
      "hint.detected":"I metadati dichiarano o suggeriscono un'origine AI.",
      "hint.maybe":"C'è una traccia di provenienza o di strumenti AI. Non basta per esserne certi.",
      "hint.metaCount":"Trovati {n} dati incorporati. Nessuna traccia evidente di AI.",
      "hint.none":"Nessun dato evidente. Questo non prova che l'immagine sia autentica.",
      "err.fileTooLarge":"File troppo grande (max {mb} MB).",
      "err.pixels":"Immagine troppo grande da elaborare (oltre 80 megapixel).",
      "err.format":"Questo formato non è elaborabile in questo browser — prova con un JPG o PNG.",
      "modal.cleanTitle":"Immagine ripulita","modal.analyzeTitle":"Analisi origine AI",
      "modal.chooseTitle":"Scegli cosa conservare",
      "add.title":"Scrivi i tuoi dati","add.sub":"Facoltativo. Vengono scritti nel file pulito al posto di quelli rimossi.",
      "add.name":"Nome dell'autore","add.namePh":"Mario Rossi",
      "add.lat":"Latitudine","add.lon":"Longitudine",
      "add.preview":"Verrà scritto:",
      "add.useMyPos":"Usa la mia posizione",
      "add.geoNote":"Su telefono la posizione arriva dal GPS. Su computer il browser può ricavarla contattando un servizio di rete: non lo fa noMeta, ma succede sul tuo dispositivo.",
      "add.geoWait":"Rilevamento in corso…","add.geoDenied":"Permesso negato. Puoi scrivere le coordinate a mano.",
      "add.geoFailed":"Posizione non disponibile. Puoi scrivere le coordinate a mano.",
      "add.coordsInvalid":"Servono entrambe le coordinate: latitudine da -90 a 90, longitudine da -180 a 180.",
      "meta.addedPill":"aggiunto","meta.addedTitle":"Metadati scritti",
      "modal.chooseSub":"Togli la spunta alle voci che vuoi lasciare nel file.",
      "modal.analyzeSub":"Ecco cosa raccontano le informazioni nascoste nel file.",
      "modal.cleanSubGps":"La posizione e gli altri dati nascosti non ci sono più.",
      "modal.cleanSubItems":"I dati nascosti non ci sono più.",
      "modal.cleanSubNone":"L'immagine è stata ricreata senza dati nascosti.",
      "meta.removedTitle":"Metadati rimossi","meta.presentTitle":"Metadati presenti nel file",
      "meta.chooseTitle":"Scegli cosa rimuovere",
      "meta.removedPill":"rimosso","size.original":"Originale","size.cleaned":"Pulita",
      "empty.unknown":"Questo browser non riesce a leggere tutti i dettagli del formato.",
      "empty.analyzeNone":"Non ho trovato dati nascosti leggibili.",
      "empty.cleanNone":"Non c'erano dati evidenti. Ho comunque ricreato l'immagine pulita.",
      "ios.secure":"Per salvarla nelle Foto: <b>tieni premuto</b> sull'immagine qui sopra → <b>Salva immagine</b>, oppure usa il pulsante qui sotto.",
      "ios.insecure":"⚠️ Il salvataggio con un tocco funziona solo aprendo questa pagina dal suo indirizzo <b>https://</b> (non dall'anteprima o da un file locale). Per ora: <b>tieni premuto</b> sull'immagine qui sopra → <b>Salva immagine</b>.",
      "meta.camera":"Fotocamera / dispositivo","meta.datetimeShot":"Data e ora dello scatto",
      "meta.datetime":"Data e ora","meta.software":"Software","meta.gps":"Posizione GPS",
      "meta.others":"Altri metadati incorporati","meta.text":"Testo incorporato","meta.lastmod":"Ultima modifica",
      "meta.c2pa":"Content Credentials (C2PA)",
      "meta.artist":"Autore / nominativo","meta.copyright":"Copyright",
      "meta.alwaysRemoved":"sempre rimosso","meta.keptPill":"mantenuto",
      "keep.remove":"Rimuovi","keep.keep":"Mantieni",
      "keep.summary":"Rimuovo {removed} voci, ne mantengo {kept}.",
      "keep.summaryAll":"Rimuovo tutte le {n} voci selezionabili.",
      "engine.title":"Come creare il file pulito",
      "engine.reencode":"Ricodifica l'immagine (consigliato)",
      "engine.reencodeNote":"Esce solo ciò che noMeta riscrive: nulla di sconosciuto sopravvive. Il JPEG viene ricompresso.",
      "engine.lossless":"Non ricodificare",
      "engine.losslessNote":"Qualità identica all'originale, ma sopravvive ciò che noMeta non riconosce.",
      "modal.cleanSubKept":"Ho rimosso i dati nascosti, tranne quelli che hai scelto di mantenere.",
      "val.gpsWhere":"dove è stata scattata","val.embeddedTimestamp":"timestamp incorporato","val.blocks":"blocco/i",
      "val.c2pa":"manifest di provenienza incorporato (spesso AI)",
      "extra.icc":"profilo colore","extra.iptc":"IPTC/Photoshop","extra.xmp":"XMP","extra.comment":"commenti",
      "verdict.detected.h":"Segnali di origine AI rilevati",
      "verdict.detected.p":"Il file contiene una dichiarazione che indica un'immagine generata o modificata con AI.",
      "verdict.maybe.h":"Possibili indizi di AI",
      "verdict.maybe.p":"Il file conserva una traccia di provenienza o nomina strumenti AI. Non è una prova.",
      "verdict.clear.h":"Nessun segnale AI nei metadati",
      "verdict.clear.p":"Non ho trovato dichiarazioni o nomi di strumenti AI. Ma i metadati possono essere rimossi.",
      "ai.pill.strong":"AI","ai.pill.weak":"indizio",
      "ai.c2pa.k":"Dichiarazione sull'origine dell'immagine",
      "ai.c2pa.v":"Il file conserva una cronologia firmata. Se dichiara l'uso di AI, è un segnale forte.",
      "ai.iptc.k":"Etichetta sull'origine digitale",
      "ai.dst.composite":"Contiene elementi generati con AI",
      "ai.dst.trained":"Dichiarata come immagine generata con AI",
      "ai.dst.compositeSynthetic":"Dichiarata come composizione sintetica",
      "ai.dst.algorithmic":"Dichiarata come immagine algoritmica",
      "ai.iptcPresent.k":"Etichetta di origine presente",
      "ai.iptcPresent.v":"Il valore non indica un'origine AI riconoscibile.",
      "ai.gen.k":"Nome di uno strumento AI",
      "ai.workflow.k":"Impostazioni di generazione",
      "ai.workflow.v":"Il file conserva prompt, modello, seed o altre impostazioni tipiche dei generatori AI.",
      "ai.compressed.k":"Testo nascosto e compresso",
      "ai.compressed.v":"Il file contiene un testo sospetto che questo browser non è riuscito ad aprire.",
      "ai.phrase.k":"Dichiarazione scritta nel file",
      "ai.debug.title":"Vista tecnica metadati",
      "ai.debug.none":"Nessun testo grezzo leggibile nei metadati analizzati.",
      "ai.debug.chunks":"Chunk PNG letti",
      "ai.debug.inflated":"Decompressi",
      "ai.debug.failed":"Compressi non aperti",
      "ai.debug.bytes":"Byte campionati",
      "ai.debug.raw":"Estratto grezzo",
      "ai.action.k":"Cosa dichiara la cronologia",
      "ai.action.created":"Immagine o risorsa creata",
      "ai.action.edited":"Immagine modificata o composta",
      "ai.noteTitle":"Cosa può sfuggire all'analisi?",
      "ai.note":"noMeta legge le informazioni scritte nel file, non i pixel. Non può quindi vedere watermark invisibili come <b>SynthID</b>. E se qualcuno ha già cancellato i metadati, la loro assenza <b>non dimostra</b> che l'immagine sia reale.",
      "info.title":"Cosa può dirti un'immagine",
      "info.sub":"noMeta legge i dati nascosti nel file. Non prova a indovinare guardando i pixel.",
      "info.detectTitle":"Tracce di AI",
      "info.detect1":"Cerca dichiarazioni di provenienza inserite dai programmi che hanno creato o modificato l'immagine.",
      "info.detect2":"Legge le etichette usate da editori e agenzie per segnalare contenuti generati o compositi.",
      "info.detect3":"Riconosce i nomi dei generatori e degli strumenti AI scritti nei metadati.",
      "info.detect4":"Cerca anche prompt, modello, seed e altre impostazioni lasciate dai programmi di generazione.",
      "info.cleanTitle":"Pulizia",
      "info.clean1":"Crea una nuova copia dell'immagine e lascia fuori posizione, dispositivo, date e altri dati nascosti.",
      "info.clean2":"Controlla anche la copia finale, perché alcuni browser possono reinserire informazioni nei file JPEG.",
      "info.clean3":"Se scegli più immagini, le pulisce una alla volta sul tuo dispositivo.",
      "info.limitsTitle":"Limiti reali",
      "info.limit1":"Non vede watermark nascosti nei pixel, come SynthID.",
      "info.limit2":"Se non trova metadati, non significa che l'immagine sia autentica.",
      "info.limit3":"I dati possono essere cancellati o falsificati. Il risultato è un indizio, non una perizia.",
      "info.privacyTitle":"Privacy",
      "info.privacy":"La tua immagine resta qui. Il browser la apre in memoria e una regola blocca ogni invio in rete.",
      "info.deepTitle":"Come leggere il risultato",
      "info.deep":"Una dichiarazione esplicita nel file vale più di un nome isolato. Più tracce indipendenti trova, più il risultato è affidabile. Una sola parola generica, invece, non basta.",
      "alt.preview":"anteprima","alt.result":"immagine pulita",
      "theme.system":"Sistema","theme.light":"Chiaro","theme.dark":"Scuro",
      "ui.credit":"© 2026 <b>profxeni</b> · Licenza <a href=\"https://creativecommons.org/licenses/by/4.0/\" target=\"_blank\" rel=\"noopener noreferrer\">CC BY 4.0</a>: puoi copiarla e modificarla citando l'autore.",
      "info.safetyTitle":"Sicurezza",
      "info.safetyText":"La pagina arriva sul dispositivo. La foto no: resta nella memoria del browser mentre la pulisci. Nessun caricamento, nessun account. Dopo la prima apertura puoi provare anche in <b>modalità aereo</b>.",
      "info.heic":"*I file HEIC vengono convertiti in JPG durante la pulizia.",
      "info.synthTitle":"Perché non rileva SynthID?",
      "info.synthText":"L'analisi legge le informazioni scritte nel file, non i pixel. Per questo non può vedere watermark invisibili come <b>SynthID</b>. E se i metadati sono già stati rimossi, non può stabilire se l'immagine è nata con l'AI. Il risultato è un indizio, non una prova.",
      "release.title":"Novità della versione 1.14",
      "release.sub":"Adesso puoi anche firmare i tuoi scatti.",
      "release.lead":"Non solo togliere: da oggi puoi scrivere i tuoi dati nella foto.",
      "release.pickTitle":"Il tuo nome, il tuo copyright",
      "release.pickText":"Scrivi come ti chiami e noMeta compone il copyright con l'anno dello scatto: «© 2019 Mario Rossi». Il nome se lo ricorda per la volta dopo.",
      "release.defaultTitle":"La posizione che vuoi tu",
      "release.defaultText":"Incolla le coordinate o usa la tua posizione attuale. Utile per rimettere un luogo che un social ha cancellato.",
      "release.qualityTitle":"Scegliere resta come prima",
      "release.qualityText":"«Rimuovi tutti i metadati» continua a togliere tutto senza chiedere. Il resto lo trovi in «Scegli cosa conservare».",
      "release.done":"Ho capito"
    },
    en:{
      "ui.badge":"100% in your browser",
      "ui.h1":"Clean your <em>shots</em>",
      "ui.badgeInfo":"How it works",
      "ui.dropTitle":"Upload an image",
      "ui.dropDesc":"Drop your images here. Or tap to choose them.",
      "ui.choiceQ":"Clean it, or see what its hidden data says?",
      "ui.reset":"↺ Load another image",
      "ui.footerLock":"Local processing",
      "ui.cleanedOne":"🧹 1 image cleaned on this device",
      "ui.cleanedMany":"🧹 {n} images cleaned on this device",
      "batch.title":"{n} images","batch.processing":"Processing…","batch.error":"Error",
      "batch.save":"Download","batch.aiBadge":"AI","batch.aiMaybeBadge":"AI?","batch.downloadAll":"Download all ({n})",
      "geo.viewMap":"Map","geo.title":"GPS location",
      "geo.openOSM":"Open in OpenStreetMap","geo.openGoogle":"Open in Google Maps",
      "geo.copy":"Copy coordinates","geo.copied":"Copied ✓",
      "geo.note":"If you open a map, these coordinates will be sent to that service. noMeta does not send them on its own.",
      "btn.clean":"Remove all metadata","btn.choose":"Choose what to keep","btn.applyClean":"Clean with these choices","btn.analyze":"Analyze image","btn.aiInfo":"AI analysis info",
      "btn.download":"Download clean image","btn.share":"Share",
      "btn.saveShare":"Save / Share","btn.fullscreen":"Open fullscreen",
      "chip.analyzing":"Analyzing…","chip.cleaning":"Removing metadata…",
      "hint.detected":"The metadata declares or suggests an AI origin.",
      "hint.maybe":"There is a provenance trace or a reference to AI tools. That is not conclusive.",
      "hint.metaCount":"Found {n} embedded data items. No clear trace of AI.",
      "hint.none":"No obvious hidden data. This does not prove the image is authentic.",
      "err.fileTooLarge":"File too large (max {mb} MB).",
      "err.pixels":"Image too large to process (over 80 megapixels).",
      "err.format":"This format can't be processed in this browser — try a JPG or PNG.",
      "modal.cleanTitle":"Image cleaned","modal.analyzeTitle":"AI origin analysis",
      "modal.chooseTitle":"Choose what to keep",
      "add.title":"Write your own details","add.sub":"Optional. These are written into the clean file, in place of what was removed.",
      "add.name":"Author name","add.namePh":"Mario Rossi",
      "add.lat":"Latitude","add.lon":"Longitude",
      "add.preview":"Will be written:",
      "add.useMyPos":"Use my location",
      "add.geoNote":"On a phone the location comes from GPS. On a computer the browser may work it out by contacting a network service: noMeta does not, but it happens on your device.",
      "add.geoWait":"Locating…","add.geoDenied":"Permission denied. You can type the coordinates instead.",
      "add.geoFailed":"Location unavailable. You can type the coordinates instead.",
      "add.coordsInvalid":"Both coordinates are needed: latitude -90 to 90, longitude -180 to 180.",
      "meta.addedPill":"added","meta.addedTitle":"Metadata written",
      "modal.chooseSub":"Untick the items you want left in the file.",
      "modal.analyzeSub":"Here is what the information hidden in the file says.",
      "modal.cleanSubGps":"The location and other hidden data are gone.",
      "modal.cleanSubItems":"The hidden data is gone.",
      "modal.cleanSubNone":"The image was rebuilt without hidden data.",
      "meta.removedTitle":"Removed metadata","meta.presentTitle":"Metadata present in the file",
      "meta.chooseTitle":"Choose what to remove",
      "meta.removedPill":"removed","size.original":"Original","size.cleaned":"Cleaned",
      "empty.unknown":"This browser cannot read every detail in this format.",
      "empty.analyzeNone":"I could not find any readable hidden data.",
      "empty.cleanNone":"There was no obvious hidden data. I rebuilt a clean copy anyway.",
      "ios.secure":"To save to Photos: <b>press and hold</b> the image above → <b>Save Image</b>, or use the button below.",
      "ios.insecure":"⚠️ One-tap saving only works when opening this page from its <b>https://</b> address (not from a preview or local file). For now: <b>press and hold</b> the image above → <b>Save Image</b>.",
      "meta.camera":"Camera / device","meta.datetimeShot":"Capture date & time",
      "meta.datetime":"Date & time","meta.software":"Software","meta.gps":"GPS location",
      "meta.others":"Other embedded metadata","meta.text":"Embedded text","meta.lastmod":"Last modified",
      "meta.c2pa":"Content Credentials (C2PA)",
      "meta.artist":"Author / name","meta.copyright":"Copyright",
      "meta.alwaysRemoved":"always removed","meta.keptPill":"kept",
      "keep.remove":"Remove","keep.keep":"Keep",
      "keep.summary":"Removing {removed} items, keeping {kept}.",
      "keep.summaryAll":"Removing all {n} selectable items.",
      "engine.title":"How to build the clean file",
      "engine.reencode":"Re-encode the image (recommended)",
      "engine.reencodeNote":"Only what noMeta rewrites survives: nothing unknown gets through. JPEG is recompressed.",
      "engine.lossless":"Do not re-encode",
      "engine.losslessNote":"Quality identical to the original, but anything noMeta does not recognise survives.",
      "modal.cleanSubKept":"Hidden data removed, except the items you chose to keep.",
      "val.gpsWhere":"where it was taken","val.embeddedTimestamp":"embedded timestamp","val.blocks":"block(s)",
      "val.c2pa":"embedded provenance manifest (often AI)",
      "extra.icc":"color profile","extra.iptc":"IPTC/Photoshop","extra.xmp":"XMP","extra.comment":"comments",
      "verdict.detected.h":"AI-origin signals detected",
      "verdict.detected.p":"The file contains a statement marking it as generated or edited with AI.",
      "verdict.maybe.h":"Possible AI hints",
      "verdict.maybe.p":"The file keeps a provenance trace or names AI tools. It is not proof.",
      "verdict.clear.h":"No AI signal in metadata",
      "verdict.clear.p":"I found no declarations or AI tool names. But metadata can be removed.",
      "ai.pill.strong":"AI","ai.pill.weak":"hint",
      "ai.c2pa.k":"Statement about the image's origin",
      "ai.c2pa.v":"The file keeps a signed history. If it declares AI use, that is a strong signal.",
      "ai.iptc.k":"Digital origin label",
      "ai.dst.composite":"Contains elements generated with AI",
      "ai.dst.trained":"Declared as generated with AI",
      "ai.dst.compositeSynthetic":"Declared as a synthetic composite",
      "ai.dst.algorithmic":"Declared as algorithmic media",
      "ai.iptcPresent.k":"Origin label present",
      "ai.iptcPresent.v":"The value does not point to a recognized AI origin.",
      "ai.gen.k":"Name of an AI tool",
      "ai.workflow.k":"Generation settings",
      "ai.workflow.v":"The file keeps a prompt, model, seed, or other settings common to AI generators.",
      "ai.compressed.k":"Hidden compressed text",
      "ai.compressed.v":"The file contains suspicious text that this browser could not open.",
      "ai.phrase.k":"Statement written into the file",
      "ai.debug.title":"Technical metadata view",
      "ai.debug.none":"No readable raw text in the analyzed metadata.",
      "ai.debug.chunks":"PNG chunks read",
      "ai.debug.inflated":"Decompressed",
      "ai.debug.failed":"Compressed not opened",
      "ai.debug.bytes":"Sampled bytes",
      "ai.debug.raw":"Raw excerpt",
      "ai.action.k":"What the image history declares",
      "ai.action.created":"Image or asset created",
      "ai.action.edited":"Image edited or composed",
      "ai.noteTitle":"What can the analysis miss?",
      "ai.note":"noMeta reads information written into the file, not its pixels. It cannot see invisible watermarks such as <b>SynthID</b>. And if someone has already removed the metadata, its absence <b>does not prove</b> the image is real.",
      "info.title":"What an image can tell you",
      "info.sub":"noMeta reads data hidden in the file. It does not try to guess by looking at pixels.",
      "info.detectTitle":"Traces of AI",
      "info.detect1":"It looks for origin statements added by programs that created or edited the image.",
      "info.detect2":"It reads labels used by publishers and agencies to mark generated or composite content.",
      "info.detect3":"It recognizes generator and AI tool names written in the metadata.",
      "info.detect4":"It also looks for prompts, models, seeds, and other settings left by generation tools.",
      "info.cleanTitle":"Cleaning",
      "info.clean1":"It creates a fresh copy and leaves out location, device, dates, and other hidden data.",
      "info.clean2":"It checks the final copy too, because some browsers can put information back into JPEG files.",
      "info.clean3":"If you choose several images, it cleans them one at a time on your device.",
      "info.limitsTitle":"Honest limits",
      "info.limit1":"It cannot see watermarks hidden in pixels, such as SynthID.",
      "info.limit2":"If it finds no metadata, that does not mean the image is authentic.",
      "info.limit3":"Data can be removed or forged. The result is a clue, not a forensic ruling.",
      "info.privacyTitle":"Privacy",
      "info.privacy":"Your image stays here. The browser opens it in memory, and a security rule blocks it from being sent online.",
      "info.deepTitle":"How to read the result",
      "info.deep":"A clear statement in the file matters more than one isolated name. The more independent traces noMeta finds, the more reliable the result. One generic word is not enough.",
      "alt.preview":"preview","alt.result":"clean image",
      "theme.system":"System","theme.light":"Light","theme.dark":"Dark",
      "ui.credit":"© 2026 <b>profxeni</b> · Licensed <a href=\"https://creativecommons.org/licenses/by/4.0/\" target=\"_blank\" rel=\"noopener noreferrer\">CC BY 4.0</a>: copy and remix it with attribution.",
      "info.safetyTitle":"Safety",
      "info.safetyText":"The page arrives on your device. Your photo does not leave it: it stays in browser memory while you clean it. No upload. No account. After the first visit, try it in <b>airplane mode</b>.",
      "info.heic":"*HEIC files are converted to JPG during cleaning.",
      "info.synthTitle":"Why can't it detect SynthID?",
      "info.synthText":"The analysis reads information written into the file, not its pixels. That means it cannot see invisible watermarks such as <b>SynthID</b>. If the metadata has already been removed, it cannot tell whether the image was made with AI. The result is a clue, not proof.",
      "release.title":"What's new in version 1.14",
      "release.sub":"Now you can sign your own shots too.",
      "release.lead":"Not only removing: from today you can write your own details into a photo.",
      "release.pickTitle":"Your name, your copyright",
      "release.pickText":"Type your name and noMeta builds the copyright with the year the photo was taken: \"© 2019 Mario Rossi\". It remembers the name for next time.",
      "release.defaultTitle":"The location you want",
      "release.defaultText":"Paste coordinates or use your current position. Handy for putting back a place a social network stripped out.",
      "release.qualityTitle":"Choosing works as before",
      "release.qualityText":"\"Remove all metadata\" still removes everything without asking. The rest lives under \"Choose what to keep\".",
      "release.done":"Got it"
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
        actChoose=$("actChoose"),
        choiceHint=$("choiceHint"), reset=$("reset"),
        modal=$("modal"), backdrop=$("backdrop"), mClose=$("mClose"),
        mImg=$("mImg"), mTitle=$("mTitle"), mSub=$("mSub"), mSizes=$("mSizes"),
        mAITitle=$("mAITitle"), mAIWrap=$("mAIWrap"),
        mMetaTitle=$("mMetaTitle"), mMeta=$("mMeta"), mKeep=$("mKeep"), mAdd=$("mAdd"),
        mActions=$("mActions"), iosHint=$("iosHint"),
        langBtn=$("langBtn"), themeBtn=$("themeBtn"), statCleaned=$("statCleaned"),
        geoModal=$("geoModal"), geoBackdrop=$("geoBackdrop"), geoClose=$("geoClose"),
        geoTitle=$("geoTitle"), geoCoords=$("geoCoords"), geoActions=$("geoActions"), geoNote=$("geoNote"),
        infoModal=$("infoModal"), infoBackdrop=$("infoBackdrop"), infoClose=$("infoClose"),
        batch=$("batch"), batchList=$("batchList"), batchTitle=$("batchTitle"),
        batchDownloadAll=$("batchDownloadAll"), batchReset=$("batchReset"),
        headerInfoBtn=$("headerInfoBtn"),
        infoVersion=$("infoVersion"),
        releaseModal=$("releaseModal"), releaseBackdrop=$("releaseBackdrop"),
        releaseClose=$("releaseClose"), releaseDone=$("releaseDone");

  let batchItems=[], batchURLs=[], batchGeneration=0;

  const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent) ||
                (navigator.platform==="MacIntel" && navigator.maxTouchPoints>1);

  let cleanedURL=null, cleanedFile=null, originalURL=null, currentFile=null,
      lastReport=null, lastSizes=null, lastAI=null, modalMode="clean", analysisGeneration=0;
  // Selezione corrente: `keepSet` contiene gli id che l'utente ha DEselezionato,
  // cioè quelli da conservare. Vuoto = comportamento storico, rimuovi tutto.
  let keepSet=new Set(), cleanEngine="reencode", currentBuf=null, lastClean=null;
  // Valori che l'utente chiede di SCRIVERE nel file, non di conservare da esso.
  let injectName="", injectLat="", injectLon="";
  const AUTHOR_KEY="nm_author";

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

  // Il nome dell'autore sopravvive alla sessione: chi marchia molte foto non lo
  // riscrive ogni volta. Resta sul dispositivo, come lingua e tema.
  injectName = readStore(AUTHOR_KEY) || "";

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
      if(ifd0[0x013B]) out.artist=readASCII(ifd0[0x013B].valOff, ifd0[0x013B].count);
      if(ifd0[0x8298]) out.copyright=readASCII(ifd0[0x8298].valOff, ifd0[0x8298].count);
      // Orientation non è un dato sensibile e non viene mostrato in UI: serve solo
      // al motore senza ricodifica, che altrimenti lascerebbe l'immagine storta.
      if(ifd0[0x0112] && ifd0[0x0112].type===3){
        const o=u16(ifd0[0x0112].valOff);
        if(o>=1 && o<=8) out.orientation=o;
      }
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

  /* Righe di analisi comuni ai tre contenitori. `id` identifica la voce in modo
     stabile: è la chiave usata dalle caselle di selezione e dallo scrittore EXIF.
     `keepable:true` = la voce può essere conservata nel file pulito. */
  function pushExifItems(res,exif,dateKey){
    if(exif.make||exif.model) res.items.push({id:"camera",keepable:true,ico:"📷",kKey:"meta.camera",v:[exif.make,exif.model].filter(Boolean).join(" ")});
    if(exif.dateOriginal||exif.datetime) res.items.push({id:"datetime",keepable:true,ico:"📅",kKey:dateKey,v:(exif.dateOriginal||exif.datetime)});
    if(exif.software) res.items.push({id:"software",keepable:true,ico:"🛠",kKey:"meta.software",v:exif.software});
    if(exif.artist) res.items.push({id:"artist",keepable:true,ico:"✍️",kKey:"meta.artist",v:exif.artist});
    if(exif.copyright) res.items.push({id:"copyright",keepable:true,ico:"©️",kKey:"meta.copyright",v:exif.copyright});
  }

  function parseJPEG(buf){
    const view=new DataView(buf), res={items:[],bytes:0,gps:null};
    if(view.getUint16(0)!==0xFFD8) return null;
    let off=2; const seen={xmp:false,icc:false,iptc:false,comment:false,c2pa:false};
    // SICUREZZA — Anti-DoS: tetto massimo sui segmenti JPEG percorsi.
    let segCount=0;
    while(off<view.byteLength-1){
      if(view.getUint8(off)!==0xFF) break;
      while(off+1<view.byteLength && view.getUint8(off+1)===0xFF) off++;
      if(off+1>=view.byteLength) break;
      const marker=0xFF00|view.getUint8(off+1);
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
          res.exif=exif;
          pushExifItems(res,exif,"meta.datetimeShot");
          if(exif.gps) res.gps=exif.gps;
        }else seen.xmp=true;
      }
      else if(marker===0xFFE0) res.bytes+=len;
      else if(marker===0xFFE2){res.bytes+=len;seen.icc=true;}
      else if(marker===0xFFED){res.bytes+=len;seen.iptc=true;}
      else if(marker===0xFFEB){
        res.bytes+=len;
        const jp=segStart+1<view.byteLength && view.getUint8(segStart)===0x4A && view.getUint8(segStart+1)===0x50;
        let sample="";for(let i=segStart;i<Math.min(segStart+128,view.byteLength,off+2+len);i++)sample+=String.fromCharCode(view.getUint8(i));
        if(jp || /c2pa|jumbf|contentauth/i.test(sample)) seen.c2pa=true;
      }
      else if(marker>=0xFFE3&&marker<=0xFFEF){res.bytes+=len;seen.xmp=true;}
      else if(marker===0xFFFE){res.bytes+=len;seen.comment=true;}
      off+=2+len;
    }
    if(res.gps) res.items.unshift({id:"gps",keepable:true,warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5),suffixKey:"val.gpsWhere"});
    const extras=[];
    if(seen.icc)extras.push("extra.icc"); if(seen.iptc)extras.push("extra.iptc");
    if(seen.xmp)extras.push("extra.xmp"); if(seen.comment)extras.push("extra.comment");
    if(extras.length)res.items.push({id:"others",ico:"🗂",kKey:"meta.others",parts:extras});
    if(seen.c2pa) res.items.push({id:"c2pa",ico:"🔏",kKey:"meta.c2pa",vKey:"val.c2pa"});
    return res;
  }

  function parsePNG(buf){
    const view=new DataView(buf), res={items:[],bytes:0,gps:null};
    const sig=[137,80,78,71,13,10,26,10];
    for(let i=0;i<8;i++) if(view.getUint8(i)!==sig[i]) return null;
    let off=8, chunkCount=0; const txt=[];
    while(off+12<=view.byteLength && chunkCount++<MAX_META_CHUNKS){
      const len=view.getUint32(off);
      let type="";for(let i=0;i<4;i++)type+=String.fromCharCode(view.getUint8(off+4+i));
      if(["tEXt","iTXt","zTXt"].includes(type)){res.bytes+=len;txt.push(type);}
      else if(type==="eXIf"){res.bytes+=len;
        const exif=parseTIFF(view, off+8);
        res.exif=exif;
        pushExifItems(res,exif,"meta.datetime");
        if(exif.gps) res.gps=exif.gps;
      }
      else if(type==="tIME"){res.bytes+=len;res.items.push({id:"lastmod",ico:"📅",kKey:"meta.lastmod",vKey:"val.embeddedTimestamp"});}
      else if(type==="caBX"){res.bytes+=len;res.c2pa=true;}   // chunk privato C2PA
      if(type==="IEND")break;
      off+=12+len;
    }
    if(res.gps) res.items.unshift({id:"gps",keepable:true,warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5)});
    if(txt.length)res.items.push({id:"text",ico:"🗂",kKey:"meta.text",blocks:{n:txt.length,types:[...new Set(txt)].join(", ")}});
    if(res.c2pa) res.items.push({id:"c2pa",ico:"🔏",kKey:"meta.c2pa",vKey:"val.c2pa"});
    return res;
  }

  // WebP (contenitore RIFF): legge i chunk EXIF, XMP, ICCP, C2PA.
  // Importante perché ChatGPT (web) salva spesso in WebP anche con estensione .png.
  function parseWEBP(buf){
    const view=new DataView(buf), res={items:[],bytes:0,gps:null};
    const cc=o=>{let s="";for(let i=0;i<4;i++)s+=String.fromCharCode(view.getUint8(o+i));return s;};
    if(view.byteLength<12 || cc(0)!=="RIFF" || cc(8)!=="WEBP") return null;
    const riffSize=view.getUint32(4,true), riffEnd=Math.min(view.byteLength,8+riffSize);
    let off=12, chunkCount=0; const seen={xmp:false,icc:false,c2pa:false};
    while(off+8<=riffEnd && chunkCount++<MAX_META_CHUNKS){
      const id=cc(off), size=view.getUint32(off+4,true), ps=off+8;
      if(ps+size>riffEnd) break;
      if(id==="EXIF"){
        // il payload EXIF inizia col TIFF (II/MM); alcuni encoder antepongono "Exif\0\0".
        let ts=ps;
        if(view.getUint8(ps)===0x45&&view.getUint8(ps+1)===0x78&&view.getUint8(ps+2)===0x69&&view.getUint8(ps+3)===0x66) ts=ps+6;
        const exif=parseTIFF(view, ts);
        res.exif=exif;
        pushExifItems(res,exif,"meta.datetime");
        if(exif.gps) res.gps=exif.gps;
      }
      else if(id==="XMP ") seen.xmp=true;
      else if(id==="ICCP") seen.icc=true;
      else if(id==="C2PA") seen.c2pa=true;
      off=ps+size+(size&1);   // padding a byte pari
    }
    if(res.gps) res.items.unshift({id:"gps",keepable:true,warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5)});
    const extras=[];
    if(seen.icc)extras.push("extra.icc"); if(seen.xmp)extras.push("extra.xmp");
    if(extras.length)res.items.push({id:"others",ico:"🗂",kKey:"meta.others",parts:extras});
    if(seen.c2pa) res.items.push({id:"c2pa",ico:"🔏",kKey:"meta.c2pa",vKey:"val.c2pa"});
    return res;
  }

  function analyze(buf,type){
    try{
      type=sniffImageType(buf,type);
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
  function normalizeDebugText(s){
    return String(s||"").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]+/g," ")
      .replace(/\s+/g," ").trim().slice(0,MAX_AI_DEBUG_CHARS);
  }

  async function inflateZlibBytes(u8,maxOutputBytes=MAX_SCAN_BYTES){
    if(!("DecompressionStream" in window) || u8.byteLength>MAX_SCAN_BYTES || maxOutputBytes<=0) return null;
    try{
      const ds=new DecompressionStream("deflate");
      const writer=ds.writable.getWriter();
      const reader=ds.readable.getReader();
      const chunks=[];
      let total=0, limited=false;
      const reading=(async()=>{
        while(total<maxOutputBytes){
          const {value,done}=await reader.read();
          if(done) break;
          const bytes=new Uint8Array(value);
          const take=Math.min(bytes.byteLength,maxOutputBytes-total);
          if(take) chunks.push(bytes.slice(0,take));
          total+=take;
          if(total>=maxOutputBytes || take<bytes.byteLength){limited=true;await reader.cancel();break;}
        }
      })();
      const writing=(async()=>{await writer.write(u8);await writer.close();})();
      const [writeResult,readResult]=await Promise.allSettled([writing,reading]);
      if(readResult.status==="rejected" || (writeResult.status==="rejected"&&!limited)) return null;
      const out=new Uint8Array(total);let off=0;
      chunks.forEach(c=>{out.set(c,off);off+=c.byteLength;});
      return out.buffer;
    }catch(e){
      return null;
    }
  }

  function containsMetadataToken(text,token){
    const pat=token.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
    return new RegExp("(^|[^a-z0-9])"+pat+"(?=$|[^a-z0-9])","i").test(text);
  }

  async function aiScan(buf,type){
    const view=new DataView(buf), parts=[];
    const flags={c2paBox:false,compressedTextKeys:[],decompressedTextKeys:[],failedCompressedTextKeys:[]};
    const debug={chunks:[],rawSample:"",scanBytes:0};
    let scanned=0, textChars=0;
    function addText(s){
      if(!s || textChars>=MAX_SCAN_BYTES) return;
      const text=String(s).slice(0,MAX_SCAN_BYTES-textChars);
      if(!text) return;
      parts.push(text); textChars+=text.length;
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
      if(scanned>=MAX_SCAN_BYTES) return "";
      start=Math.max(0,start); end=Math.min(end,view.byteLength);
      const take=Math.min(end-start,MAX_SCAN_BYTES-scanned);
      if(take<=0) return "";
      const decoded=decodeBytes(new Uint8Array(buf,start,take));
      addText(decoded);
      scanned+=take;
      return decoded;
    }
    function takeCompressed(start,end){
      start=Math.max(0,start);end=Math.min(end,view.byteLength);
      const size=end-start;
      if(size<=0 || size>MAX_SCAN_BYTES-scanned) return null;
      scanned+=size;
      return new Uint8Array(buf,start,size);
    }
    function zero(start,end){ for(let i=start;i<end;i++) if(view.getUint8(i)===0) return i; return -1; }
    function latin1Range(start,end){
      let s="";
      for(let i=start;i<end;i++) s+=String.fromCharCode(view.getUint8(i));
      return s.trim();
    }
    async function readPngText(kind,ps,len){
      const end=Math.min(ps+len,view.byteLength);
      const keyEnd=Math.min(end,ps+80), keyZero=zero(ps,keyEnd);
      const key=keyZero>ps ? latin1Range(ps,keyZero) : "";
      const z=keyZero;
      const isCompressed=kind==="zTXt" || (kind==="iTXt" && z>ps && z+1<end && view.getUint8(z+1)===1);
      debug.chunks.push({type:kind,key:key||"(empty)",bytes:Math.max(0,end-ps),compressed:isCompressed});
      if(kind==="tEXt" && z>ps){ push(ps,end); return; }
      if(kind==="zTXt" && z>ps){
        const method=z+1<end ? view.getUint8(z+1) : -1;
        const compressed=takeCompressed(z+2,end);
        const inflated=compressed && method===0 ? await inflateZlibBytes(compressed,MAX_SCAN_BYTES-scanned) : null;
        if(inflated){
          scanned+=inflated.byteLength;
          flags.decompressedTextKeys.push(key||"zTXt");
          addText(key+" "+decodeBytes(new Uint8Array(inflated)));
        }else{
          if(/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) flags.compressedTextKeys.push(key);
          flags.failedCompressedTextKeys.push(key||"zTXt");
          addText(key+" zTXt compressed text metadata");
        }
        return;
      }
      if(kind==="iTXt" && z>ps && z+3<end){
        const compressed=view.getUint8(z+1)===1;
        let p=z+3; // compression flag + method
        const langEnd=zero(p,Math.min(end,p+256)); if(langEnd<0) return;
        p=langEnd+1;
        const translatedEnd=zero(p,Math.min(end,p+1024)); if(translatedEnd<0) return;
        p=translatedEnd+1;
        if(compressed){
          const method=view.getUint8(z+2);
          const packed=takeCompressed(p,end);
          const inflated=packed && method===0 ? await inflateZlibBytes(packed,MAX_SCAN_BYTES-scanned) : null;
          if(inflated){
            scanned+=inflated.byteLength;
            flags.decompressedTextKeys.push(key||"iTXt");
            addText(key+" "+decodeBytes(new Uint8Array(inflated)));
          }else{
            if(/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) flags.compressedTextKeys.push(key);
            flags.failedCompressedTextKeys.push(key||"iTXt");
            addText(key+" iTXt compressed text metadata");
          }
        }else push(ps,end);
      }
    }
    try{
      type=sniffImageType(buf,type);
      if(type==="image/jpeg"){
        let off=2, app11Text="";
        // SICUREZZA — Anti-DoS: tetto segmenti come in parseJPEG.
        let segCount=0;
        while(off<view.byteLength-1){
          if(view.getUint8(off)!==0xFF) break;
          while(off+1<view.byteLength && view.getUint8(off+1)===0xFF) off++;
          if(off+1>=view.byteLength) break;
          const marker=0xFF00|view.getUint8(off+1);
          if(marker===0xFFDA||marker===0xFFD9) break;
          if(marker>=0xFFD0&&marker<=0xFFD9){off+=2;continue;}
          // SICUREZZA — Bound-check: servono 4 byte per leggere la lunghezza.
          if(off+4>view.byteLength) break;
          const len=view.getUint16(off+2);
          if(len<2 || segCount++>MAX_JPEG_SEG) break;
          if(marker===0xFFE1||marker===0xFFED||marker===0xFFEB||marker===0xFFFE){
            const segmentText=push(off+4, off+2+len).toLowerCase();
            if(marker===0xFFEB){
              const payloadStart=off+4, payloadEnd=Math.min(off+2+len,view.byteLength);
              const hasJP=payloadEnd-payloadStart>=2 && view.getUint8(payloadStart)===0x4A && view.getUint8(payloadStart+1)===0x50;
              if(hasJP || /c2pa|jumbf|contentauth/.test(segmentText)) flags.c2paBox=true;
              // I JUMBF grandi sono divisi in APP11 consecutivi. Ricompone il
              // payload (saltando l'header JP/istanza/sequenza) senza newline,
              // così i token al confine fra segmenti non vanno persi.
              const dataStart=hasJP&&payloadEnd-payloadStart>=8 ? payloadStart+8 : payloadStart;
              const take=Math.min(payloadEnd-dataStart,MAX_SCAN_BYTES-app11Text.length);
              if(take>0) app11Text+=latin1Range(dataStart,dataStart+take);
            }
          }
          off+=2+len;
        }
        addText(app11Text);
      }else if(type==="image/png"){
        let off=8, chunkCount=0;
        while(off+12<=view.byteLength && chunkCount++<MAX_META_CHUNKS){
          const len=view.getUint32(off);
          let tt="";for(let i=0;i<4;i++)tt+=String.fromCharCode(view.getUint8(off+4+i));
          const ps=off+8;
          if(["tEXt","iTXt","zTXt"].includes(tt)) await readPngText(tt,ps,len);
          else if(["eXIf","caBX"].includes(tt)) push(ps, ps+len);
          if(tt==="caBX") flags.c2paBox=true; // chunk privato C2PA
          if(tt==="IEND") break;
          off+=12+len;
        }
      }else if(type==="image/webp"){
        const cc=o=>{let s="";for(let i=0;i<4;i++)s+=String.fromCharCode(view.getUint8(o+i));return s;};
        if(view.byteLength>=12 && cc(0)==="RIFF" && cc(8)==="WEBP"){
          const riffEnd=Math.min(view.byteLength,8+view.getUint32(4,true));
          let off=12, chunkCount=0;
          while(off+8<=riffEnd && chunkCount++<MAX_META_CHUNKS){
            const id=cc(off), size=view.getUint32(off+4,true), ps=off+8;
            if(ps+size>riffEnd) break;
            if(id==="EXIF"||id==="XMP "||id==="C2PA") push(ps, ps+size);
            if(id==="C2PA") flags.c2paBox=true;   // manifest C2PA in WebP
            off=ps+size+(size&1);
          }
        }
      }
    }catch(e){}
    const text=parts.join("\n");
    debug.scanBytes=scanned || Math.min(text.length,MAX_SCAN_BYTES);
    debug.rawSample=normalizeDebugText(text);
    debug.decompressed=[...new Set(flags.decompressedTextKeys)];
    debug.failedCompressed=[...new Set(flags.failedCompressedTextKeys)];
    return {text, lower:text.toLowerCase(), flags, debug};
  }

  async function analyzeAI(buf,type){
    const scan=await aiScan(buf,type), lower=scan.lower, signals=[];
    let strong=false, maybe=false;

    // 1) Manifest C2PA / Content Credentials (anche WebP). Distingue generata vs modificata.
    const hasC2PA = scan.flags.c2paBox || lower.includes("c2pa") || lower.includes("contentauth")
                 || lower.includes("content credential") || lower.includes("contentcredentials");
    if(hasC2PA){
      const c2paEdited=lower.includes("c2pa.edited") || lower.includes("c2pa.placed");
      const c2paCreated=lower.includes("c2pa.created");
      // Le azioni C2PA descrivono la provenienza, non provano da sole l'uso di AI.
      // Il verdetto diventa forte solo con DigitalSourceType/generatore/frase AI.
      maybe=true;
      signals.push({strong:false,ico:"🔏",kKey:"ai.c2pa.k",vKey:"ai.c2pa.v"});
      if(c2paEdited)
        signals.push({strong:false,ico:"✏️",kKey:"ai.action.k",vKey:"ai.action.edited"});
      else if(c2paCreated)
        signals.push({strong:false,ico:"✨",kKey:"ai.action.k",vKey:"ai.action.created"});
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
      ["azure openai","Azure OpenAI"],["chat gpt","ChatGPT (OpenAI)"],["chatgpt","ChatGPT (OpenAI)"],["openai","OpenAI"],
      ["dall·e","DALL·E"],["dall-e","DALL·E"],["dall e","DALL·E"],["dalle","DALL·E"],["gpt-image","GPT-image (OpenAI)"],["gpt image","GPT-image (OpenAI)"],["gpt-4o","GPT-4o (OpenAI)"],["gpt 4o","GPT-4o (OpenAI)"],["gpt4o","GPT-4o (OpenAI)"],["sora","Sora (OpenAI)"],
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
    for(const [tok,label] of gens){ if(containsMetadataToken(lower,tok)&&!foundGens.includes(label)) foundGens.push(label); }
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
    const phrases=[
      ["made with ai","Made with AI"],["ai generated","AI generated"],["generated by ai","Generated by AI"],
      ["created with ai","Created with AI"],["created by ai","Created by AI"],["ai generated image","AI generated image"],
      ["edited with ai","Edited with AI"],["edited by ai","Edited by AI"],["modified with ai","Modified with AI"],
      ["powered by ai","Powered by AI"],["created by openai","Created by OpenAI"],["generated by openai","Generated by OpenAI"],
      ["made with openai","Made with OpenAI"],["created with openai","Created with OpenAI"],
      ["created by chatgpt","Created by ChatGPT"],["generated by chatgpt","Generated by ChatGPT"],
      ["made with chatgpt","Made with ChatGPT"],["created with chatgpt","Created with ChatGPT"]
    ];
    const foundPhr=[];
    function hasPhrase(tok){
      const pat=tok.replace(/[.*+?^${}()|[\]\\]/g,"\\$&").replace(/\s+/g,"\\s+");
      return new RegExp("\\b"+pat+"\\b","i").test(lower);
    }
    for(const [tok,label] of phrases){ if(hasPhrase(tok)&&!foundPhr.includes(label)) foundPhr.push(label); }
    if(foundPhr.length){ strong=true; signals.push({strong:true,ico:"💬",kKey:"ai.phrase.k",vRaw:foundPhr.join(", ")}); }

    return { level: strong?"detected":(maybe?"maybe":"clear"), signals, debug:scan.debug };
  }

  const AI_ICON={detected:"🤖",maybe:"❓",clear:"✓"};
  function renderAI(ai,showDebug){
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
    if(showDebug) renderAIDebug(ai);
  }

  function renderAIDebug(ai){
    const dbg=ai&&ai.debug;
    if(!dbg) return;
    const details=document.createElement("details");
    details.className="why ai-debug";
    const summary=document.createElement("summary");
    summary.textContent=t("ai.debug.title");
    details.appendChild(summary);

    const body=document.createElement("div");
    body.className="ai-debug-body";
    const chunks=(dbg.chunks||[]).map(c=>c.type+(c.key ? ":"+c.key : "")).join(", ");
    const rows=[
      [t("ai.debug.bytes"), String(dbg.scanBytes||0)],
      [t("ai.debug.chunks"), chunks || "0"],
      [t("ai.debug.inflated"), (dbg.decompressed||[]).join(", ") || "0"],
      [t("ai.debug.failed"), (dbg.failedCompressed||[]).join(", ") || "0"]
    ];
    rows.forEach(([k,v])=>{
      const row=document.createElement("div");
      row.className="ai-debug-row";
      const key=document.createElement("span"); key.textContent=k;
      const val=document.createElement("b"); val.textContent=v;
      row.appendChild(key); row.appendChild(val);
      body.appendChild(row);
    });

    const label=document.createElement("div");
    label.className="ai-debug-label";
    label.textContent=t("ai.debug.raw");
    body.appendChild(label);
    const pre=document.createElement("pre");
    pre.textContent=dbg.rawSample || t("ai.debug.none");
    body.appendChild(pre);
    details.appendChild(body);
    mAIWrap.appendChild(details);
  }

  /* ====================== SCRITTURA EXIF ======================
     Gemello vanilla di `src/metadata/exif.ts`, che è la versione coperta da test
     (`npm test`). La duplicazione è voluta finché dura la migrazione React: la
     versione stabile resta un singolo file senza moduli. Ogni modifica qui va
     riportata là, e viceversa. */

  const MAX_EXIF_BYTES=65527;          // tetto fisico di un APP1 JPEG, meno "Exif\0\0"
  // Voci che l'utente può scegliere di conservare. Tutto il resto viene sempre
  // rimosso: ICC falserebbe i colori dopo la ricodifica e C2PA risulterebbe
  // comunque una firma non valida.
  const KEEPABLE_IDS=["gps","camera","datetime","software","artist","copyright"];

  /* TIFF dichiara ASCII a 7 bit, ma i lettori — incluso `parseTIFF` qui sopra,
     che fa `String.fromCharCode(byte)` — decodificano Latin-1. Accettarlo permette
     di scrivere «©» e i nomi accentati senza storpiarli, cosa che conta da quando
     i valori li digita l'utente. Fuori da Latin-1 (cirillico, CJK) non esiste un
     byte singolo: quei caratteri si scartano, non si traducono in altro. */
  function sanitizeAscii(value){
    if(value==null) return "";
    const src=String(value); let out="";
    for(let i=0;i<src.length && out.length<MAX_META_CHARS;i++){
      const c=src.charCodeAt(i);
      if((c>=0x20 && c<=0x7E) || (c>=0xA0 && c<=0xFF)) out+=src[i];
    }
    return out.trim();
  }

  /* «© 2026 Mario Rossi». L'anno viene dalla data di scatto quando il file la
     conserva — è l'anno in cui la foto è stata fatta, non quello in cui la si
     ripulisce — altrimenti dall'orologio di sistema. */
  function composeCopyright(name,capturedAt){
    const clean=sanitizeAscii(name);
    if(!clean) return "";
    const m=capturedAt ? /^(\d{4})/.exec(String(capturedAt)) : null;
    return "\u00a9 "+(m?m[1]:new Date().getFullYear())+" "+clean;
  }
  function exifAsciiEntry(tag,value){
    const clean=sanitizeAscii(value);
    if(!clean) return null;
    const data=new Uint8Array(clean.length+1);
    for(let i=0;i<clean.length;i++) data[i]=clean.charCodeAt(i);
    return {tag,type:2,count:data.length,data};
  }
  function exifShortEntry(tag,value){
    const data=new Uint8Array(2);
    new DataView(data.buffer).setUint16(0,value,true);
    return {tag,type:3,count:1,data};
  }
  function exifRationalEntry(tag,parts){
    const data=new Uint8Array(parts.length*8), dv=new DataView(data.buffer);
    parts.forEach((p,i)=>{ dv.setUint32(i*8,p[0],true); dv.setUint32(i*8+4,p[1],true); });
    return {tag,type:5,count:parts.length,data};
  }

  /* Gradi decimali → gradi/primi/secondi. I secondi sono in decimillesimi:
     precisione ~3 µm e denominatore mai 0, che manderebbe in NaN il lettore. */
  function degreesToDMS(value){
    const abs=Math.abs(value);
    let deg=Math.floor(abs);
    let min=Math.floor((abs-deg)*60);
    let sec=Math.round(((abs-deg)*60-min)*60*10000);
    if(sec>=600000){ sec-=600000; min+=1; }   // riporti da arrotondamento
    if(min>=60){ min-=60; deg+=1; }
    return [[deg,1],[min,1],[sec,10000]];
  }

  /* Serializza il sottoinsieme conservabile in un TIFF little-endian valido.
     Restituisce un array vuoto se non c'è nulla da scrivere. */
  function buildExifTIFF(values){
    const ifd0=[], exifIfd=[], gpsIfd=[];
    const push=(list,e)=>{ if(e) list.push(e); };

    push(ifd0,exifAsciiEntry(0x010F,values.make));
    push(ifd0,exifAsciiEntry(0x0110,values.model));
    // Orientation solo per il motore senza ricodifica: con la ricodifica canvas
    // la rotazione è già nei pixel e riscriverla ruoterebbe una seconda volta.
    if(Number.isInteger(values.orientation)&&values.orientation>=1&&values.orientation<=8)
      ifd0.push(exifShortEntry(0x0112,values.orientation));
    push(ifd0,exifAsciiEntry(0x0131,values.software));
    push(ifd0,exifAsciiEntry(0x0132,values.datetime));
    push(ifd0,exifAsciiEntry(0x013B,values.artist));
    push(ifd0,exifAsciiEntry(0x8298,values.copyright));

    const dateOriginal=exifAsciiEntry(0x9003,values.dateOriginal);
    if(dateOriginal){ exifIfd.push(dateOriginal); ifd0.push({tag:0x8769,type:4,count:1,data:new Uint8Array(4),pointerTo:"exif"}); }

    const g=values.gps;
    const gpsOk = g && Number.isFinite(g.lat) && Number.isFinite(g.lon) &&
                  g.lat>=-90 && g.lat<=90 && g.lon>=-180 && g.lon<=180;
    if(gpsOk){
      gpsIfd.push({tag:0x0000,type:1,count:4,data:Uint8Array.from([2,3,0,0])});
      push(gpsIfd,exifAsciiEntry(0x0001,g.lat<0?"S":"N"));
      gpsIfd.push(exifRationalEntry(0x0002,degreesToDMS(g.lat)));
      push(gpsIfd,exifAsciiEntry(0x0003,g.lon<0?"W":"E"));
      gpsIfd.push(exifRationalEntry(0x0004,degreesToDMS(g.lon)));
      ifd0.push({tag:0x8825,type:4,count:1,data:new Uint8Array(4),pointerTo:"gps"});
    }

    if(!ifd0.length) return new Uint8Array(0);

    const byTag=(a,b)=>a.tag-b.tag;             // lo standard richiede tag crescenti
    ifd0.sort(byTag); exifIfd.sort(byTag); gpsIfd.sort(byTag);

    const ifdSize=n=>2+n*12+4;
    const ifd0Offset=8;
    let cursor=ifd0Offset+ifdSize(ifd0.length);
    const exifOffset=exifIfd.length?cursor:0;
    if(exifIfd.length) cursor+=ifdSize(exifIfd.length);
    const gpsOffset=gpsIfd.length?cursor:0;
    if(gpsIfd.length) cursor+=ifdSize(gpsIfd.length);

    // Valori oltre i 4 byte della entry: area dati, ad offset pari.
    const dataOffsets=new Map();
    const all=ifd0.concat(exifIfd,gpsIfd);
    for(const e of all){
      if(e.data.length<=4) continue;
      if(cursor%2) cursor+=1;
      dataOffsets.set(e,cursor);
      cursor+=e.data.length;
    }
    if(cursor>MAX_EXIF_BYTES) throw new Error("EXIF ricostruito troppo grande");

    const out=new Uint8Array(cursor), dv=new DataView(out.buffer);
    out[0]=0x49; out[1]=0x49;                   // "II" — little-endian
    dv.setUint16(2,0x002A,true);
    dv.setUint32(4,ifd0Offset,true);

    function writeIfd(entries,at){
      dv.setUint16(at,entries.length,true);
      entries.forEach((e,i)=>{
        const off=at+2+i*12;
        dv.setUint16(off,e.tag,true);
        dv.setUint16(off+2,e.type,true);
        dv.setUint32(off+4,e.count,true);
        if(e.pointerTo){ dv.setUint32(off+8,e.pointerTo==="exif"?exifOffset:gpsOffset,true); return; }
        if(e.data.length<=4){ out.set(e.data,off+8); return; }
        const target=dataOffsets.get(e);
        dv.setUint32(off+8,target,true);
        out.set(e.data,target);
      });
      dv.setUint32(at+2+entries.length*12,0,true);
    }
    writeIfd(ifd0,ifd0Offset);
    if(exifIfd.length) writeIfd(exifIfd,exifOffset);
    if(gpsIfd.length) writeIfd(gpsIfd,gpsOffset);
    return out;
  }

  /* Filtra i valori letti dal file tenendo solo gli id selezionati dall'utente.
     `withOrientation` vale solo per il motore senza ricodifica. */
  function keptExifValues(exif,keep,withOrientation,inject){
    const out={};
    if(exif && keep && keep.size){
      if(keep.has("camera")){ out.make=exif.make; out.model=exif.model; }
      if(keep.has("datetime")){ out.datetime=exif.datetime; out.dateOriginal=exif.dateOriginal; }
      if(keep.has("software")) out.software=exif.software;
      if(keep.has("artist")) out.artist=exif.artist;
      if(keep.has("copyright")) out.copyright=exif.copyright;
      if(keep.has("gps")) out.gps=exif.gps;
    }
    if(withOrientation && exif && exif.orientation) out.orientation=exif.orientation;
    // Ciò che l'utente scrive vince su ciò che c'era nel file: se ha digitato un
    // nome o una posizione, è quella che vuole nel file finale.
    if(inject){
      if(inject.artist) out.artist=inject.artist;
      if(inject.copyright) out.copyright=inject.copyright;
      if(inject.gps) out.gps=inject.gps;
    }
    return Object.keys(out).length ? out : null;
  }

  /* Costruisce il TIFF da reinserire, o null se non c'è nulla da conservare.
     Un errore di serializzazione non deve mai impedire la pulizia: si perde la
     conservazione, non la rimozione. */
  function buildKeptExif(exif,keep,withOrientation,inject){
    try{
      const values=keptExifValues(exif,keep,withOrientation,inject);
      if(!values) return null;
      const tiff=buildExifTIFF(values);
      return tiff.length?tiff:null;
    }catch(e){ return null; }
  }

  // CRC32 tabellare: serve solo per *creare* il chunk PNG eXIf. Rimuovere un
  // chunk non richiede alcun ricalcolo, perché ognuno porta già il proprio CRC.
  let crcTable=null;
  function crc32(bytes){
    if(!crcTable){
      crcTable=new Uint32Array(256);
      for(let n=0;n<256;n++){
        let c=n;
        for(let k=0;k<8;k++) c = (c&1) ? (0xEDB88320 ^ (c>>>1)) : (c>>>1);
        crcTable[n]=c>>>0;
      }
    }
    let c=0xFFFFFFFF;
    for(let i=0;i<bytes.length;i++) c = crcTable[(c ^ bytes[i]) & 0xFF] ^ (c>>>8);
    return (c ^ 0xFFFFFFFF)>>>0;
  }

  function concatBytes(parts){
    let total=0; parts.forEach(p=>total+=p.length);
    const out=new Uint8Array(total); let at=0;
    parts.forEach(p=>{ out.set(p,at); at+=p.length; });
    return out;
  }

  /* ====================== PULIZIA ====================== */
  /* Rende la pulizia "idempotente": dopo la ricodifica su canvas il browser
     reinserisce comunque dei segmenti nel JPEG (profilo colore ICC, marcatori
     Adobe/Photoshop). Qui li rimuoviamo, tenendo solo l'essenziale (APP0/JFIF +
     tabelle + dati immagine), così il file salvato è davvero senza metadati e
     reimportandolo non risulta più alcun "metadato incorporato". */
  /* Con `exifBytes` inserisce un APP1 "Exif\0\0" ricostruito subito dopo SOI (o
     dopo APP0/JFIF, che è l'ordine convenzionale). Serve a entrambi i motori:
     sul buffer del canvas per la ricodifica, sul file originale per il taglio
     senza ricodifica. */
  function stripJpegMarkers(buf,exifBytes){
    const v=new DataView(buf), src=new Uint8Array(buf);
    if(v.getUint16(0)!==0xFFD8) return buf;            // non è JPEG: lascia com'è
    const parts=[src.subarray(0,2)];                   // SOI
    let app1=null;
    if(exifBytes && exifBytes.length && exifBytes.length+8<=65535){
      const seg=new Uint8Array(exifBytes.length+10);
      seg[0]=0xFF; seg[1]=0xE1;
      new DataView(seg.buffer).setUint16(2,exifBytes.length+8);  // len + "Exif\0\0"
      seg.set([0x45,0x78,0x69,0x66,0x00,0x00],4);
      seg.set(exifBytes,10);
      app1=seg;
    }
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
    if(app1){
      // Ordine convenzionale: SOI, APP0/JFIF se presente, poi APP1/Exif.
      const hasJfif = parts.length>1 && parts[1].length>1 && parts[1][0]===0xFF && parts[1][1]===0xE0;
      parts.splice(hasJfif?2:1,0,app1);
    }
    return concatBytes(parts).buffer;
  }

  /* Ricostruisce un PNG saltando i chunk di metadati e, se richiesto, inserendo
     un eXIf ricostruito prima di IEND. Vale per entrambi i motori: sull'output
     del canvas e sul file originale. Ritorna null se il buffer non è un PNG.
     Rimuovere un chunk non richiede di ricalcolare CRC: ognuno porta il proprio. */
  const PNG_DROP_CHUNKS=["eXIf","tEXt","iTXt","zTXt","tIME","iCCP","caBX"];
  function rebuildPng(buf,exifBytes){
    const view=new DataView(buf), src=new Uint8Array(buf);
    const sig=[137,80,78,71,13,10,26,10];
    if(src.length<8) return null;
    for(let i=0;i<8;i++) if(src[i]!==sig[i]) return null;
    const parts=[src.subarray(0,8)];
    let off=8, chunkCount=0, sawEnd=false;
    while(off+12<=view.byteLength && chunkCount++<MAX_META_CHUNKS){
      const len=view.getUint32(off);
      // SICUREZZA — una lunghezza dichiarata oltre il buffer indica dati corrotti.
      if(len>view.byteLength-off-12) break;
      let type=""; for(let i=0;i<4;i++) type+=String.fromCharCode(view.getUint8(off+4+i));
      const end=off+12+len;
      if(type==="IEND"){
        if(exifBytes && exifBytes.length) parts.push(pngChunk("eXIf",exifBytes));
        parts.push(src.subarray(off,end));
        sawEnd=true;
        break;                                  // scarta eventuali byte dopo IEND
      }
      if(PNG_DROP_CHUNKS.indexOf(type)<0) parts.push(src.subarray(off,end));
      off=end;
    }
    if(!sawEnd) return null;                    // PNG troncato: meglio non toccarlo
    return concatBytes(parts).buffer;
  }
  function pngChunk(type,data){
    const out=new Uint8Array(data.length+12), dv=new DataView(out.buffer);
    dv.setUint32(0,data.length);
    for(let i=0;i<4;i++) out[4+i]=type.charCodeAt(i);
    out.set(data,8);
    dv.setUint32(out.length-4,crc32(out.subarray(4,out.length-4)));
    return out;
  }

  /* Ricostruisce un WebP saltando i chunk di metadati e, se richiesto, aggiungendo
     un chunk EXIF. Il contenitore RIFF ammette EXIF solo con un header esteso
     VP8X: l'output del canvas ne è privo, quindi va sintetizzato usando le
     dimensioni note del canvas. Senza quelle dimensioni si rinuncia (null) invece
     di produrre un file rotto. */
  const WEBP_DROP_CHUNKS=["EXIF","XMP ","ICCP","C2PA"];
  function rebuildWebp(buf,exifBytes,canvasW,canvasH){
    const view=new DataView(buf), src=new Uint8Array(buf);
    const cc=o=>{let s="";for(let i=0;i<4;i++)s+=String.fromCharCode(view.getUint8(o+i));return s;};
    if(view.byteLength<12 || cc(0)!=="RIFF" || cc(8)!=="WEBP") return null;
    const riffEnd=Math.min(view.byteLength,8+view.getUint32(4,true));
    const kept=[];                              // {id, payload}
    let off=12, chunkCount=0;
    while(off+8<=riffEnd && chunkCount++<MAX_META_CHUNKS){
      const id=cc(off), size=view.getUint32(off+4,true), ps=off+8;
      if(size>riffEnd-ps) break;
      if(WEBP_DROP_CHUNKS.indexOf(id)<0) kept.push({id,payload:src.subarray(ps,ps+size)});
      off=ps+size+(size&1);                     // padding a byte pari
    }
    if(!kept.length) return null;

    const wantExif = !!(exifBytes && exifBytes.length);
    let vp8x=kept.find(c=>c.id==="VP8X");
    if(wantExif && !vp8x){
      if(!(canvasW>0 && canvasH>0 && canvasW<=1<<24 && canvasH<=1<<24)) return null;
      const payload=new Uint8Array(10);
      payload[4]=(canvasW-1)&0xFF; payload[5]=((canvasW-1)>>8)&0xFF; payload[6]=((canvasW-1)>>16)&0xFF;
      payload[7]=(canvasH-1)&0xFF; payload[8]=((canvasH-1)>>8)&0xFF; payload[9]=((canvasH-1)>>16)&0xFF;
      vp8x={id:"VP8X",payload};
      kept.unshift(vp8x);                       // VP8X deve essere il primo chunk
    }
    if(wantExif) kept.push({id:"EXIF",payload:exifBytes});

    // I flag VP8X devono descrivere esattamente i chunk rimasti.
    if(vp8x && vp8x.payload.length>=1){
      const has=id=>kept.some(c=>c.id===id);
      let flags=0;
      if(has("ANIM")) flags|=0x02;
      if(has("XMP ")) flags|=0x04;
      if(has("EXIF")) flags|=0x08;
      if(has("ALPH")) flags|=0x10;
      if(has("ICCP")) flags|=0x20;
      const copy=new Uint8Array(vp8x.payload); copy[0]=flags; vp8x.payload=copy;
      const at=kept.indexOf(vp8x); if(at>=0) kept[at]=vp8x;
    }

    const body=[];
    for(const c of kept){
      const head=new Uint8Array(8);
      for(let i=0;i<4;i++) head[i]=c.id.charCodeAt(i);
      new DataView(head.buffer).setUint32(4,c.payload.length,true);
      body.push(head,c.payload);
      if(c.payload.length&1) body.push(new Uint8Array(1));
    }
    let bodySize=0; body.forEach(p=>bodySize+=p.length);
    const header=new Uint8Array(12), hv=new DataView(header.buffer);
    header.set([0x52,0x49,0x46,0x46],0);        // "RIFF"
    hv.setUint32(4,bodySize+4,true);            // size = "WEBP" + chunk
    header.set([0x57,0x45,0x42,0x50],8);        // "WEBP"
    return concatBytes([header].concat(body)).buffer;
  }

  /* Motore senza ricodifica: riscrive il contenitore del file originale saltando
     i segmenti di metadati e copiando i dati immagine byte per byte. Qualità
     intatta, ma è un approccio a blacklist — sopravvive ciò che non riconosciamo.
     Ritorna null se il formato non è gestibile senza ricodifica. */
  function cleanLossless(buf,type,exifBytes){
    try{
      if(type==="image/jpeg") return stripJpegMarkers(buf,exifBytes);
      if(type==="image/png")  return rebuildPng(buf,exifBytes);
      if(type==="image/webp") return rebuildWebp(buf,exifBytes);
    }catch(e){}
    return null;
  }

  /* `opts` = {keep:Set<id>, engine:"reencode"|"lossless", exif, buf}.
     Senza `opts` (o con `keep` vuoto ed engine "reencode") il percorso è identico
     a quello storico: ricodifica e basta. */
  async function cleanImage(file,opts){
    const keep=(opts&&opts.keep)||null;
    const engine=(opts&&opts.engine)||"reencode";
    const exif=(opts&&opts.exif)||null;
    const inject=(opts&&opts.inject)||null;

    // Motore senza ricodifica: si lavora sui byte originali, i pixel non si toccano.
    if(engine==="lossless" && opts && opts.buf){
      const type=sniffImageType(opts.buf,file.type)||file.type;
      const exifBytes=buildKeptExif(exif,keep,true,inject);   // orientamento sempre riportato
      const out=cleanLossless(opts.buf,type,exifBytes);
      if(out){
        const blob=new Blob([out],{type});
        const dim=await imageSize(blob);
        return {blob,type,w:dim.w,h:dim.h,engine:"lossless",keptExif:!!((keep&&keep.size||inject)&&exifBytes)};
      }
      // Formato non tagliabile a mano (es. HEIC): si ricade sulla ricodifica.
    }

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
    // L'orientamento è già cotto nei pixel da `imageOrientation:"from-image"`:
    // riscrivere il tag farebbe ruotare l'immagine una seconda volta.
    const exifBytes=buildKeptExif(exif,keep,false,inject);
    let keptExif=!!exifBytes;
    // Per i JPEG, togli i segmenti APP/commenti reintrodotti dall'encoder del
    // browser, e reinserisci l'EXIF ricostruito se l'utente ha scelto di tenerne.
    if(outType==="image/jpeg" && blob){
      try{ blob=new Blob([stripJpegMarkers(await blob.arrayBuffer(),exifBytes)],{type:"image/jpeg"}); }catch(e){ keptExif=false; }
    }else if(blob && (outType==="image/png"||outType==="image/webp")){
      // Sempre, anche senza nulla da conservare: l'encoder del browser aggiunge
      // di suo dei chunk (Chromium mette un ICCP nel WebP) che vanno tolti,
      // esattamente come si fa per i marker APP dei JPEG.
      try{
        const src=await blob.arrayBuffer();
        const out = outType==="image/png"
          ? rebuildPng(src,exifBytes)
          : rebuildWebp(src,exifBytes,canvas.width,canvas.height);
        if(out) blob=new Blob([out],{type:outType});
        else keptExif=false;      // contenitore non riconosciuto: meglio pulito che rotto
      }catch(e){ keptExif=false; }
    }
    return {blob,type:outType,w:canvas.width,h:canvas.height,engine:"reencode",keptExif};
  }

  // Dimensioni di un blob già codificato, senza passare dal canvas.
  async function imageSize(blob){
    try{
      const bmp=await createImageBitmap(blob);
      const dim={w:bmp.width,h:bmp.height};
      bmp.close&&bmp.close();
      return dim;
    }catch(e){ return {w:0,h:0}; }
  }
  function renameClean(name,type){
    // SICUREZZA — Previene path traversal: prende solo l'ultimo componente del nome
    // (dopo l'ultimo / o \), rimuove .. e caratteri non sicuri.
    name=name.replace(/^.*[\\/]/,"").replace(/^[.]+/,"").replace(/[^a-z0-9_.() -]/gi,"_")||"image";
    return name.replace(/\.[^.]+$/,"")+"-pulita."+ext(type);
  }

  // Riepilogo sotto i pulsanti di scelta, ricalcolato (anche al cambio lingua).
  // Il pulsante di scelta compare solo se c'è davvero qualcosa da conservare.
  function syncChooseBtn(){
    // Visibile anche su un file senza metadati: da lì si scrivono autore e posizione.
    actChoose.hidden = !lastReport;
  }

  function setChoiceHint(){
    syncChooseBtn();
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
    if(!isAllowedFile(file)) return;   // solo immagini raster (no SVG)
    const generation=++analysisGeneration;
    ++batchGeneration; // un caricamento singolo invalida un eventuale batch in corso
    if(modal.classList.contains("open")) closeModal();
    batch.classList.remove("show"); batchURLs.forEach(u=>URL.revokeObjectURL(u));
    batchURLs=[]; batchItems=[]; batchList.innerHTML="";
    lastReport=null; lastAI=null; lastSizes=null; cleanedFile=null;
    keepSet=new Set(); cleanEngine="reencode"; currentBuf=null; lastClean=null;
    injectLat=""; injectLon="";   // il nome resta, la posizione è di questo scatto
    actChoose.hidden=true;
    choiceHint.textContent="";
    if(cleanedURL){URL.revokeObjectURL(cleanedURL);cleanedURL=null;}
    if(file.size>MAX_FILE_BYTES){
      currentFile=null;
      if(originalURL){URL.revokeObjectURL(originalURL);originalURL=null;}
      preview.removeAttribute("src");
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

    try{
      const buf=await file.arrayBuffer();
      if(generation!==analysisGeneration || currentFile!==file) return;
      const detectedType=sniffImageType(buf,file.type);
      if(!detectedType && !isAllowedType(file.type)) throw new Error("Formato non riconosciuto");
      const report=analyze(buf,detectedType||file.type);
      const ai=await analyzeAI(buf,detectedType||file.type);
      // Latest-wins: reset, paste o una nuova selezione non possono essere
      // sovrascritti dal completamento tardivo di questa analisi.
      if(generation!==analysisGeneration || currentFile!==file) return;
      lastReport=report; lastAI=ai;
      // Serve al motore senza ricodifica, che lavora sui byte originali.
      currentBuf=buf;
    }catch(e){
      if(generation!==analysisGeneration || currentFile!==file) return;
      frame.classList.remove("scanning"); chip.classList.remove("show");
      choice.style.visibility="visible";
      choiceHint.textContent=t("err.format");
      return;
    }

    if(generation!==analysisGeneration || currentFile!==file) return;
    frame.classList.remove("scanning"); chip.classList.remove("show");
    setChoiceHint();
    choice.style.visibility="visible";
  }

  /* ====================== CARICAMENTO MULTIPLO (BATCH) ====================== */
  // 1 file → flusso dettagliato (pulizia/analisi); 2+ file → pulizia in serie.
  function handleFiles(fileList){
    const candidates=[...fileList].filter(isAllowedFile);
    if(!candidates.length) return;
    if(candidates.length===1) return handleFile(candidates[0]);
    const list=candidates.filter(f=>f.size<=MAX_FILE_BYTES);
    if(!list.length) return;
    return list.length===1 ? handleFile(list[0]) : handleBatch(list);
  }

  async function handleBatch(list){
    const generation=++batchGeneration;
    ++analysisGeneration; // il batch invalida una scansione singola pendente
    currentFile=null; lastReport=null; lastAI=null; lastSizes=null; cleanedFile=null;
    currentBuf=null; keepSet=new Set(); cleanEngine="reencode"; lastClean=null;
    if(originalURL){URL.revokeObjectURL(originalURL);originalURL=null;}
    if(cleanedURL){URL.revokeObjectURL(cleanedURL);cleanedURL=null;}
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
    for(const it of batchItems){
      if(generation!==batchGeneration) return;
      await processBatchItem(it,generation);
    }
    if(generation!==batchGeneration) return;
    const ready=batchItems.filter(x=>x.url).length;
    batchDownloadAll.disabled = ready===0;
    batchDownloadAll.textContent=t("batch.downloadAll",{n:ready});
  }

  async function processBatchItem(it,generation){
    const {file,row}=it;
    const thumb=row.querySelector(".bthumb"), size=row.querySelector(".bsize"),
          act=row.querySelector(".bact"), name=row.querySelector(".bname");
    try{
      const buf=await file.arrayBuffer();
      if(generation!==batchGeneration) return;
      const ai=await analyzeAI(buf,file.type);
      if(generation!==batchGeneration) return;
      const cleaned=await cleanImage(file);
      if(generation!==batchGeneration) return;
      const cf=new File([cleaned.blob], renameClean(file.name,cleaned.type), {type:cleaned.type});
      const url=URL.createObjectURL(cleaned.blob); batchURLs.push(url);
      it.cleanedFile=cf; it.url=url;
      const img=document.createElement("img"); img.alt=""; img.src=url;
      thumb.innerHTML=""; thumb.appendChild(img);
      size.textContent=fmtBytes(file.size)+" → "+fmtBytes(cleaned.blob.size);
      if(ai.level!=="clear"){
        const b=document.createElement("span"); b.className="bbadge ai";
        b.textContent=t(ai.level==="detected"?"batch.aiBadge":"batch.aiMaybeBadge"); name.appendChild(b);
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
    ++batchGeneration;
    batch.classList.remove("show"); drop.classList.remove("hidden");
    fileInput.value="";
    currentBuf=null; keepSet=new Set(); cleanEngine="reencode"; lastClean=null;
    batchURLs.forEach(u=>URL.revokeObjectURL(u)); batchURLs=[]; batchItems=[];
    batchList.innerHTML="";
  }

  async function doClean(){
    if(!currentFile) return;
    const file=currentFile, generation=analysisGeneration;
    choice.style.visibility="hidden";
    chip.classList.add("show"); chiptx.textContent=t("chip.cleaning"); frame.classList.add("scanning");
    // Catturato una volta: serve alla pulizia e al riepilogo, e deve essere
    // lo stesso valore in entrambi.
    const injected=injectionValues();
    let cleaned;
    try{
      cleaned=await cleanImage(file,{
        keep:keepSet,
        engine:losslessAvailable()?cleanEngine:"reencode",
        exif:lastReport&&lastReport.exif,
        buf:currentBuf,
        inject:injected
      });
    }
    catch(e){
      if(generation!==analysisGeneration || currentFile!==file) return;
      frame.classList.remove("scanning"); chip.classList.remove("show");
      choice.style.visibility="visible";
      choiceHint.textContent=/pixel/.test(e&&e.message) ? t("err.pixels") : t("err.format");
      return;
    }
    if(generation!==analysisGeneration || currentFile!==file) return;
    frame.classList.remove("scanning"); chip.classList.remove("show");

    cleanedFile=new File([cleaned.blob], renameClean(file.name,cleaned.type), {type:cleaned.type});
    if(cleanedURL)URL.revokeObjectURL(cleanedURL);
    cleanedURL=URL.createObjectURL(cleaned.blob);
    preview.src=cleanedURL;
    lastSizes={orig:file.size, clean:cleaned.blob.size, w:cleaned.w, h:cleaned.h};
    lastClean={engine:cleaned.engine, keptExif:cleaned.keptExif, keep:new Set(keepSet), inject:injected};
    choice.style.visibility="visible";
    incCount();   // +1 immagine ripulita su questo dispositivo (solo locale)

    modalMode="clean";
    populateModal();
    openModal();
  }

  function showAnalysis(){
    if(!currentFile || !lastAI) return;
    modalMode="analyze";
    populateModal();
    openModal();
  }

  /* Schermata di scelta. È la stessa modale, ma senza il pannello sull'origine
     AI: quello è lungo e spingerebbe le caselle sotto la piega, che è esattamente
     il motivo per cui la selezione risultava introvabile. L'analisi AI resta
     raggiungibile dal suo pulsante. */
  function showChoose(){
    if(!currentFile || !lastReport) return;
    modalMode="choose";
    populateModal();
    openModal();
  }

  function populateModal(){
    const analyzeOnly = modalMode!=="clean";     // analisi o scelta: si sta ancora decidendo
    const chooseMode  = modalMode==="choose";
    mImg.src = analyzeOnly ? originalURL : cleanedURL;

    if(analyzeOnly){
      mTitle.textContent=t(chooseMode?"modal.chooseTitle":"modal.analyzeTitle");
      mSub.textContent=t(chooseMode?"modal.chooseSub":"modal.analyzeSub");
      mSizes.style.display="none";
      mMetaTitle.textContent=(lastReport&&lastReport.items||[]).some(x=>x.keepable)
        ? t("meta.chooseTitle") : t("meta.presentTitle");
    }else{
      mTitle.textContent=t("modal.cleanTitle");
      // Se qualcosa è stato conservato non si può dire che "non c'è più".
      if(lastClean && lastClean.keptExif) mSub.textContent=t("modal.cleanSubKept");
      else if(lastReport && lastReport.gps) mSub.textContent=t("modal.cleanSubGps");
      else if(lastReport && lastReport.items.length) mSub.textContent=t("modal.cleanSubItems");
      else mSub.textContent=t("modal.cleanSubNone");
      mSizes.style.display="";
      mSizes.innerHTML='<span>'+esc(t("size.original"))+' <b>'+esc(fmtBytes(lastSizes.orig))+'</b></span>'+
        '<span class="arrow">→</span>'+
        '<span>'+esc(t("size.cleaned"))+' <b>'+esc(fmtBytes(lastSizes.clean))+'</b> · '+lastSizes.w+'×'+lastSizes.h+'</span>';
      mMetaTitle.textContent=t("meta.removedTitle");
    }
    mAITitle.textContent=t("modal.analyzeTitle");
    mAITitle.hidden=chooseMode;
    mAIWrap.hidden=chooseMode;
    if(!chooseMode) renderAI(lastAI, analyzeOnly);

    mMeta.innerHTML="";
    if(lastReport && lastReport.items.length){
      lastReport.items.forEach(it=>{
        const el=document.createElement("div");
        el.className="m-row"+(it.warn?" warn":"");
        // esc(): il valore può contenere stringhe arbitrarie lette dall'EXIF → XSS.
        el.innerHTML='<div class="ic">'+esc(it.ico)+'</div><div class="tx">'+
          '<div class="k">'+esc(t(it.kKey))+'</div>'+
          '<div class="v"'+(analyzeOnly?' style="text-decoration:none"':'')+'>'+esc(itemValue(it))+'</div></div>';
        const kEl=el.querySelector(".k");

        if(analyzeOnly){
          if(it.keepable) el.appendChild(buildKeepToggle(it));
          else if(kEl){
            const s=document.createElement("span");
            s.className="pill"; s.textContent=t("meta.alwaysRemoved");
            kEl.appendChild(s);
          }
        }else if(kEl){
          // Dopo la pulizia ogni riga dichiara la propria sorte.
          const kept = lastClean && lastClean.keptExif && lastClean.keep.has(it.id);
          const s=document.createElement("span");
          s.className="pill"+(kept?" kept":"");
          s.textContent=t(kept?"meta.keptPill":"meta.removedPill");
          kEl.appendChild(s);
          if(kept) el.classList.add("kept");   // toglie la barratura sul valore
        }

        // Il link mappa è cliccabile da solo: la riga intera non lo è più, o il
        // clic si sovrapporrebbe alla casella di selezione.
        if(it.id==="gps" && lastReport.gps && kEl){
          el.classList.add("geo-row");
          const m=document.createElement("button");
          m.type="button"; m.className="maplink"; m.textContent="🗺 "+t("geo.viewMap");
          m.addEventListener("click",e=>{ e.stopPropagation(); openGeo(lastReport.gps.lat, lastReport.gps.lon); });
          kEl.appendChild(m);
        }
        mMeta.appendChild(el);
      });
    }else{
      const e=document.createElement("div"); e.className="m-empty";
      e.textContent=(lastReport&&lastReport.unknown) ? t("empty.unknown")
        : (analyzeOnly ? t("empty.analyzeNone") : t("empty.cleanNone"));
      mMeta.appendChild(e);
    }

    if(!analyzeOnly) renderAddedRows();
    renderAddForm(chooseMode);
    renderKeepControls(analyzeOnly);
    buildActions(analyzeOnly);
  }

  /* Dopo la pulizia mostra anche ciò che è stato SCRITTO nel file. Senza queste
     righe l'utente inietterebbe una posizione senza vederne conferma da nessuna
     parte, e il riepilogo racconterebbe solo metà dell'operazione. */
  function renderAddedRows(){
    const inject=lastClean&&lastClean.inject;
    if(!inject) return;
    const rows=[];
    if(inject.gps) rows.push({ico:"\ud83d\udccd",kKey:"meta.gps",v:inject.gps.lat.toFixed(5)+", "+inject.gps.lon.toFixed(5)});
    if(inject.artist) rows.push({ico:"\u270d\ufe0f",kKey:"meta.artist",v:inject.artist});
    if(inject.copyright) rows.push({ico:"\u00a9\ufe0f",kKey:"meta.copyright",v:inject.copyright});
    if(!rows.length) return;

    const head=document.createElement("div");
    head.className="m-section-title m-added-title";
    head.textContent=t("meta.addedTitle");
    mMeta.appendChild(head);

    rows.forEach(it=>{
      const el=document.createElement("div");
      el.className="m-row kept";
      // esc(): il nome lo digita l'utente, ma resta input non fidato per il DOM.
      el.innerHTML='<div class="ic">'+esc(it.ico)+'</div><div class="tx">'+
        '<div class="k">'+esc(t(it.kKey))+'<span class="pill added">'+esc(t("meta.addedPill"))+'</span></div>'+
        '<div class="v">'+esc(it.v)+'</div></div>';
      mMeta.appendChild(el);
    });
  }

  /* Casella per una voce conservabile. Spuntata = verrà rimossa: il default è
     "rimuovi tutto", esattamente come prima di questa funzione. */
  function buildKeepToggle(it){
    const wrap=document.createElement("label");
    wrap.className="m-keep-toggle";
    const box=document.createElement("input");
    box.type="checkbox";
    box.checked=!keepSet.has(it.id);
    box.setAttribute("aria-label",t("keep.remove")+" — "+t(it.kKey));
    const txt=document.createElement("span");
    const sync=()=>{ txt.textContent=t(box.checked?"keep.remove":"keep.keep"); };
    sync();
    box.addEventListener("change",()=>{
      if(box.checked) keepSet.delete(it.id); else keepSet.add(it.id);
      sync();
      renderKeepControls(true);
      buildActions(true);   // l'etichetta del pulsante dipende dalla selezione
    });
    wrap.appendChild(box); wrap.appendChild(txt);
    return wrap;
  }

  /* ====================== METADATI DA SCRIVERE ======================
     Non è l'opposto della pulizia: l'utente rimuove ciò che non vuole e scrive
     ciò che vuole. I valori passano dallo stesso `buildExifTIFF` usato per le
     voci conservate, quindi nel file esce sempre e solo ciò che noMeta serializza. */

  /* Accetta il punto e la virgola decimale: chi incolla da Google Maps in
     italiano si ritrova spesso la virgola. */
  function parseCoord(value){
    const t=String(value==null?"":value).trim().replace(",",".");
    if(!t || !/^[-+]?\d*\.?\d+$/.test(t)) return NaN;
    return parseFloat(t);
  }
  /* «41.9028, 12.4964» incollato in un solo campo: due numeri con il punto
     decimale separati da virgola non sono ambigui, quindi li dividiamo. */
  function splitPastedPair(text){
    const m=/^\s*([-+]?\d+\.\d+)\s*[,;\s]\s*([-+]?\d+\.\d+)\s*$/.exec(String(text||""));
    return m ? [m[1],m[2]] : null;
  }
  function injectedGps(){
    const lat=parseCoord(injectLat), lon=parseCoord(injectLon);
    if(!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
    if(lat<-90||lat>90||lon<-180||lon>180) return null;
    return {lat,lon};
  }
  /* Traduce il modulo in valori EXIF; null se non c'è nulla da scrivere, così
     senza compilare niente il percorso resta identico a prima. */
  function injectionValues(){
    const out={};
    const name=sanitizeAscii(injectName);
    if(name){
      const exif=lastReport&&lastReport.exif;
      out.artist=name;
      out.copyright=composeCopyright(name, exif&&(exif.dateOriginal||exif.datetime));
    }
    const gps=injectedGps();
    if(gps) out.gps=gps;
    return Object.keys(out).length?out:null;
  }

  let addPreview=null, addLat=null, addLon=null, addGeoMsg=null;

  /* Ricostruito solo all'apertura della modale e al cambio lingua: mai mentre si
     digita, o il campo perderebbe il focus a ogni tasto. */
  function renderAddForm(chooseMode){
    if(!chooseMode){ mAdd.hidden=true; mAdd.innerHTML=""; addPreview=addLat=addLon=addGeoMsg=null; return; }
    mAdd.hidden=false;
    mAdd.innerHTML="";

    const title=document.createElement("p");
    title.className="m-add-t"; title.textContent=t("add.title");
    const sub=document.createElement("p");
    sub.className="m-add-sub"; sub.textContent=t("add.sub");
    mAdd.appendChild(title); mAdd.appendChild(sub);

    const field=(labelKey,value,placeholder,onInput,extraClass)=>{
      const wrap=document.createElement("label");
      wrap.className="m-field"+(extraClass?" "+extraClass:"");
      const lab=document.createElement("span"); lab.textContent=t(labelKey);
      const inp=document.createElement("input");
      inp.type="text"; inp.value=value; inp.placeholder=placeholder;
      inp.autocomplete="off"; inp.spellcheck=false;
      inp.maxLength=MAX_META_CHARS;
      inp.addEventListener("input",()=>onInput(inp));
      wrap.appendChild(lab); wrap.appendChild(inp);
      return {wrap,inp};
    };

    const name=field("add.name",injectName,t("add.namePh"),inp=>{
      injectName=inp.value;
      writeStore(AUTHOR_KEY,injectName);   // solo il nome, non le coordinate
      syncAddPreview();
    });
    mAdd.appendChild(name.wrap);

    addPreview=document.createElement("p");
    addPreview.className="m-add-prev";
    mAdd.appendChild(addPreview);

    const coords=document.createElement("div");
    coords.className="m-coords";
    const lat=field("add.lat",injectLat,"41.9028",inp=>{
      const pair=splitPastedPair(inp.value);
      if(pair){ inp.value=pair[0]; injectLon=pair[1]; if(addLon) addLon.value=pair[1]; }
      injectLat=inp.value; syncAddPreview();
    });
    const lon=field("add.lon",injectLon,"12.4964",inp=>{ injectLon=inp.value; syncAddPreview(); });
    addLat=lat.inp; addLon=lon.inp;
    lat.inp.inputMode="decimal"; lon.inp.inputMode="decimal";
    coords.appendChild(lat.wrap); coords.appendChild(lon.wrap);
    mAdd.appendChild(coords);

    if(navigator.geolocation){
      const geo=document.createElement("button");
      geo.type="button"; geo.className="btn btn-ghost m-geo-btn";
      geo.textContent=t("add.useMyPos");
      geo.addEventListener("click",()=>useMyPosition(geo));
      mAdd.appendChild(geo);
      const note=document.createElement("p");
      note.className="m-add-note"; note.textContent=t("add.geoNote");
      mAdd.appendChild(note);
    }

    addGeoMsg=document.createElement("p");
    addGeoMsg.className="m-add-msg";
    mAdd.appendChild(addGeoMsg);

    syncAddPreview();
  }

  /* Mostra esattamente ciò che finirà nel file: niente sorprese al download. */
  function syncAddPreview(){
    if(!addPreview) return;
    const v=injectionValues();
    const parts=[];
    if(v&&v.copyright) parts.push(v.copyright);
    if(v&&v.gps) parts.push(v.gps.lat.toFixed(5)+", "+v.gps.lon.toFixed(5));
    addPreview.textContent = parts.length ? t("add.preview")+" "+parts.join("  ·  ") : "";
    addPreview.hidden = !parts.length;
    // Segnala coordinate incomplete o fuori range, invece di ignorarle in silenzio.
    if(addGeoMsg){
      const someCoord=String(injectLat).trim()||String(injectLon).trim();
      addGeoMsg.textContent = (someCoord && !injectedGps()) ? t("add.coordsInvalid") : "";
    }
    if(typeof buildActions==="function" && modalMode==="choose") buildActions(true);
  }

  /* `navigator.geolocation` non è una chiamata della pagina: la CSP non la blocca
     e su telefono usa il GPS locale. Su desktop però il browser può contattare un
     servizio di localizzazione, perciò accanto al pulsante c'è la nota. */
  function useMyPosition(btn){
    if(!navigator.geolocation || !addGeoMsg) return;
    btn.disabled=true;
    addGeoMsg.textContent=t("add.geoWait");
    navigator.geolocation.getCurrentPosition(pos=>{
      injectLat=pos.coords.latitude.toFixed(6);
      injectLon=pos.coords.longitude.toFixed(6);
      if(addLat) addLat.value=injectLat;
      if(addLon) addLon.value=injectLon;
      btn.disabled=false;
      addGeoMsg.textContent="";
      syncAddPreview();
    },err=>{
      btn.disabled=false;
      addGeoMsg.textContent = (err&&err.code===1) ? t("add.geoDenied") : t("add.geoFailed");
    },{enableHighAccuracy:true,timeout:15000,maximumAge:0});
  }

  // Il taglio senza ricodifica esiste solo per i contenitori che sappiamo
  // riscrivere: HEIC va per forza convertito, quindi ricodificato.
  function losslessAvailable(){
    if(!currentBuf) return false;
    const type=sniffImageType(currentBuf, currentFile&&currentFile.type);
    return type==="image/jpeg" || type==="image/png" || type==="image/webp";
  }

  /* Riepilogo della selezione e scelta del motore. Vengono mostrati solo in
     analisi e solo se c'è davvero qualcosa da scegliere. */
  function renderKeepControls(analyzeOnly){
    const keepable=(lastReport&&lastReport.items||[]).filter(x=>x.keepable);
    if(!analyzeOnly || !keepable.length){ mKeep.hidden=true; mKeep.innerHTML=""; return; }
    mKeep.hidden=false;
    mKeep.innerHTML="";

    const kept=keepable.filter(x=>keepSet.has(x.id)).length;
    const summary=document.createElement("p");
    summary.className="m-keep-sum";
    summary.textContent=kept
      ? t("keep.summary",{removed:keepable.length-kept, kept})
      : t("keep.summaryAll",{n:keepable.length});
    mKeep.appendChild(summary);

    if(!losslessAvailable()) return;
    const box=document.createElement("div");
    box.className="m-engine";
    const title=document.createElement("p");
    title.className="m-engine-t"; title.textContent=t("engine.title");
    box.appendChild(title);
    [["reencode","engine.reencode","engine.reencodeNote"],
     ["lossless","engine.lossless","engine.losslessNote"]].forEach(([id,labelKey,noteKey])=>{
      const label=document.createElement("label");
      label.className="m-engine-opt"+(cleanEngine===id?" on":"");
      const radio=document.createElement("input");
      radio.type="radio"; radio.name="nometa-engine"; radio.checked=cleanEngine===id;
      radio.addEventListener("change",()=>{ cleanEngine=id; renderKeepControls(true); });
      const tx=document.createElement("span");
      tx.innerHTML='<b>'+esc(t(labelKey))+'</b><em>'+esc(t(noteKey))+'</em>';
      label.appendChild(radio); label.appendChild(tx);
      box.appendChild(label);
    });
    mKeep.appendChild(box);
  }

  function buildActions(analyzeOnly){
    mActions.innerHTML="";
    if(analyzeOnly){
      iosHint.classList.remove("show");
      const c=document.createElement("button");
      c.className="btn btn-primary";
      const keptNow=(lastReport&&lastReport.items||[]).some(x=>x.keepable&&keepSet.has(x.id)) || !!injectionValues();
      c.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21l4-1 11-11-3-3L4 17l-1 4z"/><path d="M14 6l3 3"/></svg>'+esc(t(keptNow?"btn.applyClean":"btn.clean"));
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
    if(infoVersion) infoVersion.textContent="v"+APP_VERSION+" · beta";
    infoModal.classList.add("open");
    infoModal.setAttribute("aria-hidden","false");
    document.body.classList.add("lock");
  }
  function closeInfo(){
    infoModal.classList.remove("open");
    infoModal.setAttribute("aria-hidden","true");
    if(!modal.classList.contains("open") && !geoModal.classList.contains("open")) document.body.classList.remove("lock");
  }

  const RELEASE_SEEN_KEY="nm_release_seen";
  function openRelease(markSeen=true){
    if(infoModal.classList.contains("open")) closeInfo();
    releaseModal.classList.add("open");
    releaseModal.setAttribute("aria-hidden","false");
    document.body.classList.add("lock");
    if(markSeen) writeStore(RELEASE_SEEN_KEY,PUBLIC_RELEASE_VERSION);
  }
  function closeRelease(){
    writeStore(RELEASE_SEEN_KEY,PUBLIC_RELEASE_VERSION);
    releaseModal.classList.remove("open");
    releaseModal.setAttribute("aria-hidden","true");
    if(!modal.classList.contains("open") && !geoModal.classList.contains("open") && !infoModal.classList.contains("open"))
      document.body.classList.remove("lock");
  }

  function doReset(){
    ++analysisGeneration;
    ++batchGeneration;
    closeModal();
    stage.classList.remove("show"); drop.classList.remove("hidden");
    frame.classList.remove("scanning"); chip.classList.remove("show");
    choice.style.visibility="hidden"; choiceHint.textContent="";
    fileInput.value="";
    if(cleanedURL){URL.revokeObjectURL(cleanedURL);cleanedURL=null;}
    if(originalURL){URL.revokeObjectURL(originalURL);originalURL=null;}
    preview.removeAttribute("src");
    cleanedFile=null; currentFile=null; lastReport=null; lastSizes=null; lastAI=null;
    // currentBuf può pesare fino a MAX_FILE_BYTES: va rilasciato subito.
    keepSet=new Set(); cleanEngine="reencode"; currentBuf=null; lastClean=null;
    injectLat=""; injectLon="";   // il nome resta, la posizione è di questo scatto
    actChoose.hidden=true;
  }

  /* ====================== EVENTI ====================== */
  drop.addEventListener("click",()=>fileInput.click());
  fileInput.addEventListener("change",e=>{
    const files=[...(e.target.files||[])];
    // Consente di riselezionare subito anche lo stesso file/nome.
    e.target.value="";
    if(files.length) handleFiles(files);
  });
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
  // Il pulsante diretto resta il "rimuovi tutto": ignora ed azzera ogni scelta
  // fatta nella modale, così il comportamento predefinito non cambia mai.
  actClean.addEventListener("click",()=>{ keepSet=new Set(); cleanEngine="reencode"; doClean(); });
  actChoose.addEventListener("click",showChoose);
  actAnalyze.addEventListener("click",showAnalysis);
  headerInfoBtn.addEventListener("click",openInfo);
  aiInfoBtn.addEventListener("click",openInfo);
  mClose.addEventListener("click",closeModal);
  backdrop.addEventListener("click",closeModal);
  geoClose.addEventListener("click",closeGeo);
  geoBackdrop.addEventListener("click",closeGeo);
  infoClose.addEventListener("click",closeInfo);
  infoBackdrop.addEventListener("click",closeInfo);
  infoVersion.addEventListener("click",()=>openRelease(false));
  releaseClose.addEventListener("click",closeRelease);
  releaseBackdrop.addEventListener("click",closeRelease);
  releaseDone.addEventListener("click",closeRelease);
  document.addEventListener("keydown",e=>{
    if(e.key!=="Escape") return;
    if(releaseModal.classList.contains("open")) closeRelease();
    else if(infoModal.classList.contains("open")) closeInfo();
    else if(geoModal.classList.contains("open")) closeGeo();
    else if(modal.classList.contains("open")) closeModal();
  });
  langBtn.addEventListener("click",()=>setLang(LANG==="it"?"en":"it"));
  themeBtn.addEventListener("click",cycleTheme);

  ["dragenter","dragover"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add("over");}));
  ["dragleave","drop"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove("over");}));
  drop.addEventListener("drop",e=>{ if(e.dataTransfer.files.length) handleFiles(e.dataTransfer.files); });
  window.addEventListener("paste",e=>{ const f=e.clipboardData&&e.clipboardData.files&&e.clipboardData.files[0]; if(isAllowedFile(f)) handleFile(f); });

  /* ====================== AVVIO ====================== */
  applyTheme();
  applyStaticI18n();
  renderCount();
  if(readStore(RELEASE_SEEN_KEY)!==PUBLIC_RELEASE_VERSION) requestAnimationFrame(()=>openRelease(true));
})();
