/*!
 * Pulisci — Rimozione metadati & analisi origine AI
 * @version 1.5.4
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
  const APP_VERSION="1.5.4";

  // Limiti difensivi (anti-DoS in locale).
  const MAX_FILE_BYTES=64*1024*1024;   // 64 MB: tetto sul file in ingresso
  const MAX_META_CHARS=512;            // lunghezza massima mostrata per un valore
  const MAX_SCAN_BYTES=2*1024*1024;    // byte di metadati analizzati per l'AI scan
  const MAX_PIXELS=80*1000*1000;       // ~80 MP: guardia contro "decompression bomb"

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
      "ui.sub":"Le foto parlano. Questo le fa tacere: niente GPS, niente dispositivo, niente tag nascosti. <b>Resta tutto con te.</b>",
      "ui.dropTitle":"Carica un'immagine",
      "ui.dropDesc":"Trascinala qui, oppure tocca per sceglierla",
      "ui.choiceQ":"Cosa vuoi fare con questa immagine?",
      "ui.reset":"↺ Carica un'altra immagine",
      "ui.footerLock":"Elaborazione locale",
      "ui.footerOffline":"Nessuna immagine viene caricata online. Puoi usarla anche offline.",
      "ui.footerHeic":"*I file HEIC vengono convertiti in JPG durante la pulizia.",
      "ui.footerAi":"L'analisi AI legge solo i metadati: non rileva i watermark invisibili nei pixel (es. SynthID). Non usare questo strumento per spacciare contenuti AI come reali o per rimuovere l'attribuzione altrui.",
      "ui.cleanedOne":"🧹 1 immagine ripulita su questo dispositivo",
      "ui.cleanedMany":"🧹 {n} immagini ripulite su questo dispositivo",
      "btn.clean":"Pulisci i metadati","btn.analyze":"Analizza immagine",
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
      "val.gpsWhere":"dove è stata scattata","val.embeddedTimestamp":"timestamp incorporato","val.blocks":"blocco/i",
      "extra.icc":"profilo colore","extra.iptc":"IPTC/Photoshop","extra.xmp":"XMP","extra.comment":"commenti",
      "verdict.detected.h":"Segnali di origine AI rilevati",
      "verdict.detected.p":"Nei metadati ci sono credenziali o etichette che indicano contenuto generato o modificato con AI.",
      "verdict.maybe.h":"Possibili indizi di AI",
      "verdict.maybe.p":"Trovati riferimenti a strumenti AI nei metadati. Indizio non conclusivo.",
      "verdict.clear.h":"Nessun segnale AI nei metadati",
      "verdict.clear.p":"Non risultano credenziali C2PA, etichette IPTC né nomi di generatori AI nei metadati del file.",
      "ai.pill.strong":"AI","ai.pill.weak":"indizio",
      "ai.c2pa.k":"Credenziali di provenienza C2PA",
      "ai.c2pa.v":"Manifest Content Credentials incorporato (dichiara origine/cronologia, usato per marcare contenuti AI)",
      "ai.iptc.k":"Etichetta IPTC di origine digitale",
      "ai.dst.composite":"Composito con elementi generati da AI (IPTC)",
      "ai.dst.trained":"Generata da AI addestrata — IPTC trainedAlgorithmicMedia",
      "ai.dst.compositeSynthetic":"Composito sintetico (IPTC)",
      "ai.dst.algorithmic":"Media algoritmica (IPTC)",
      "ai.iptcPresent.k":"Campo IPTC DigitalSourceType presente",
      "ai.iptcPresent.v":"presente, ma con valore non riconosciuto come AI",
      "ai.gen.k":"Software/generatore AI nei metadati",
      "ai.phrase.k":"Dichiarazione testuale nei metadati",
      "ai.noteTitle":"Perché non rileva SynthID?",
      "ai.note":"Questa analisi legge solo i <b>metadati</b> del file. I <b>watermark invisibili nei pixel</b> (es. Google <b>SynthID</b> di Gemini/Imagen) <b>non sono verificabili in questo browser</b>: serve il rilevatore ufficiale di Google. I metadati inoltre possono essere stati rimossi, quindi la loro assenza <b>non prova</b> che un'immagine non sia generata da AI.",
      "alt.preview":"anteprima","alt.result":"immagine pulita",
      "theme.system":"Sistema","theme.light":"Chiaro","theme.dark":"Scuro",
      "ui.credit":"© 2026 <b>profxeni</b> · Licenza <a href=\"https://creativecommons.org/licenses/by/4.0/\" target=\"_blank\" rel=\"noopener noreferrer\">CC BY 4.0</a>: puoi copiarla e modificarla citando l'autore.",
      "ui.whySafeTitle":"Perché è sicura?",
      "ui.whySafe":"Gira nel browser, ma non carica niente. La pagina si scarica <b>una volta</b>; da lì la foto è elaborata <b>solo sul tuo dispositivo</b>, in memoria. Una regola di sicurezza (<code>connect-src 'none'</code>) blocca ogni richiesta di rete, quindi l'immagine non può uscire nemmeno per errore. Prova del nove: attiva la <b>modalità aereo</b> e funziona lo stesso."
    },
    en:{
      "ui.badge":"100% in your browser",
      "ui.h1":"Clean your <em>shots</em>",
      "ui.sub":"Photos talk. This makes them stop: no GPS, no device, no hidden tags. <b>Everything stays with you.</b>",
      "ui.dropTitle":"Upload an image",
      "ui.dropDesc":"Drag it here, or tap to choose",
      "ui.choiceQ":"What do you want to do with this image?",
      "ui.reset":"↺ Load another image",
      "ui.footerLock":"Local processing",
      "ui.footerOffline":"No image is uploaded online. You can use it offline too.",
      "ui.footerHeic":"*HEIC files are converted to JPG during cleaning.",
      "ui.footerAi":"The AI analysis reads metadata only: it does not detect invisible pixel watermarks (e.g. SynthID). Do not use this tool to pass AI content off as real or to strip someone else's attribution.",
      "ui.cleanedOne":"🧹 1 image cleaned on this device",
      "ui.cleanedMany":"🧹 {n} images cleaned on this device",
      "btn.clean":"Clean metadata","btn.analyze":"Analyze image",
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
      "val.gpsWhere":"where it was taken","val.embeddedTimestamp":"embedded timestamp","val.blocks":"block(s)",
      "extra.icc":"color profile","extra.iptc":"IPTC/Photoshop","extra.xmp":"XMP","extra.comment":"comments",
      "verdict.detected.h":"AI-origin signals detected",
      "verdict.detected.p":"The metadata contains credentials or labels indicating AI-generated or AI-edited content.",
      "verdict.maybe.h":"Possible AI hints",
      "verdict.maybe.p":"References to AI tools were found in the metadata. Not conclusive.",
      "verdict.clear.h":"No AI signal in metadata",
      "verdict.clear.p":"No C2PA credentials, IPTC labels or AI generator names were found in the file's metadata.",
      "ai.pill.strong":"AI","ai.pill.weak":"hint",
      "ai.c2pa.k":"C2PA provenance credentials",
      "ai.c2pa.v":"Embedded Content Credentials manifest (declares origin/history, used to mark AI content)",
      "ai.iptc.k":"IPTC digital source type label",
      "ai.dst.composite":"Composite with AI-generated elements (IPTC)",
      "ai.dst.trained":"Generated by trained AI — IPTC trainedAlgorithmicMedia",
      "ai.dst.compositeSynthetic":"Synthetic composite (IPTC)",
      "ai.dst.algorithmic":"Algorithmic media (IPTC)",
      "ai.iptcPresent.k":"IPTC DigitalSourceType field present",
      "ai.iptcPresent.v":"present, but with a value not recognized as AI",
      "ai.gen.k":"AI software/generator in metadata",
      "ai.phrase.k":"Text declaration in metadata",
      "ai.noteTitle":"Why can't it detect SynthID?",
      "ai.note":"This analysis reads only the file's <b>metadata</b>. <b>Invisible pixel watermarks</b> (e.g. Google <b>SynthID</b> in Gemini/Imagen) <b>cannot be verified in this browser</b>: Google's official detector is required. Metadata may also have been stripped, so its absence <b>does not prove</b> an image is not AI-generated.",
      "alt.preview":"preview","alt.result":"clean image",
      "theme.system":"System","theme.light":"Light","theme.dark":"Dark",
      "ui.credit":"© 2026 <b>profxeni</b> · Licensed <a href=\"https://creativecommons.org/licenses/by/4.0/\" target=\"_blank\" rel=\"noopener noreferrer\">CC BY 4.0</a>: copy and remix it with attribution.",
      "ui.whySafeTitle":"Why is it safe?",
      "ui.whySafe":"It runs in your browser, but nothing is uploaded. The page is downloaded <b>once</b>; from then on your photo is processed <b>only on your device</b>, in memory. A security rule (<code>connect-src 'none'</code>) blocks every network request, so the image can't leave, even by mistake. Proof: turn on <b>airplane mode</b> and it still works."
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
        choice=$("choice"), actClean=$("actClean"), actAnalyze=$("actAnalyze"),
        choiceHint=$("choiceHint"), reset=$("reset"),
        modal=$("modal"), backdrop=$("backdrop"), mClose=$("mClose"),
        mImg=$("mImg"), mTitle=$("mTitle"), mSub=$("mSub"), mSizes=$("mSizes"),
        mAITitle=$("mAITitle"), mAIWrap=$("mAIWrap"),
        mMetaTitle=$("mMetaTitle"), mMeta=$("mMeta"),
        mActions=$("mActions"), iosHint=$("iosHint"),
        langBtn=$("langBtn"), themeBtn=$("themeBtn"), statCleaned=$("statCleaned");

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
      function readASCII(off,count){count=Math.min(count,MAX_META_CHARS);let s="";for(let i=0;i<count;i++){const c=view.getUint8(off+i);if(c===0)break;s+=String.fromCharCode(c);}return s.trim();}
      function readRational(off){return u32(off)/u32(off+4);}
      function readIFD(dirStart){
        const entries=u16(dirStart); const tags={};
        for(let i=0;i<entries;i++){
          const e=dirStart+2+i*12, tag=u16(e), type=u16(e+2), count=u32(e+4);
          const sz=(TYPE_SIZE[type]||1)*count; let valOff=e+8;
          if(sz>4) valOff=tiffStart+u32(e+8);
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
    let off=2; const seen={xmp:false,icc:false,iptc:false,comment:false};
    while(off<view.byteLength-1){
      if(view.getUint8(off)!==0xFF){off++;continue;}
      const marker=view.getUint16(off);
      if(marker===0xFFDA) break;
      if(marker>=0xFFD0 && marker<=0xFFD9){off+=2;continue;}
      const len=view.getUint16(off+2), segStart=off+4;
      if(marker===0xFFE1){
        let hdr="";for(let i=0;i<6&&segStart+i<view.byteLength;i++)hdr+=String.fromCharCode(view.getUint8(segStart+i));
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
      else if(marker>=0xFFE3&&marker<=0xFFEF){res.bytes+=len;seen.xmp=true;}
      else if(marker===0xFFFE){res.bytes+=len;seen.comment=true;}
      off+=2+len;
    }
    if(res.gps) res.items.unshift({warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5),suffixKey:"val.gpsWhere"});
    const extras=[];
    if(seen.icc)extras.push("extra.icc"); if(seen.iptc)extras.push("extra.iptc");
    if(seen.xmp)extras.push("extra.xmp"); if(seen.comment)extras.push("extra.comment");
    if(extras.length)res.items.push({ico:"🗂",kKey:"meta.others",parts:extras});
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
      if(type==="IEND")break;
      off+=12+len;
    }
    if(res.gps) res.items.unshift({warn:true,ico:"📍",kKey:"meta.gps",v:res.gps.lat.toFixed(5)+", "+res.gps.lon.toFixed(5)});
    if(txt.length)res.items.push({ico:"🗂",kKey:"meta.text",blocks:{n:txt.length,types:[...new Set(txt)].join(", ")}});
    return res;
  }

  function analyze(buf,type){
    try{
      if(type==="image/jpeg") return parseJPEG(buf);
      if(type==="image/png")  return parsePNG(buf);
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
    const view=new DataView(buf), bytes=[]; const flags={c2paBox:false};
    // Non accumuliamo più di MAX_SCAN_BYTES (anti-DoS).
    function push(start,end){ for(let i=start;i<end&&i<view.byteLength&&bytes.length<MAX_SCAN_BYTES;i++) bytes.push(view.getUint8(i)); }
    try{
      if(type==="image/jpeg"){
        let off=2;
        while(off<view.byteLength-1){
          if(view.getUint8(off)!==0xFF){off++;continue;}
          const marker=view.getUint16(off);
          if(marker===0xFFDA||marker===0xFFD9) break;
          if(marker>=0xFFD0&&marker<=0xFFD9){off+=2;continue;}
          const len=view.getUint16(off+2);
          if((marker>=0xFFE0&&marker<=0xFFEF)||marker===0xFFFE){
            push(off+4, off+2+len);
            if(marker===0xFFEB) flags.c2paBox=true; // APP11 → contenitore JUMBF/C2PA
          }
          off+=2+len;
        }
      }else if(type==="image/png"){
        let off=8;
        while(off<view.byteLength){
          const len=view.getUint32(off);
          let tt="";for(let i=0;i<4;i++)tt+=String.fromCharCode(view.getUint8(off+4+i));
          if(["tEXt","iTXt","zTXt","eXIf","iCCP","caBX"].includes(tt)) push(off+8, off+8+len);
          if(tt==="caBX") flags.c2paBox=true; // chunk privato C2PA
          if(tt==="IEND") break;
          off+=12+len;
        }
      }
    }catch(e){}
    let s="";
    try{ s=new TextDecoder("latin1").decode(Uint8Array.from(bytes)); }
    catch(e){ for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]); }
    return {text:s, lower:s.toLowerCase(), flags};
  }

  function analyzeAI(buf,type){
    const scan=aiScan(buf,type), lower=scan.lower, signals=[];
    let strong=false, maybe=false;

    if(scan.flags.c2paBox || lower.includes("c2pa") || lower.includes("contentauth") || lower.includes("content credential")){
      strong=true; signals.push({strong:true,ico:"🔏",kKey:"ai.c2pa.k",vKey:"ai.c2pa.v"});
    }

    const dst=[
      ["compositewithtrainedalgorithmicmedia","ai.dst.composite"],
      ["trainedalgorithmicmedia","ai.dst.trained"],
      ["compositesynthetic","ai.dst.compositeSynthetic"],
      ["algorithmicmedia","ai.dst.algorithmic"]
    ];
    let dstHit=null;
    for(const [tok,vk] of dst){ if(lower.includes(tok)){ dstHit=vk; break; } }
    if(dstHit){ strong=true; signals.push({strong:true,ico:"🏷️",kKey:"ai.iptc.k",vKey:dstHit}); }
    else if(lower.includes("digitalsourcetype")){ maybe=true; signals.push({ico:"🏷️",kKey:"ai.iptcPresent.k",vKey:"ai.iptcPresent.v"}); }

    const gens=[
      ["midjourney","Midjourney"],["stable diffusion","Stable Diffusion"],["stablediffusion","Stable Diffusion"],
      ["dall-e","DALL·E"],["dall·e","DALL·E"],["gpt-image","GPT-image (OpenAI)"],["sora","Sora (OpenAI)"],
      ["adobe firefly","Adobe Firefly"],["firefly","Adobe Firefly"],
      ["nano banana","Gemini 2.5 Flash Image (nano banana)"],["gemini","Google Gemini"],["imagen","Google Imagen"],
      ["leonardo.ai","Leonardo.Ai"],["ideogram","Ideogram"],["bing image creator","Bing Image Creator"],
      ["flux.1","FLUX"],["black forest labs","FLUX (Black Forest Labs)"],
      ["runwayml","Runway"],["recraft","Recraft"],["nightcafe","NightCafe"],["novelai","NovelAI"],["qwen image","Qwen Image"]
    ];
    const foundGens=[];
    for(const [tok,label] of gens){ if(lower.includes(tok)&&!foundGens.includes(label)) foundGens.push(label); }
    if(foundGens.length){ maybe=true; signals.push({ico:"🤖",kKey:"ai.gen.k",vRaw:foundGens.join(", ")}); }

    const phrases=[["made with ai","“Made with AI”"],["ai generated","“AI generated”"],["generated by ai","“Generated by AI”"],["created with ai","“Created with AI”"]];
    const foundPhr=[];
    for(const [tok,label] of phrases){ if(lower.includes(tok)) foundPhr.push(label); }
    if(foundPhr.length){ maybe=true; signals.push({ico:"💬",kKey:"ai.phrase.k",vRaw:foundPhr.join(", ")}); }

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
    while(off<v.byteLength){
      if(src[off]!==0xFF){ parts.push(src.subarray(off)); break; }
      const marker=v.getUint16(off);
      if(marker===0xFFDA){ parts.push(src.subarray(off)); break; }   // SOS: copia dati+EOI così come sono
      if(marker>=0xFFD0&&marker<=0xFFD9){ parts.push(src.subarray(off,off+2)); off+=2; continue; }
      if(off+4>v.byteLength){ parts.push(src.subarray(off)); break; }
      const len=v.getUint16(off+2), segEnd=off+2+len;
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
  function renameClean(name,type){ return name.replace(/\.[^.]+$/,"")+"-pulita."+ext(type); }

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
    const canShare = navigator.canShare && cleanedFile && navigator.canShare({files:[cleanedFile]});
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
  function closeModal(){ modal.classList.remove("open"); modal.setAttribute("aria-hidden","true"); document.body.classList.remove("lock"); }

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
  fileInput.addEventListener("change",e=>{ if(e.target.files[0]) handleFile(e.target.files[0]); });
  reset.addEventListener("click",doReset);
  actClean.addEventListener("click",doClean);
  actAnalyze.addEventListener("click",showAnalysis);
  mClose.addEventListener("click",closeModal);
  backdrop.addEventListener("click",closeModal);
  document.addEventListener("keydown",e=>{ if(e.key==="Escape"&&modal.classList.contains("open")) closeModal(); });
  langBtn.addEventListener("click",()=>setLang(LANG==="it"?"en":"it"));
  themeBtn.addEventListener("click",cycleTheme);

  ["dragenter","dragover"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add("over");}));
  ["dragleave","drop"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove("over");}));
  drop.addEventListener("drop",e=>{ const f=e.dataTransfer.files[0]; if(f) handleFile(f); });
  window.addEventListener("paste",e=>{ const f=e.clipboardData&&e.clipboardData.files&&e.clipboardData.files[0]; if(f&&isAllowedType(f.type)) handleFile(f); });

  /* ====================== AVVIO ====================== */
  applyTheme();
  applyStaticI18n();
  renderCount();
})();
