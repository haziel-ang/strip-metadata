/**
 * Scrittore EXIF minimale — il pezzo che permette la rimozione selettiva.
 *
 * La pulizia di noMeta ricodifica i pixel su canvas: l'operazione distrugge ogni
 * metadato per costruzione, quindi non esiste un "non rimuovere questo". L'unico
 * modo per conservare una voce è **riscriverla da zero** dopo la ricodifica, ed è
 * quello che fa `buildExifTIFF`. Nel file esce solo ciò che questo modulo ha
 * serializzato: nessun byte originale non interpretato rientra nell'immagine.
 *
 * `readExifTIFF` è il lettore gemello, usato dai test come oracolo del round-trip
 * e allineato a `parseTIFF` in `app.js`.
 */

export type GpsCoords = { lat: number; lon: number };

export type KeepableExif = {
  make?: string;
  model?: string;
  datetime?: string;
  dateOriginal?: string;
  software?: string;
  artist?: string;
  copyright?: string;
  /**
   * Solo per il motore senza ricodifica. Con la ricodifica canvas la rotazione è
   * già cotta nei pixel (`imageOrientation:"from-image"`): riscrivere il tag
   * farebbe ruotare l'immagine una seconda volta.
   */
  orientation?: number;
  gps?: GpsCoords;
};

export type ParsedExif = KeepableExif;

/** Un segmento APP1 JPEG non può superare 65533 byte, meno "Exif\0\0". */
export const MAX_EXIF_BYTES = 65527;

/** Stesso tetto di `MAX_META_CHARS` in app.js. */
const MAX_META_CHARS = 512;

const TYPE_BYTE = 1;
const TYPE_ASCII = 2;
const TYPE_SHORT = 3;
const TYPE_LONG = 4;
const TYPE_RATIONAL = 5;

const TAG_MAKE = 0x010f;
const TAG_MODEL = 0x0110;
const TAG_ORIENTATION = 0x0112;
const TAG_SOFTWARE = 0x0131;
const TAG_DATETIME = 0x0132;
const TAG_ARTIST = 0x013b;
const TAG_COPYRIGHT = 0x8298;
const TAG_EXIF_IFD = 0x8769;
const TAG_GPS_IFD = 0x8825;
const TAG_DATE_ORIGINAL = 0x9003;

const TAG_GPS_VERSION = 0x0000;
const TAG_GPS_LAT_REF = 0x0001;
const TAG_GPS_LAT = 0x0002;
const TAG_GPS_LON_REF = 0x0003;
const TAG_GPS_LON = 0x0004;

type SubIfd = "exif" | "gps";

type Entry = {
  tag: number;
  type: number;
  count: number;
  data: Uint8Array;
  /** Le entry puntatore ricevono il valore solo dopo il calcolo del layout. */
  pointerTo?: SubIfd;
};

/**
 * TIFF dichiara ASCII a 7 bit, ma in pratica i lettori — incluso `parseTIFF` in
 * app.js, che fa `String.fromCharCode(byte)` — decodificano Latin-1. Accettare
 * Latin-1 permette di scrivere «©» e i nomi accentati senza storpiarli, cosa che
 * conta da quando i valori li digita l'utente e non arrivano solo dai file.
 * Fuori da Latin-1 (cirillico, CJK) non c'è un byte singolo: quei caratteri
 * vengono scartati, non tradotti in qualcosa di diverso.
 */
function sanitizeAscii(value: string | undefined): string {
  if (value == null) return "";
  const source = String(value);
  let out = "";
  for (let i = 0; i < source.length && out.length < MAX_META_CHARS; i += 1) {
    const code = source.charCodeAt(i);
    const printable = (code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff);
    if (printable) out += source[i];
  }
  return out.trim();
}

function asciiEntry(tag: number, value: string | undefined): Entry | null {
  const clean = sanitizeAscii(value);
  if (!clean) return null;
  const data = new Uint8Array(clean.length + 1);
  for (let i = 0; i < clean.length; i += 1) data[i] = clean.charCodeAt(i);
  return { tag, type: TYPE_ASCII, count: data.length, data };
}

function shortEntry(tag: number, value: number): Entry {
  const data = new Uint8Array(2);
  new DataView(data.buffer).setUint16(0, value, true);
  return { tag, type: TYPE_SHORT, count: 1, data };
}

function byteEntry(tag: number, values: number[]): Entry {
  return { tag, type: TYPE_BYTE, count: values.length, data: Uint8Array.from(values) };
}

function pointerEntry(tag: number, pointerTo: SubIfd): Entry {
  return { tag, type: TYPE_LONG, count: 1, data: new Uint8Array(4), pointerTo };
}

function rationalEntry(tag: number, parts: Array<[number, number]>): Entry {
  const data = new Uint8Array(parts.length * 8);
  const view = new DataView(data.buffer);
  parts.forEach(([numerator, denominator], index) => {
    view.setUint32(index * 8, numerator, true);
    view.setUint32(index * 8 + 4, denominator, true);
  });
  return { tag, type: TYPE_RATIONAL, count: parts.length, data };
}

/**
 * Gradi decimali → tre RATIONAL (gradi, primi, secondi).
 * I secondi vengono espressi in decimillesimi: la precisione è di ~3 µm e il
 * denominatore non è mai 0, cosa che manderebbe in NaN il lettore.
 */
export function degreesToDMS(value: number): Array<[number, number]> {
  const abs = Math.abs(value);
  let degrees = Math.floor(abs);
  let minutes = Math.floor((abs - degrees) * 60);
  let seconds = Math.round(((abs - degrees) * 60 - minutes) * 60 * 10000);
  // L'arrotondamento può produrre 60" o 60': si riporta sull'unità superiore.
  if (seconds >= 600000) {
    seconds -= 600000;
    minutes += 1;
  }
  if (minutes >= 60) {
    minutes -= 60;
    degrees += 1;
  }
  return [
    [degrees, 1],
    [minutes, 1],
    [seconds, 10000]
  ];
}

/**
 * Compone il copyright nella forma convenzionale «© 2026 Mario Rossi».
 * L'anno viene dalla data di scatto quando il file la conserva — è l'anno in cui
 * la foto è stata fatta, non quello in cui la si ripulisce — altrimenti
 * dall'orologio di sistema. Restituisce stringa vuota senza un nome.
 */
export function composeCopyright(name: string | undefined, capturedAt?: string, now: Date = new Date()): string {
  const clean = sanitizeAscii(name);
  if (!clean) return "";
  const match = capturedAt ? /^(\d{4})/.exec(String(capturedAt)) : null;
  const year = match ? match[1] : String(now.getFullYear());
  return `\u00a9 ${year} ${clean}`;
}

function normalizeGps(gps: GpsCoords | undefined): GpsCoords | null {
  if (!gps) return null;
  const { lat, lon } = gps;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null;
  return { lat, lon };
}

function isValidOrientation(value: number | undefined): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 8;
}

/**
 * Serializza il sottoinsieme conservabile in un TIFF little-endian valido.
 * Restituisce un array vuoto quando non c'è nulla da scrivere: il chiamante in
 * quel caso non deve inserire alcun segmento.
 */
export function buildExifTIFF(values: KeepableExif): Uint8Array {
  const ifd0: Entry[] = [];
  const exifIfd: Entry[] = [];
  const gpsIfd: Entry[] = [];

  const push = (list: Entry[], entry: Entry | null): void => {
    if (entry) list.push(entry);
  };

  push(ifd0, asciiEntry(TAG_MAKE, values.make));
  push(ifd0, asciiEntry(TAG_MODEL, values.model));
  if (isValidOrientation(values.orientation)) ifd0.push(shortEntry(TAG_ORIENTATION, values.orientation));
  push(ifd0, asciiEntry(TAG_SOFTWARE, values.software));
  push(ifd0, asciiEntry(TAG_DATETIME, values.datetime));
  push(ifd0, asciiEntry(TAG_ARTIST, values.artist));
  push(ifd0, asciiEntry(TAG_COPYRIGHT, values.copyright));

  const dateOriginal = asciiEntry(TAG_DATE_ORIGINAL, values.dateOriginal);
  if (dateOriginal) {
    exifIfd.push(dateOriginal);
    ifd0.push(pointerEntry(TAG_EXIF_IFD, "exif"));
  }

  const gps = normalizeGps(values.gps);
  if (gps) {
    gpsIfd.push(byteEntry(TAG_GPS_VERSION, [2, 3, 0, 0]));
    push(gpsIfd, asciiEntry(TAG_GPS_LAT_REF, gps.lat < 0 ? "S" : "N"));
    gpsIfd.push(rationalEntry(TAG_GPS_LAT, degreesToDMS(gps.lat)));
    push(gpsIfd, asciiEntry(TAG_GPS_LON_REF, gps.lon < 0 ? "W" : "E"));
    gpsIfd.push(rationalEntry(TAG_GPS_LON, degreesToDMS(gps.lon)));
    ifd0.push(pointerEntry(TAG_GPS_IFD, "gps"));
  }

  if (!ifd0.length) return new Uint8Array(0);

  // Lo standard TIFF richiede le entry ordinate per tag crescente.
  const byTag = (a: Entry, b: Entry): number => a.tag - b.tag;
  ifd0.sort(byTag);
  exifIfd.sort(byTag);
  gpsIfd.sort(byTag);

  const ifdSize = (count: number): number => 2 + count * 12 + 4;
  const ifd0Offset = 8;
  let cursor = ifd0Offset + ifdSize(ifd0.length);
  const exifOffset = exifIfd.length ? cursor : 0;
  if (exifIfd.length) cursor += ifdSize(exifIfd.length);
  const gpsOffset = gpsIfd.length ? cursor : 0;
  if (gpsIfd.length) cursor += ifdSize(gpsIfd.length);

  // I valori che non stanno nei 4 byte della entry vanno nell'area dati, ad
  // offset pari come richiede lo standard.
  const dataOffsets = new Map<Entry, number>();
  const all = [...ifd0, ...exifIfd, ...gpsIfd];
  for (const entry of all) {
    if (entry.data.length <= 4) continue;
    if (cursor % 2) cursor += 1;
    dataOffsets.set(entry, cursor);
    cursor += entry.data.length;
  }

  if (cursor > MAX_EXIF_BYTES) throw new Error("EXIF ricostruito troppo grande");

  const out = new Uint8Array(cursor);
  const view = new DataView(out.buffer);
  out[0] = 0x49; // "II" — little-endian
  out[1] = 0x49;
  view.setUint16(2, 0x002a, true);
  view.setUint32(4, ifd0Offset, true);

  const writeIfd = (entries: Entry[], at: number): void => {
    view.setUint16(at, entries.length, true);
    entries.forEach((entry, index) => {
      const off = at + 2 + index * 12;
      view.setUint16(off, entry.tag, true);
      view.setUint16(off + 2, entry.type, true);
      view.setUint32(off + 4, entry.count, true);
      if (entry.pointerTo) {
        view.setUint32(off + 8, entry.pointerTo === "exif" ? exifOffset : gpsOffset, true);
        return;
      }
      if (entry.data.length <= 4) {
        out.set(entry.data, off + 8);
        return;
      }
      const target = dataOffsets.get(entry) as number;
      view.setUint32(off + 8, target, true);
      out.set(entry.data, target);
    });
    view.setUint32(at + 2 + entries.length * 12, 0, true);
  };

  writeIfd(ifd0, ifd0Offset);
  if (exifIfd.length) writeIfd(exifIfd, exifOffset);
  if (gpsIfd.length) writeIfd(gpsIfd, gpsOffset);

  return out;
}

/**
 * Lettore gemello di `parseTIFF` (app.js), con gli stessi bound-check: serve ai
 * test come oracolo dello scrittore. Ogni errore di struttura produce un oggetto
 * vuoto, mai un'eccezione.
 */
export function readExifTIFF(bytes: Uint8Array, tiffStart = 0): ParsedExif {
  const out: ParsedExif = {};
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (tiffStart < 0 || tiffStart + 8 > view.byteLength) return out;
    const little = view.getUint16(tiffStart) === 0x4949;
    const u16 = (offset: number): number => view.getUint16(offset, little);
    const u32 = (offset: number): number => view.getUint32(offset, little);
    if (view.getUint16(tiffStart + 2, little) !== 0x002a) return out;

    const typeSize: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

    const readAscii = (offset: number, count: number): string => {
      if (offset < 0 || offset >= view.byteLength) return "";
      const limit = Math.min(count, MAX_META_CHARS, view.byteLength - offset);
      let value = "";
      for (let i = 0; i < limit; i += 1) {
        const code = view.getUint8(offset + i);
        if (code === 0) break;
        value += String.fromCharCode(code);
      }
      return value.trim();
    };

    const readRational = (offset: number): number => {
      const denominator = u32(offset + 4);
      return denominator === 0 ? 0 : u32(offset) / denominator;
    };

    type Tag = { type: number; count: number; valOff: number };

    const readIfd = (dirStart: number): Record<number, Tag> => {
      const tags: Record<number, Tag> = {};
      if (dirStart < 0 || dirStart + 2 > view.byteLength) return tags;
      const entries = u16(dirStart);
      if (entries > 512) return tags;
      for (let i = 0; i < entries; i += 1) {
        const entry = dirStart + 2 + i * 12;
        if (entry + 12 > view.byteLength) break;
        const tag = u16(entry);
        const type = u16(entry + 2);
        const count = u32(entry + 4);
        const size = (typeSize[type] || 1) * count;
        let valOff = entry + 8;
        if (size > 4) {
          valOff = tiffStart + u32(entry + 8);
          if (valOff < 0 || valOff + size > view.byteLength) continue;
        }
        tags[tag] = { type, count, valOff };
      }
      return tags;
    };

    const ifd0 = readIfd(tiffStart + u32(tiffStart + 4));
    const readTagAscii = (tag: number): string | undefined => {
      const found = ifd0[tag];
      return found ? readAscii(found.valOff, found.count) || undefined : undefined;
    };

    out.make = readTagAscii(TAG_MAKE);
    out.model = readTagAscii(TAG_MODEL);
    out.datetime = readTagAscii(TAG_DATETIME);
    out.software = readTagAscii(TAG_SOFTWARE);
    out.artist = readTagAscii(TAG_ARTIST);
    out.copyright = readTagAscii(TAG_COPYRIGHT);

    const orientation = ifd0[TAG_ORIENTATION];
    if (orientation && orientation.type === TYPE_SHORT) {
      const value = u16(orientation.valOff);
      if (value >= 1 && value <= 8) out.orientation = value;
    }

    const exifPointer = ifd0[TAG_EXIF_IFD];
    if (exifPointer) {
      const exif = readIfd(tiffStart + u32(exifPointer.valOff));
      const dateOriginal = exif[TAG_DATE_ORIGINAL];
      if (dateOriginal) out.dateOriginal = readAscii(dateOriginal.valOff, dateOriginal.count) || undefined;
    }

    const gpsPointer = ifd0[TAG_GPS_IFD];
    if (gpsPointer) {
      const gps = readIfd(tiffStart + u32(gpsPointer.valOff));
      const toDegrees = (tag: number): number => {
        const found = gps[tag];
        if (!found) return NaN;
        const offset = found.valOff;
        return readRational(offset) + readRational(offset + 8) / 60 + readRational(offset + 16) / 3600;
      };
      if (gps[TAG_GPS_LAT] && gps[TAG_GPS_LON]) {
        let lat = toDegrees(TAG_GPS_LAT);
        let lon = toDegrees(TAG_GPS_LON);
        const latRef = gps[TAG_GPS_LAT_REF] ? readAscii(gps[TAG_GPS_LAT_REF].valOff, gps[TAG_GPS_LAT_REF].count) : "N";
        const lonRef = gps[TAG_GPS_LON_REF] ? readAscii(gps[TAG_GPS_LON_REF].valOff, gps[TAG_GPS_LON_REF].count) : "E";
        if (latRef === "S") lat = -lat;
        if (lonRef === "W") lon = -lon;
        if (Number.isFinite(lat) && Number.isFinite(lon)) out.gps = { lat, lon };
      }
    }
  } catch {
    return out;
  }
  return out;
}
