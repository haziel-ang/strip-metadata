export type AILevel = "detected" | "maybe" | "clear";

export type AISignal = {
  kind: "c2pa" | "digital-source" | "generator" | "workflow" | "phrase" | "compressed";
  strong: boolean;
  label: string;
};

export type AIDebug = {
  chunks: Array<{ type: string; key: string; bytes: number; compressed: boolean }>;
  decompressed: string[];
  failedCompressed: string[];
  rawSample: string;
  scanBytes: number;
  container: ImageContainer;
};

export type AIAnalysis = {
  level: AILevel;
  signals: AISignal[];
  debug: AIDebug;
};

export type ImageContainer = "jpeg" | "png" | "webp" | "unknown";

const MAX_SCAN_BYTES = 2 * 1024 * 1024;
const MAX_DEBUG_CHARS = 1800;
const MAX_JPEG_SEGMENTS = 4096;
const MAX_META_CHUNKS = 4096;

type ScanResult = {
  text: string;
  lower: string;
  compressedTextKeys: string[];
  c2paBox: boolean;
  debug: AIDebug;
};

function fourCC(view: DataView, offset: number): string {
  if (offset < 0 || offset + 4 > view.byteLength) return "";
  let value = "";
  for (let i = 0; i < 4; i += 1) value += String.fromCharCode(view.getUint8(offset + i));
  return value;
}

export function sniffImageContainer(buf: ArrayBuffer, _declaredType = ""): ImageContainer {
  const view = new DataView(buf);
  if (view.byteLength >= 8) {
    const png = [137, 80, 78, 71, 13, 10, 26, 10];
    if (png.every((byte, index) => view.getUint8(index) === byte)) return "png";
  }
  if (view.byteLength >= 3 && view.getUint8(0) === 0xff && view.getUint8(1) === 0xd8 && view.getUint8(2) === 0xff) {
    return "jpeg";
  }
  if (view.byteLength >= 12 && fourCC(view, 0) === "RIFF" && fourCC(view, 8) === "WEBP") return "webp";

  return "unknown";
}

function decodeBytes(u8: Uint8Array): string {
  const out: string[] = [];
  const add = (value: string) => {
    const readable = value.match(/[A-Za-z0-9:_./ -]/g)?.length ?? 0;
    if (readable >= 3) out.push(value.replace(/\u0000/g, " "));
  };
  try {
    add(new TextDecoder("latin1").decode(u8));
  } catch {}
  try {
    add(new TextDecoder("utf-8").decode(u8));
  } catch {}
  if (u8.length > 3) {
    try {
      add(new TextDecoder("utf-16le").decode(u8));
    } catch {}
    try {
      add(new TextDecoder("utf-16be").decode(u8));
    } catch {}
  }
  return out.join("\n");
}

function normalizeDebugText(value: string): string {
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_DEBUG_CHARS);
}

async function inflateZlibBytes(u8: Uint8Array, maxOutputBytes = MAX_SCAN_BYTES): Promise<ArrayBuffer | null> {
  if (!("DecompressionStream" in globalThis) || u8.byteLength > MAX_SCAN_BYTES || maxOutputBytes <= 0) return null;
  try {
    const ds = new DecompressionStream("deflate");
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    let limited = false;

    const readOutput = async () => {
      while (total < maxOutputBytes) {
        const { value, done } = await reader.read();
        if (done) break;
        const bytes = new Uint8Array(value);
        const take = Math.min(bytes.byteLength, maxOutputBytes - total);
        if (take) chunks.push(bytes.slice(0, take));
        total += take;
        if (total >= maxOutputBytes || take < bytes.byteLength) {
          limited = true;
          await reader.cancel();
          break;
        }
      }
    };

    const reading = readOutput();
    const writing = (async () => {
      await writer.write(u8 as BufferSource);
      await writer.close();
    })();
    const [writeResult, readResult] = await Promise.allSettled([writing, reading]);
    if (readResult.status === "rejected" || (writeResult.status === "rejected" && !limited)) return null;

    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out.buffer;
  } catch {
    return null;
  }
}

function zero(view: DataView, start: number, end: number): number {
  for (let i = start; i < end; i += 1) {
    if (view.getUint8(i) === 0) return i;
  }
  return -1;
}

function latin1Range(buf: ArrayBuffer, start: number, end: number): string {
  let out = "";
  const u8 = new Uint8Array(buf, start, Math.max(0, end - start));
  for (const byte of u8) out += String.fromCharCode(byte);
  return out.trim();
}

function createCollector(buf: ArrayBuffer, container: ImageContainer) {
  const parts: string[] = [];
  let scanned = 0;
  let textChars = 0;

  const addText = (value: string) => {
    if (!value || textChars >= MAX_SCAN_BYTES) return;
    const text = value.slice(0, MAX_SCAN_BYTES - textChars);
    if (!text) return;
    parts.push(text);
    textChars += text.length;
  };

  const addRange = (start: number, end: number) => {
    if (scanned >= MAX_SCAN_BYTES) return "";
    const safeStart = Math.max(0, Math.min(start, buf.byteLength));
    const safeEnd = Math.max(safeStart, Math.min(end, buf.byteLength));
    const take = Math.min(safeEnd - safeStart, MAX_SCAN_BYTES - scanned);
    if (take <= 0) return "";
    const text = decodeBytes(new Uint8Array(buf, safeStart, take));
    scanned += take;
    addText(text);
    return text;
  };

  const takeCompressed = (start: number, end: number) => {
    const safeStart = Math.max(0, Math.min(start, buf.byteLength));
    const safeEnd = Math.max(safeStart, Math.min(end, buf.byteLength));
    const size = safeEnd - safeStart;
    if (size <= 0 || size > MAX_SCAN_BYTES - scanned) return null;
    scanned += size;
    return new Uint8Array(buf, safeStart, size);
  };

  const addInflated = (value: string, byteLength: number) => {
    if (byteLength <= 0 || byteLength > MAX_SCAN_BYTES - scanned) return false;
    scanned += byteLength;
    addText(value);
    return true;
  };

  const finish = (
    debug: Omit<AIDebug, "rawSample" | "scanBytes" | "container">,
    compressedTextKeys: string[],
    c2paBox: boolean
  ): ScanResult => {
    const text = parts.join("\n");
    return {
      text,
      lower: text.normalize("NFKC").toLowerCase(),
      compressedTextKeys: [...new Set(compressedTextKeys)],
      c2paBox,
      debug: {
        ...debug,
        decompressed: [...new Set(debug.decompressed)],
        failedCompressed: [...new Set(debug.failedCompressed)],
        rawSample: normalizeDebugText(text),
        scanBytes: scanned,
        container
      }
    };
  };

  return { addText, addRange, takeCompressed, addInflated, finish, remaining: () => Math.max(0, MAX_SCAN_BYTES - scanned) };
}

async function scanPngMetadata(buf: ArrayBuffer): Promise<ScanResult> {
  const view = new DataView(buf);
  const debug = { chunks: [] as AIDebug["chunks"], decompressed: [] as string[], failedCompressed: [] as string[] };
  const compressedTextKeys: string[] = [];
  const collector = createCollector(buf, "png");
  let c2paBox = false;
  let off = 8;
  let chunkCount = 0;

  while (off + 12 <= view.byteLength && chunkCount < MAX_META_CHUNKS) {
    chunkCount += 1;
    const len = view.getUint32(off);
    const type = fourCC(view, off + 4);
    const ps = off + 8;
    const end = ps + len;
    if (end < ps || end + 4 > view.byteLength) break;

    if (type === "tEXt" || type === "zTXt" || type === "iTXt") {
      const keywordEnd = Math.min(end, ps + 80);
      const z = zero(view, ps, keywordEnd);
      const key = z > ps ? latin1Range(buf, ps, z) : "";
      debug.chunks.push({ type, key: key || "(empty)", bytes: len, compressed: type !== "tEXt" });

      if (type === "tEXt" && z > ps) collector.addRange(ps, end);

      if (type === "zTXt" && z > ps) {
        const method = z + 1 < end ? view.getUint8(z + 1) : -1;
        const packed = collector.takeCompressed(z + 2, end);
        const inflated = method === 0 && packed
          ? await inflateZlibBytes(packed, collector.remaining())
          : null;
        if (inflated) {
          debug.decompressed.push(key || "zTXt");
          collector.addInflated(`${key} ${decodeBytes(new Uint8Array(inflated))}`, inflated.byteLength);
        } else {
          if (/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) compressedTextKeys.push(key);
          debug.failedCompressed.push(key || "zTXt");
          collector.addText(`${key} zTXt compressed text metadata`);
        }
      }

      if (type === "iTXt" && z > ps && z + 3 < end) {
        const compressed = view.getUint8(z + 1) === 1;
        const method = view.getUint8(z + 2);
        let p = z + 3;
        const langEnd = zero(view, p, Math.min(end, p + 256));
        if (langEnd >= 0) {
          p = langEnd + 1;
          const translatedEnd = zero(view, p, Math.min(end, p + 1024));
          if (translatedEnd >= 0) {
            p = translatedEnd + 1;
            if (compressed) {
              const packed = collector.takeCompressed(p, end);
              const inflated = method === 0 && packed
                ? await inflateZlibBytes(packed, collector.remaining())
                : null;
              if (inflated) {
                debug.decompressed.push(key || "iTXt");
                collector.addInflated(`${key} ${decodeBytes(new Uint8Array(inflated))}`, inflated.byteLength);
              } else {
                if (/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) compressedTextKeys.push(key);
                debug.failedCompressed.push(key || "iTXt");
                collector.addText(`${key} iTXt compressed text metadata`);
              }
            } else {
              collector.addRange(ps, end);
            }
          }
        }
      }
    } else if (type === "eXIf" || type === "caBX") {
      debug.chunks.push({ type, key: type, bytes: len, compressed: false });
      collector.addRange(ps, end);
      if (type === "caBX") c2paBox = true;
    }

    if (type === "IEND") break;
    off = end + 4;
  }

  return collector.finish(debug, compressedTextKeys, c2paBox);
}

function scanJpegMetadata(buf: ArrayBuffer): ScanResult {
  const view = new DataView(buf);
  const debug = { chunks: [] as AIDebug["chunks"], decompressed: [] as string[], failedCompressed: [] as string[] };
  const collector = createCollector(buf, "jpeg");
  let c2paBox = false;
  let off = 2;
  let segments = 0;
  let app11Text = "";

  while (off + 1 < view.byteLength && segments < MAX_JPEG_SEGMENTS) {
    if (view.getUint8(off) !== 0xff) break;
    while (off + 1 < view.byteLength && view.getUint8(off + 1) === 0xff) off += 1;
    if (off + 1 >= view.byteLength) break;
    const marker = 0xff00 | view.getUint8(off + 1);
    if (marker === 0xffda || marker === 0xffd9) break;
    if (marker >= 0xffd0 && marker <= 0xffd9) {
      off += 2;
      continue;
    }
    if (off + 4 > view.byteLength) break;
    const len = view.getUint16(off + 2);
    const end = off + 2 + len;
    if (len < 2 || end > view.byteLength) break;
    segments += 1;

    if (marker === 0xffe1 || marker === 0xffed || marker === 0xffeb || marker === 0xfffe) {
      const type = marker === 0xffeb ? "APP11" : marker === 0xfffe ? "COM" : `APP${marker - 0xffe0}`;
      debug.chunks.push({ type, key: type, bytes: len - 2, compressed: false });
      const text = collector.addRange(off + 4, end).toLowerCase();
      if (marker === 0xffeb) {
        const payloadStart = off + 4;
        const hasJP = end - payloadStart >= 2 && view.getUint8(payloadStart) === 0x4a && view.getUint8(payloadStart + 1) === 0x50;
        if (hasJP || /c2pa|jumbf|contentauth/.test(text)) c2paBox = true;
        const dataStart = hasJP && end - payloadStart >= 8 ? payloadStart + 8 : payloadStart;
        const take = Math.min(end - dataStart, MAX_SCAN_BYTES - app11Text.length);
        if (take > 0) app11Text += latin1Range(buf, dataStart, dataStart + take);
      }
    }
    off = end;
  }

  collector.addText(app11Text);

  return collector.finish(debug, [], c2paBox);
}

function scanWebpMetadata(buf: ArrayBuffer): ScanResult {
  const view = new DataView(buf);
  const debug = { chunks: [] as AIDebug["chunks"], decompressed: [] as string[], failedCompressed: [] as string[] };
  const collector = createCollector(buf, "webp");
  let c2paBox = false;
  let off = 12;
  let chunkCount = 0;
  const riffEnd = view.byteLength >= 8 ? Math.min(view.byteLength, 8 + view.getUint32(4, true)) : view.byteLength;

  while (off + 8 <= riffEnd && chunkCount < MAX_META_CHUNKS) {
    chunkCount += 1;
    const type = fourCC(view, off);
    const len = view.getUint32(off + 4, true);
    const ps = off + 8;
    const end = ps + len;
    if (end < ps || end > riffEnd) break;
    if (type === "EXIF" || type === "XMP " || type === "C2PA") {
      debug.chunks.push({ type, key: type.trim(), bytes: len, compressed: false });
      collector.addRange(ps, end);
      if (type === "C2PA") c2paBox = true;
    }
    off = end + (len & 1);
  }

  return collector.finish(debug, [], c2paBox);
}

function emptyScan(container: ImageContainer): ScanResult {
  const debug: AIDebug = {
    chunks: [],
    decompressed: [],
    failedCompressed: [],
    rawSample: "",
    scanBytes: 0,
    container
  };
  return { text: "", lower: "", compressedTextKeys: [], c2paBox: false, debug };
}

async function scanMetadata(buf: ArrayBuffer, declaredType: string): Promise<ScanResult> {
  const container = sniffImageContainer(buf, declaredType);
  try {
    if (container === "png") return await scanPngMetadata(buf);
    if (container === "jpeg") return scanJpegMetadata(buf);
    if (container === "webp") return scanWebpMetadata(buf);
  } catch {}
  return emptyScan(container);
}

function hasPhrase(lower: string, token: string): boolean {
  const pat = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
  return new RegExp(`\\b${pat}\\b`, "i").test(lower);
}

function containsMetadataToken(lower: string, token: string): boolean {
  const pat = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9])${pat}(?=$|[^a-z0-9])`, "i").test(lower);
}

export async function analyzeAI(buf: ArrayBuffer, type: string): Promise<AIAnalysis> {
  const scan = await scanMetadata(buf, type);
  const signals: AISignal[] = [];
  let strong = false;
  let maybe = false;

  const hasC2PA = scan.c2paBox || /c2pa|contentauth|content credentials?/.test(scan.lower);
  if (hasC2PA) {
    const actions = ["c2pa.created", "c2pa.edited", "c2pa.placed"].filter((action) => scan.lower.includes(action));
    maybe = true;
    signals.push({ kind: "c2pa", strong: false, label: actions.join(", ") || "Content Credentials" });
  }

  const digitalSources: Array<[string, string]> = [
    ["compositewithtrainedalgorithmicmedia", "Composite with trained algorithmic media"],
    ["composite_with_trained_algorithmic_media", "Composite with trained algorithmic media"],
    ["trainedalgorithmicmedia", "Trained algorithmic media"],
    ["trained_algorithmic_media", "Trained algorithmic media"],
    ["compositesynthetic", "Composite synthetic"],
    ["algorithmicmedia", "Algorithmic media"]
  ];
  const digitalSource = digitalSources.find(([token]) => scan.lower.includes(token));
  if (digitalSource) {
    strong = true;
    signals.push({ kind: "digital-source", strong: true, label: digitalSource[1] });
  }

  const generators: Array<[string, string]> = [
    ["azure openai", "Azure OpenAI"], ["open ai", "OpenAI"], ["openai", "OpenAI"],
    ["chat-gpt", "ChatGPT (OpenAI)"], ["chat gpt", "ChatGPT (OpenAI)"], ["chatgpt", "ChatGPT (OpenAI)"],
    ["dall·e", "DALL·E"], ["dall-e", "DALL·E"], ["dall e", "DALL·E"], ["dalle", "DALL·E"],
    ["gpt-image", "GPT-image (OpenAI)"], ["gpt_image", "GPT-image (OpenAI)"], ["gpt image", "GPT-image (OpenAI)"],
    ["gpt-4o", "GPT-4o (OpenAI)"], ["gpt 4o", "GPT-4o (OpenAI)"], ["gpt4o", "GPT-4o (OpenAI)"],
    ["sora", "Sora (OpenAI)"], ["adobe firefly", "Adobe Firefly"], ["firefly", "Adobe Firefly"],
    ["midjourney", "Midjourney"], ["stable diffusion", "Stable Diffusion"], ["stablediffusion", "Stable Diffusion"],
    ["sdxl", "Stable Diffusion XL"], ["automatic1111", "Stable Diffusion (A1111)"], ["a1111", "Stable Diffusion (A1111)"],
    ["comfyui", "ComfyUI"], ["fooocus", "Fooocus"], ["invokeai", "InvokeAI"],
    ["google c2pa", "Google (C2PA)"], ["made with google ai", "Google AI"], ["gemini", "Google Gemini"],
    ["imagen", "Google Imagen"], ["leonardo.ai", "Leonardo.Ai"], ["ideogram", "Ideogram"],
    ["black forest labs", "FLUX (Black Forest Labs)"], ["stability.ai", "Stability AI"], ["recraft", "Recraft"]
  ];
  const foundGenerators = [...new Set(generators.filter(([token]) => containsMetadataToken(scan.lower, token)).map(([, label]) => label))];
  if (foundGenerators.length) {
    strong = true;
    signals.push({ kind: "generator", strong: true, label: foundGenerators.join(", ") });
  }

  const workflowTests: Array<[string, string[]]> = [
    ["prompt", ["prompt:", "negative prompt", "positive prompt", '"prompt"', "parameters"]],
    ["seed", ["seed:", " seed ", "seed=", '"seed"']],
    ["sampler", ["sampler:", "sampler_name", '"sampler"']],
    ["model", ["model hash", "model_hash", "model:", "model_name", '"checkpoint"', ".safetensors"]],
    ["steps", ["steps:", "num_inference_steps", '"steps"']],
    ["cfg", ["cfg scale", "cfg_scale", "guidance_scale"]],
    ["workflow", ['"class_type"', '"workflow"', "comfyui", "node graph"]]
  ];
  const workflowHits = workflowTests.filter(([, tests]) => tests.some((token) => scan.lower.includes(token))).map(([label]) => label);
  const hasPrompt = workflowHits.includes("prompt");
  const hasGenerationParams = workflowHits.some((hit) => hit !== "prompt");
  if ((hasPrompt && hasGenerationParams) || workflowHits.includes("workflow") || (workflowHits.includes("sampler") && workflowHits.includes("steps"))) {
    strong = true;
    signals.push({ kind: "workflow", strong: true, label: workflowHits.join(", ") });
  } else if (scan.compressedTextKeys.length) {
    maybe = true;
    signals.push({ kind: "compressed", strong: false, label: scan.compressedTextKeys.join(", ") });
  }

  const phrases: Array<[string, string]> = [
    ["made with ai", "Made with AI"], ["ai generated", "AI generated"], ["generated by ai", "Generated by AI"],
    ["created with ai", "Created with AI"], ["created by ai", "Created by AI"], ["edited with ai", "Edited with AI"],
    ["edited by ai", "Edited by AI"], ["powered by ai", "Powered by AI"], ["created by openai", "Created by OpenAI"],
    ["generated by openai", "Generated by OpenAI"], ["made with openai", "Made with OpenAI"],
    ["created by chatgpt", "Created by ChatGPT"], ["generated by chatgpt", "Generated by ChatGPT"]
  ];
  const foundPhrases = [...new Set(phrases.filter(([token]) => hasPhrase(scan.lower, token)).map(([, label]) => label))];
  if (foundPhrases.length) {
    strong = true;
    signals.push({ kind: "phrase", strong: true, label: foundPhrases.join(", ") });
  }

  return { level: strong ? "detected" : maybe ? "maybe" : "clear", signals, debug: scan.debug };
}
