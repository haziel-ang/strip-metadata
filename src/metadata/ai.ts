export type AILevel = "detected" | "maybe" | "clear";

export type AISignal = {
  kind: "generator" | "workflow" | "phrase" | "compressed";
  strong: boolean;
  label: string;
};

export type AIDebug = {
  chunks: Array<{ type: string; key: string; bytes: number; compressed: boolean }>;
  decompressed: string[];
  failedCompressed: string[];
  rawSample: string;
};

export type AIAnalysis = {
  level: AILevel;
  signals: AISignal[];
  debug: AIDebug;
};

const MAX_SCAN_BYTES = 2 * 1024 * 1024;
const MAX_DEBUG_CHARS = 1800;

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

async function inflateZlibBytes(u8: Uint8Array): Promise<ArrayBuffer | null> {
  if (!("DecompressionStream" in globalThis)) return null;
  try {
    const ds = new DecompressionStream("deflate");
    const writer = ds.writable.getWriter();
    await writer.write(u8 as BufferSource);
    await writer.close();
    return await new Response(ds.readable).arrayBuffer();
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

function textRange(buf: ArrayBuffer, start: number, end: number): string {
  return decodeBytes(new Uint8Array(buf, start, Math.max(0, end - start))).trim();
}

function latin1Range(buf: ArrayBuffer, start: number, end: number): string {
  let out = "";
  const u8 = new Uint8Array(buf, start, Math.max(0, end - start));
  for (const byte of u8) out += String.fromCharCode(byte);
  return out.trim();
}

async function scanPngText(buf: ArrayBuffer) {
  const view = new DataView(buf);
  const debug: AIDebug = { chunks: [], decompressed: [], failedCompressed: [], rawSample: "" };
  const parts: string[] = [];
  const compressedTextKeys: string[] = [];

  const addText = (value: string) => {
    if (value) parts.push(value.slice(0, MAX_SCAN_BYTES));
  };

  let off = 8;
  while (off + 12 <= view.byteLength) {
    const len = view.getUint32(off);
    let type = "";
    for (let i = 0; i < 4; i += 1) type += String.fromCharCode(view.getUint8(off + 4 + i));
    const ps = off + 8;
    const end = Math.min(ps + len, view.byteLength);

    if (type === "tEXt" || type === "zTXt" || type === "iTXt") {
      const z = zero(view, ps, end);
      const key = z > ps ? latin1Range(buf, ps, z) : "";
      debug.chunks.push({ type, key: key || "(empty)", bytes: Math.max(0, end - ps), compressed: type !== "tEXt" });

      if (type === "tEXt" && z > ps) {
        addText(`${key} ${textRange(buf, z + 1, end)}`);
      }

      if (type === "zTXt" && z > ps) {
        const method = z + 1 < end ? view.getUint8(z + 1) : -1;
        const inflated = method === 0 ? await inflateZlibBytes(new Uint8Array(buf, z + 2, Math.max(0, end - z - 2))) : null;
        if (inflated) {
          debug.decompressed.push(key || "zTXt");
          addText(`${key} ${decodeBytes(new Uint8Array(inflated))}`);
        } else {
          if (/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) compressedTextKeys.push(key);
          debug.failedCompressed.push(key || "zTXt");
          addText(`${key} zTXt compressed text metadata`);
        }
      }

      if (type === "iTXt" && z > ps && z + 3 < end) {
        const compressed = view.getUint8(z + 1) === 1;
        const method = view.getUint8(z + 2);
        let p = z + 3;
        const langEnd = zero(view, p, end);
        if (langEnd >= 0) {
          p = langEnd + 1;
          const translatedEnd = zero(view, p, end);
          if (translatedEnd >= 0) {
            p = translatedEnd + 1;
            if (compressed) {
              const inflated = method === 0 ? await inflateZlibBytes(new Uint8Array(buf, p, Math.max(0, end - p))) : null;
              if (inflated) {
                debug.decompressed.push(key || "iTXt");
                addText(`${key} ${decodeBytes(new Uint8Array(inflated))}`);
              } else {
                if (/prompt|parameters|workflow|comfy|stable|generation/i.test(key)) compressedTextKeys.push(key);
                debug.failedCompressed.push(key || "iTXt");
                addText(`${key} iTXt compressed text metadata`);
              }
            } else {
              addText(`${key} ${textRange(buf, p, end)}`);
            }
          }
        }
      }
    }

    if (type === "IEND") break;
    off += 12 + len;
  }

  const text = parts.join("\n");
  debug.rawSample = normalizeDebugText(text);
  debug.decompressed = [...new Set(debug.decompressed)];
  debug.failedCompressed = [...new Set(debug.failedCompressed)];
  return { text, lower: text.toLowerCase(), compressedTextKeys, debug };
}

function hasPhrase(lower: string, token: string): boolean {
  const pat = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
  return new RegExp(`\\b${pat}\\b`, "i").test(lower);
}

export async function analyzeAI(buf: ArrayBuffer, type: string): Promise<AIAnalysis> {
  const scan = type === "image/png" ? await scanPngText(buf) : { text: "", lower: "", compressedTextKeys: [], debug: { chunks: [], decompressed: [], failedCompressed: [], rawSample: "" } };
  const signals: AISignal[] = [];
  let strong = false;
  let maybe = false;

  const generators: Array<[string, string]> = [
    ["azure openai", "Azure OpenAI"],
    ["chat gpt", "ChatGPT (OpenAI)"],
    ["chatgpt", "ChatGPT (OpenAI)"],
    ["openai", "OpenAI"],
    ["dall-e", "DALL-E"],
    ["dall e", "DALL-E"],
    ["dalle", "DALL-E"],
    ["gpt-image", "GPT-image (OpenAI)"],
    ["gpt image", "GPT-image (OpenAI)"],
    ["gpt-4o", "GPT-4o (OpenAI)"],
    ["gpt 4o", "GPT-4o (OpenAI)"],
    ["gpt4o", "GPT-4o (OpenAI)"],
    ["sora", "Sora (OpenAI)"],
    ["stable diffusion", "Stable Diffusion"],
    ["comfyui", "ComfyUI"]
  ];
  const foundGenerators = [...new Set(generators.filter(([token]) => scan.lower.includes(token)).map(([, label]) => label))];
  if (foundGenerators.length) {
    strong = true;
    signals.push({ kind: "generator", strong: true, label: foundGenerators.join(", ") });
  }

  const workflowHits = ["prompt", "seed", "sampler", "model", "steps", "cfg", "workflow"].filter((hit) => scan.lower.includes(hit));
  if ((workflowHits.includes("prompt") && workflowHits.some((hit) => hit !== "prompt")) || workflowHits.includes("workflow")) {
    strong = true;
    signals.push({ kind: "workflow", strong: true, label: workflowHits.join(", ") });
  } else if (scan.compressedTextKeys.length) {
    maybe = true;
    signals.push({ kind: "compressed", strong: false, label: scan.compressedTextKeys.join(", ") });
  }

  const phrases: Array<[string, string]> = [
    ["made with ai", "Made with AI"],
    ["ai generated", "AI generated"],
    ["generated by ai", "Generated by AI"],
    ["created with ai", "Created with AI"],
    ["created by ai", "Created by AI"],
    ["edited with ai", "Edited with AI"],
    ["powered by ai", "Powered by AI"],
    ["created by openai", "Created by OpenAI"],
    ["generated by openai", "Generated by OpenAI"],
    ["created by chatgpt", "Created by ChatGPT"]
  ];
  const foundPhrases = [...new Set(phrases.filter(([token]) => hasPhrase(scan.lower, token)).map(([, label]) => label))];
  if (foundPhrases.length) {
    strong = true;
    signals.push({ kind: "phrase", strong: true, label: foundPhrases.join(", ") });
  }

  return { level: strong ? "detected" : maybe ? "maybe" : "clear", signals, debug: scan.debug };
}
