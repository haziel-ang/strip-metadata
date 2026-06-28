import { deflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { analyzeAI } from "./ai";

function chunk(type: string, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + payload.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, payload.length);
  for (let i = 0; i < 4; i += 1) out[4 + i] = type.charCodeAt(i);
  out.set(payload, 8);
  return out;
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function concat(parts: Uint8Array[]): ArrayBuffer {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out.buffer;
}

function pngWith(chunks: Uint8Array[]): ArrayBuffer {
  return concat([
    new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]),
    ...chunks,
    chunk("IEND", new Uint8Array())
  ]);
}

function textChunk(key: string, value: string): Uint8Array {
  const keyBytes = bytes(key);
  const valueBytes = bytes(value);
  const payload = new Uint8Array(keyBytes.length + 1 + valueBytes.length);
  payload.set(keyBytes);
  payload[keyBytes.length] = 0;
  payload.set(valueBytes, keyBytes.length + 1);
  return chunk("tEXt", payload);
}

function ztxtChunk(key: string, value: string): Uint8Array {
  const keyBytes = bytes(key);
  const packed = deflateSync(bytes(value));
  const payload = new Uint8Array(keyBytes.length + 2 + packed.length);
  payload.set(keyBytes);
  payload[keyBytes.length] = 0;
  payload[keyBytes.length + 1] = 0;
  payload.set(packed, keyBytes.length + 2);
  return chunk("zTXt", payload);
}

function itxtChunk(key: string, value: string): Uint8Array {
  const keyBytes = bytes(key);
  const packed = deflateSync(bytes(value));
  const payload = new Uint8Array(keyBytes.length + 5 + packed.length);
  payload.set(keyBytes);
  let p = keyBytes.length;
  payload[p++] = 0;
  payload[p++] = 1;
  payload[p++] = 0;
  payload[p++] = 0;
  payload[p++] = 0;
  payload.set(packed, p);
  return chunk("iTXt", payload);
}

describe("analyzeAI", () => {
  it("detects explicit OpenAI phrases in PNG text chunks", async () => {
    const png = pngWith([textChunk("Description", "Created by OpenAI with GPT-4o")]);
    const result = await analyzeAI(png, "image/png");

    expect(result.level).toBe("detected");
    expect(result.signals.some((signal) => signal.kind === "generator")).toBe(true);
    expect(result.signals.some((signal) => signal.kind === "phrase")).toBe(true);
  });

  it("inflates zTXt chunks and detects workflow metadata", async () => {
    const png = pngWith([ztxtChunk("parameters", "prompt: cat\nsteps: 20\nmodel: sdxl")]);
    const result = await analyzeAI(png, "image/png");

    expect(result.level).toBe("detected");
    expect(result.debug.decompressed).toContain("parameters");
    expect(result.signals.some((signal) => signal.kind === "workflow")).toBe(true);
  });

  it("inflates compressed iTXt chunks and detects AI phrases", async () => {
    const png = pngWith([itxtChunk("Comment", "Edited with AI in ChatGPT")]);
    const result = await analyzeAI(png, "image/png");

    expect(result.level).toBe("detected");
    expect(result.debug.decompressed).toContain("Comment");
    expect(result.signals.some((signal) => signal.kind === "phrase")).toBe(true);
  });
});
