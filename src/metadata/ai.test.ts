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

function malformedZtxtChunk(key: string): Uint8Array {
  const keyBytes = bytes(key);
  const payload = new Uint8Array(keyBytes.length + 5);
  payload.set(keyBytes);
  payload[keyBytes.length] = 0;
  payload[keyBytes.length + 1] = 0;
  payload.set([0xff, 0x00, 0xff], keyBytes.length + 2);
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

function riffChunk(type: string, payload: Uint8Array): Uint8Array {
  const paddedLength = payload.length + (payload.length & 1);
  const out = new Uint8Array(8 + paddedLength);
  const view = new DataView(out.buffer);
  for (let i = 0; i < 4; i += 1) out[i] = type.charCodeAt(i);
  view.setUint32(4, payload.length, true);
  out.set(payload, 8);
  return out;
}

function webpWith(chunks: Uint8Array[]): ArrayBuffer {
  const bodyLength = chunks.reduce((sum, part) => sum + part.length, 0);
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);
  header.set(bytes("RIFF"), 0);
  view.setUint32(4, 4 + bodyLength, true);
  header.set(bytes("WEBP"), 8);
  return concat([header, ...chunks]);
}

function jpegWithApp11(value: string): ArrayBuffer {
  const payload = bytes(value);
  const segment = new Uint8Array(4 + payload.length);
  const view = new DataView(segment.buffer);
  view.setUint16(0, 0xffeb);
  view.setUint16(2, payload.length + 2);
  segment.set(payload, 4);
  return concat([new Uint8Array([0xff, 0xd8]), segment, new Uint8Array([0xff, 0xd9])]);
}

function jpegWithFragmentedApp11(values: string[]): ArrayBuffer {
  const segments = values.map((value, index) => {
    const data = bytes(value);
    const payload = new Uint8Array(8 + data.length);
    payload.set(bytes("JP"), 0);
    payload[3] = 1;
    payload[7] = index + 1;
    payload.set(data, 8);
    const segment = new Uint8Array(4 + payload.length);
    const view = new DataView(segment.buffer);
    view.setUint16(0, 0xffeb);
    view.setUint16(2, payload.length + 2);
    segment.set(payload, 4);
    return segment;
  });
  return concat([new Uint8Array([0xff, 0xd8, 0xff, 0xff]), ...segments.map((segment, index) => index === 0 ? segment.slice(1) : segment), new Uint8Array([0xff, 0xd9])]);
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

  it("contains malformed compressed metadata without an unhandled failure", async () => {
    const png = pngWith([malformedZtxtChunk("parameters")]);
    const result = await analyzeAI(png, "image/png");

    expect(result.level).toBe("maybe");
    expect(result.debug.failedCompressed).toContain("parameters");
  });

  it("caps highly expanded compressed metadata and still inspects its prefix", async () => {
    const expanded = `Created by OpenAI ${"x".repeat(2 * 1024 * 1024 + 4096)}`;
    const png = pngWith([ztxtChunk("Description", expanded)]);
    const result = await analyzeAI(png, "image/png");

    expect(result.level).toBe("detected");
    expect(result.debug.scanBytes).toBeLessThanOrEqual(2 * 1024 * 1024);
  });

  it("supports concurrent compressed analyses without shared state", async () => {
    const first = pngWith([ztxtChunk("parameters", "prompt: cat\nsteps: 20")]);
    const second = pngWith([itxtChunk("Comment", "Created by ChatGPT")]);
    const [firstResult, secondResult] = await Promise.all([
      analyzeAI(first, "image/png"),
      analyzeAI(second, "image/png")
    ]);

    expect(firstResult.level).toBe("detected");
    expect(secondResult.level).toBe("detected");
  });

  it("sniffs a WebP container even when the file is declared as PNG", async () => {
    const webp = webpWith([riffChunk("XMP ", bytes("Created by OpenAI with gpt-image"))]);
    const result = await analyzeAI(webp, "image/png");

    expect(result.level).toBe("detected");
    expect(result.signals.some((signal) => signal.kind === "generator")).toBe(true);
  });

  it("recognizes OpenAI C2PA data in JPEG APP11", async () => {
    const jpeg = jpegWithApp11("JUMBF c2pa c2pa.created claim_generator OpenAI");
    const result = await analyzeAI(jpeg, "image/jpeg");

    expect(result.level).toBe("detected");
    expect(result.signals.some((signal) => signal.kind === "c2pa")).toBe(true);
  });

  it("treats generic C2PA actions as provenance hints, not proof of AI", async () => {
    const jpeg = jpegWithApp11("JUMBF c2pa c2pa.created camera capture");
    const result = await analyzeAI(jpeg, "image/jpeg");

    expect(result.level).toBe("maybe");
    expect(result.signals.find((signal) => signal.kind === "c2pa")?.strong).toBe(false);
  });

  it("reassembles AI tokens split across JPEG APP11 fragments and accepts fill bytes", async () => {
    const jpeg = jpegWithFragmentedApp11(["c2pa c2pa.cre", "ated claim_generator Open", "AI gpt-", "image"]);
    const result = await analyzeAI(jpeg, "image/png");

    expect(result.level).toBe("detected");
    expect(result.signals.some((signal) => signal.kind === "generator")).toBe(true);
  });

  it("keeps consecutive analyses independent across real container types", async () => {
    const first = pngWith([textChunk("Description", "Created by OpenAI")]);
    const second = webpWith([riffChunk("C2PA", bytes("c2pa.created OpenAI gpt-image"))]);

    const firstResult = await analyzeAI(first, "image/png");
    const secondResult = await analyzeAI(second, "image/png");

    expect(firstResult.level).toBe("detected");
    expect(secondResult.level).toBe("detected");
  });

  it("does not leak signals from a previous analysis", async () => {
    const detected = pngWith([textChunk("Description", "Created by OpenAI")]);
    const clean = pngWith([textChunk("Description", "Camera original")]);

    expect((await analyzeAI(detected, "image/png")).level).toBe("detected");
    expect((await analyzeAI(clean, "image/png")).level).toBe("clear");
  });
});
