import { describe, expect, it } from "vitest";
import { MAX_EXIF_BYTES, buildExifTIFF, degreesToDMS, readExifTIFF } from "./exif";

/** Precisione attesa dal round-trip: i secondi sono scritti in decimillesimi. */
const GPS_TOLERANCE = 1e-6;

/** Legge la struttura grezza del TIFF prodotto, per le asserzioni di formato. */
function inspect(tiff: Uint8Array): {
  entries: Array<{ tag: number; type: number; count: number; dataOffset: number | null }>;
} {
  const view = new DataView(tiff.buffer, tiff.byteOffset, tiff.byteLength);
  const typeSize: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8 };
  const entries: Array<{ tag: number; type: number; count: number; dataOffset: number | null }> = [];

  const walk = (dirStart: number): void => {
    const count = view.getUint16(dirStart, true);
    for (let i = 0; i < count; i += 1) {
      const at = dirStart + 2 + i * 12;
      const tag = view.getUint16(at, true);
      const type = view.getUint16(at + 2, true);
      const valueCount = view.getUint32(at + 4, true);
      const size = (typeSize[type] || 1) * valueCount;
      entries.push({ tag, type, count: valueCount, dataOffset: size > 4 ? view.getUint32(at + 8, true) : null });
      if (tag === 0x8769 || tag === 0x8825) walk(view.getUint32(at + 8, true));
    }
  };

  walk(view.getUint32(4, true));
  return { entries };
}

describe("buildExifTIFF", () => {
  it("returns nothing when there is nothing to keep", () => {
    expect(buildExifTIFF({}).length).toBe(0);
    expect(buildExifTIFF({ make: "   " }).length).toBe(0);
  });

  it("round-trips GPS coordinates in the northern/eastern hemisphere", () => {
    const gps = { lat: 41.9028, lon: 12.4964 };
    const parsed = readExifTIFF(buildExifTIFF({ gps }));

    expect(parsed.gps).toBeDefined();
    expect(parsed.gps?.lat).toBeCloseTo(gps.lat, 6);
    expect(parsed.gps?.lon).toBeCloseTo(gps.lon, 6);
  });

  it("round-trips GPS coordinates in the southern/western hemisphere", () => {
    const gps = { lat: -33.8688, lon: -151.2093 };
    const parsed = readExifTIFF(buildExifTIFF({ gps }));

    expect(parsed.gps?.lat).toBeCloseTo(gps.lat, 6);
    expect(parsed.gps?.lon).toBeCloseTo(gps.lon, 6);
  });

  it("round-trips coordinates at the extremes and at zero", () => {
    for (const gps of [
      { lat: 0, lon: 0 },
      { lat: 90, lon: 180 },
      { lat: -90, lon: -180 }
    ]) {
      const parsed = readExifTIFF(buildExifTIFF({ gps }));
      expect(Math.abs((parsed.gps?.lat ?? NaN) - gps.lat)).toBeLessThan(GPS_TOLERANCE);
      expect(Math.abs((parsed.gps?.lon ?? NaN) - gps.lon)).toBeLessThan(GPS_TOLERANCE);
    }
  });

  it("drops GPS values that are out of range or not finite", () => {
    expect(readExifTIFF(buildExifTIFF({ gps: { lat: 91, lon: 0 } })).gps).toBeUndefined();
    expect(readExifTIFF(buildExifTIFF({ gps: { lat: 0, lon: 181 } })).gps).toBeUndefined();
    expect(readExifTIFF(buildExifTIFF({ gps: { lat: NaN, lon: 0 } })).gps).toBeUndefined();
  });

  it("round-trips the author name and copyright", () => {
    const parsed = readExifTIFF(
      buildExifTIFF({ artist: "Mario Rossi", copyright: "(c) 2026 Mario Rossi" })
    );

    expect(parsed.artist).toBe("Mario Rossi");
    expect(parsed.copyright).toBe("(c) 2026 Mario Rossi");
  });

  it("round-trips camera, software and date fields", () => {
    const parsed = readExifTIFF(
      buildExifTIFF({
        make: "Canon",
        model: "EOS R6",
        software: "noMeta",
        datetime: "2026:08:17 10:30:00"
      })
    );

    expect(parsed.make).toBe("Canon");
    expect(parsed.model).toBe("EOS R6");
    expect(parsed.software).toBe("noMeta");
    expect(parsed.datetime).toBe("2026:08:17 10:30:00");
  });

  it("round-trips DateTimeOriginal through the Exif IFD pointer", () => {
    const parsed = readExifTIFF(buildExifTIFF({ dateOriginal: "2026:08:17 10:30:00" }));

    expect(parsed.dateOriginal).toBe("2026:08:17 10:30:00");
    expect(inspect(buildExifTIFF({ dateOriginal: "2026:08:17 10:30:00" })).entries
      .some((entry) => entry.tag === 0x8769)).toBe(true);
  });

  it("strips non-ASCII characters instead of mangling them", () => {
    const parsed = readExifTIFF(buildExifTIFF({ artist: "Renée Müller 日本" }));

    expect(parsed.artist).toBe("Rene Mller");
  });

  it("truncates oversized strings to the shared metadata cap", () => {
    const parsed = readExifTIFF(buildExifTIFF({ software: "x".repeat(2000) }));

    expect(parsed.software?.length).toBe(512);
  });

  it("never writes Orientation unless it is explicitly provided", () => {
    const withoutOrientation = readExifTIFF(buildExifTIFF({ make: "Canon" }));
    const withOrientation = readExifTIFF(buildExifTIFF({ make: "Canon", orientation: 6 }));

    expect(withoutOrientation.orientation).toBeUndefined();
    expect(withOrientation.orientation).toBe(6);
  });

  it("ignores orientation values outside the 1-8 range", () => {
    expect(readExifTIFF(buildExifTIFF({ make: "Canon", orientation: 0 })).orientation).toBeUndefined();
    expect(readExifTIFF(buildExifTIFF({ make: "Canon", orientation: 9 })).orientation).toBeUndefined();
  });

  it("keeps every value independent when several are written together", () => {
    const values = {
      make: "Fujifilm",
      model: "X-T5",
      software: "noMeta",
      artist: "Mario Rossi",
      copyright: "(c) 2026",
      datetime: "2026:08:17 10:30:00",
      dateOriginal: "2026:08:17 10:29:00",
      gps: { lat: 45.4642, lon: 9.19 }
    };
    const parsed = readExifTIFF(buildExifTIFF(values));

    expect(parsed.make).toBe(values.make);
    expect(parsed.model).toBe(values.model);
    expect(parsed.software).toBe(values.software);
    expect(parsed.artist).toBe(values.artist);
    expect(parsed.copyright).toBe(values.copyright);
    expect(parsed.datetime).toBe(values.datetime);
    expect(parsed.dateOriginal).toBe(values.dateOriginal);
    expect(parsed.gps?.lat).toBeCloseTo(values.gps.lat, 6);
    expect(parsed.gps?.lon).toBeCloseTo(values.gps.lon, 6);
  });

  it("writes a header a TIFF reader accepts", () => {
    const tiff = buildExifTIFF({ make: "Canon" });

    expect(tiff[0]).toBe(0x49);
    expect(tiff[1]).toBe(0x49);
    expect(new DataView(tiff.buffer).getUint16(2, true)).toBe(0x002a);
    expect(new DataView(tiff.buffer).getUint32(4, true)).toBe(8);
  });

  it("orders entries by ascending tag inside every IFD", () => {
    const tiff = buildExifTIFF({
      copyright: "(c) 2026",
      make: "Canon",
      artist: "Mario Rossi",
      dateOriginal: "2026:08:17 10:29:00",
      gps: { lat: 45.4642, lon: 9.19 }
    });
    const view = new DataView(tiff.buffer);

    const assertSorted = (dirStart: number): void => {
      const count = view.getUint16(dirStart, true);
      let previous = -1;
      for (let i = 0; i < count; i += 1) {
        const tag = view.getUint16(dirStart + 2 + i * 12, true);
        expect(tag).toBeGreaterThan(previous);
        previous = tag;
      }
    };

    // IFD0 e, attraverso i puntatori, anche i sotto-IFD Exif e GPS.
    assertSorted(view.getUint32(4, true));
    const subIfds = inspect(tiff).entries.filter((entry) => entry.tag === 0x8769 || entry.tag === 0x8825);
    expect(subIfds.length).toBe(2);
    const ifd0Count = view.getUint16(view.getUint32(4, true), true);
    for (let i = 0; i < ifd0Count; i += 1) {
      const at = view.getUint32(4, true) + 2 + i * 12;
      const tag = view.getUint16(at, true);
      if (tag === 0x8769 || tag === 0x8825) assertSorted(view.getUint32(at + 8, true));
    }
  });

  it("aligns out-of-line values to even offsets and keeps them inside the buffer", () => {
    const tiff = buildExifTIFF({
      make: "Canon",
      model: "EOS R6",
      artist: "Mario Rossi",
      gps: { lat: 45.4642, lon: 9.19 }
    });

    for (const entry of inspect(tiff).entries) {
      if (entry.dataOffset === null) continue;
      expect(entry.dataOffset % 2).toBe(0);
      expect(entry.dataOffset).toBeLessThan(tiff.length);
    }
  });

  it("never writes a zero denominator, which would make the reader return NaN", () => {
    const tiff = buildExifTIFF({ gps: { lat: 0, lon: 0 } });
    const view = new DataView(tiff.buffer);

    for (const entry of inspect(tiff).entries) {
      if (entry.type !== 5 || entry.dataOffset === null) continue;
      for (let i = 0; i < entry.count; i += 1) {
        expect(view.getUint32(entry.dataOffset + i * 8 + 4, true)).toBeGreaterThan(0);
      }
    }
  });

  it("stays well inside the JPEG APP1 size limit even with every field at its cap", () => {
    const long = "x".repeat(2000);
    const tiff = buildExifTIFF({
      make: long,
      model: long,
      software: long,
      artist: long,
      copyright: long,
      datetime: long,
      dateOriginal: long,
      gps: { lat: 45.4642, lon: 9.19 }
    });

    expect(tiff.length).toBeLessThanOrEqual(MAX_EXIF_BYTES);
  });
});

describe("degreesToDMS", () => {
  it("splits decimal degrees into degrees, minutes and seconds", () => {
    // 41.9028° = 41° 54' 10.08"
    expect(degreesToDMS(41.9028)).toEqual([
      [41, 1],
      [54, 1],
      [100800, 10000]
    ]);
  });

  it("carries rounding over instead of emitting 60 minutes or 60 seconds", () => {
    for (const value of [0.9999999999, 59.9999999999, 12.499999999999]) {
      const [[, degDen], [minutes, minDen], [seconds, secDen]] = degreesToDMS(value);
      expect(minutes).toBeLessThan(60);
      expect(seconds).toBeLessThan(600000);
      expect(degDen).toBe(1);
      expect(minDen).toBe(1);
      expect(secDen).toBe(10000);
    }
  });

  it("ignores the sign, which travels in the N/S and E/W reference tags", () => {
    expect(degreesToDMS(-41.9028)).toEqual(degreesToDMS(41.9028));
  });
});
