import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateFile, validateBytes } from "../index.js";

const assets = path.join(path.dirname(fileURLToPath(import.meta.url)), "assets");

test("success results expose ok and code", async () => {
  const result = await validateFile(path.join(assets, "image-sample.jpg"));
  assert.equal(result.ok, true);
  assert.equal(result.status, true);
  assert.equal(result.code, "OK");
});

test("PDF javascript failures use PDF_JAVASCRIPT", async () => {
  const result = await validateFile(path.join(assets, "doc-sample-injected.pdf"));
  assert.equal(result.ok, false);
  assert.equal(result.code, "PDF_JAVASCRIPT");
});

test("validates an in-memory PNG buffer without touching disk", async () => {
  const bytes = await readFile(path.join(assets, "image-sample.jpg"));
  const result = await validateFile(bytes, { filename: "photo.jpg" });
  assert.equal(result.ok, true, result.message);
  assert.equal(result.code, "OK");
});

test("validateBytes accepts Uint8Array with extension", async () => {
  const bytes = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const result = validateBytes(bytes, { extension: "png" });
  assert.equal(result.ok, true, result.message);
});

test("buffer input without extension fails with INVALID_EXTENSION", async () => {
  const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const result = await validateFile(bytes);
  assert.equal(result.ok, false);
  assert.equal(result.code, "INVALID_EXTENSION");
});

test("buffer size limit uses byteLength", () => {
  const bytes = Buffer.alloc(32, 0);
  bytes[0] = 0x89;
  bytes[1] = 0x50;
  bytes[2] = 0x4e;
  bytes[3] = 0x47;
  const result = validateBytes(bytes, { extension: ".png", maxSizeInBytes: 8 });
  assert.equal(result.ok, false);
  assert.equal(result.code, "TOO_LARGE");
});
