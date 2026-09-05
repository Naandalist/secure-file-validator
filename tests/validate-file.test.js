import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateFile, checkFileSignature } from "../index.js";

const assets = path.join(path.dirname(fileURLToPath(import.meta.url)), "assets");
const asset = (name) => path.join(assets, name);

test("rejects unsupported extensions", async () => {
  const result = await validateFile(asset("doc-sample.pdf").replace(/\.pdf$/, ".txt"));
  assert.equal(result.status, false);
  assert.match(result.message, /Invalid file extension|Unsupported file type|File validation failed/i);
});

test("rejects missing files without throwing", async () => {
  const result = await validateFile(path.join(assets, "does-not-exist.jpg"));
  assert.equal(result.status, false);
  assert.match(result.message, /File validation failed/);
});

test("rejects files over maxSizeInBytes", async () => {
  const result = await validateFile(asset("image-sample.jpg"), { maxSizeInBytes: 10 });
  assert.equal(result.status, false);
  assert.match(result.message, /File size exceeds limit/);
});

test("accepts a legitimate JPEG", async () => {
  const result = await validateFile(asset("image-sample.jpg"));
  assert.equal(result.status, true);
});

test("rejects a JPEG with an invalid signature", async () => {
  const result = await validateFile(asset("image-sample-injected.jpg"));
  assert.equal(result.status, false);
  assert.match(result.message, /Invalid file signature/);
});

test("accepts a legitimate SVG", async () => {
  const result = await validateFile(asset("icon-sample.svg"));
  assert.equal(result.status, true);
});

test("rejects an SVG that contains a script tag", async () => {
  const result = await validateFile(asset("icon-sample-injected.svg"));
  assert.equal(result.status, false);
  assert.match(result.message, /script/i);
});

test("accepts the legitimate PDF sample", async () => {
  const result = await validateFile(asset("doc-sample.pdf"));
  assert.equal(result.status, true, result.message);
});

test("rejects a PDF that contains a JavaScript name", async () => {
  const result = await validateFile(asset("doc-sample-injected.pdf"));
  assert.equal(result.status, false);
  assert.match(result.message, /JavaScript/);
});

test("rejects the EICAR JavaScript PDF", async () => {
  const result = await validateFile(asset("eicar-adobe-acrobat-javascript-alert.pdf"));
  assert.equal(result.status, false);
});

test("does not treat Metadata-only whitelist as a free pass for JS PDFs", { skip: "blocked by #3/#4 — current scanner returns first hit (/Metadata/) and then skips remaining checks incorrectly when that name is whitelisted" }, async () => {
  const result = await validateFile(asset("eicar-adobe-acrobat-javascript-alert.pdf"), {
    pdfWhitelist: ["Metadata"],
  });
  assert.equal(result.status, false, "JS-bearing PDFs must still fail after Metadata is allowed");
});

test("checkFileSignature matches a PNG header", () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]);
  assert.equal(checkFileSignature(png, [[0x89, 0x50, 0x4e, 0x47]]), true);
  assert.equal(checkFileSignature(png, [[0xff, 0xd8, 0xff]]), false);
});
