import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
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
  assert.match(result.message, /\/(?:JavaScript|JS)/);
});

test("rejects the EICAR JavaScript PDF", async () => {
  const result = await validateFile(asset("eicar-adobe-acrobat-javascript-alert.pdf"));
  assert.equal(result.status, false);
  assert.match(result.message, /\/(?:JavaScript|JS)/);
});

test("does not treat Metadata-only whitelist as a free pass for JS PDFs", async () => {
  const result = await validateFile(asset("eicar-adobe-acrobat-javascript-alert.pdf"), {
    pdfWhitelist: ["Metadata"],
  });
  assert.equal(result.status, false, result.message);
  assert.match(result.message, /\/(?:JavaScript|JS)/);
});

test("allows Metadata and OpenAction tokens by default", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "meta.pdf");
  await writeFile(file, "%PDF-1.4\n1 0 obj<</Metadata 2 0 R/OpenAction 3 0 R/Annots[]>>endobj\n%%EOF\n");
  try {
    const result = await validateFile(file);
    assert.equal(result.status, true, result.message);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("does not flag the letters JS unless they form a /JS name token", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "letters.pdf");
  await writeFile(file, "%PDF-1.4\n1 0 obj<</Title (Not a JS token, just JSON-like text)>>endobj\n%%EOF\n");
  try {
    const result = await validateFile(file);
    assert.equal(result.status, true, result.message);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("detects hex-escaped PDF JavaScript names", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "escaped.pdf");
  await writeFile(file, "%PDF-1.4\n1 0 obj<</J#53 2 0 R>>endobj\n%%EOF\n");
  try {
    const result = await validateFile(file);
    assert.equal(result.status, false, result.message);
    assert.match(result.message, /\/JS/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("pdf.allowOpenAction false rejects OpenAction without allowing JavaScript", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "open-action.pdf");
  await writeFile(file, "%PDF-1.4\n1 0 obj<</OpenAction 2 0 R>>endobj\n%%EOF\n");
  try {
    const allowed = await validateFile(file);
    assert.equal(allowed.status, true, allowed.message);
    const denied = await validateFile(file, { pdf: { allowOpenAction: false } });
    assert.equal(denied.status, false, denied.message);
    assert.match(denied.message, /\/OpenAction/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("pdf.allowJavaScript covers both /JS and /JavaScript", async () => {
  const injected = await validateFile(asset("doc-sample-injected.pdf"), { pdf: { allowJavaScript: true } });
  assert.equal(injected.status, true, injected.message);
  const eicar = await validateFile(asset("eicar-adobe-acrobat-javascript-alert.pdf"), { pdf: { allowJavaScript: true } });
  assert.equal(eicar.status, true, eicar.message);
  const stillDenied = await validateFile(asset("doc-sample-injected.pdf"), { pdf: { allowJavaScript: false } });
  assert.equal(stillDenied.status, false);
});

test("deprecated pdfWhitelist still maps onto the structured policy", async () => {
  const result = await validateFile(asset("doc-sample-injected.pdf"), { pdfWhitelist: ["JavaScript"] });
  assert.equal(result.status, true, result.message);
});

test("accepts JPEG SOI markers beyond JFIF/Exif", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "dqt.jpg");
  await writeFile(file, Buffer.from([0xff, 0xd8, 0xff, 0xdb, 0x00, 0x02]));
  try {
    const result = await validateFile(file);
    assert.equal(result.status, true, result.message);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("does not scan raster images for HTML/JS substrings", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "fn.png");
  await writeFile(file, Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from("function(onload")]));
  try {
    const result = await validateFile(file);
    assert.equal(result.status, true, result.message);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("allows an SVG DOCTYPE without ENTITY", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const file = path.join(dir, "doctype.svg");
  await writeFile(file, `<?xml version="1.0"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg xmlns="http://www.w3.org/2000/svg" href="#ok"><circle r="1"/></svg>`);
  try {
    const result = await validateFile(file);
    assert.equal(result.status, true, result.message);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("rejects SVG event handlers and XXE entities", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sfv-"));
  const onload = path.join(dir, "onload.svg");
  const entity = path.join(dir, "entity.svg");
  await writeFile(onload, `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`);
  await writeFile(entity, `<svg xmlns="http://www.w3.org/2000/svg"><!ENTITY xxe SYSTEM "file:///etc/passwd"></svg>`);
  try {
    const onloadResult = await validateFile(onload);
    assert.equal(onloadResult.status, false);
    assert.match(onloadResult.message, /event handler/);
    const entityResult = await validateFile(entity);
    assert.equal(entityResult.status, false);
    assert.match(entityResult.message, /ENTITY/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("checkFileSignature matches a PNG header", () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]);
  assert.equal(checkFileSignature(png, [[0x89, 0x50, 0x4e, 0x47]]), true);
  assert.equal(checkFileSignature(png, [[0xff, 0xd8, 0xff]]), false);
});
