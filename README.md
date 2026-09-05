# secure-file-validator

[![npm version](https://badge.fury.io/js/secure-file-validator.svg)](https://badge.fury.io/js/secure-file-validator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/secure-file-validator.svg)](https://nodejs.org)

Node.js helper for **upload type checks**: extension, size, magic numbers, plus a small PDF/SVG content policy.

It is aligned with the *file-type checking* portion of [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) and [CWE-434](https://cwe.mitre.org/data/definitions/434.html). It is **not** a complete upload-security program and it is **not** an antivirus.

## What this library does

- Rejects disallowed extensions (JPEG, PNG, GIF, PDF, SVG only).
- Enforces a size cap (default 5MB).
- Checks magic numbers against the declared extension (JPEG is `FF D8 FF`, any marker).
- PDF: looks for **name tokens** (`/JS`, `/JavaScript`, `/Launch`, …) in the body and in inflated Flate streams. It does not treat the letters `JS` inside ordinary text or XMP as a hit.
- SVG: rejects script, event handlers, and XXE entities; optionally rejects `foreignObject`, `data:` URIs, and external `href`.
- Accepts a filesystem path, `Buffer`, or `Uint8Array`.
- Returns `{ ok, code, message, details? }`. `status` is a deprecated alias of `ok`.

## What this library does not do

- Scan for malware, macros, or EICAR as a virus product.
- Unpack or inspect ZIP/Office/XML containers beyond the PDF/SVG rules above.
- Detect zip bombs, pixel bombs, or decompression bombs in general.
- Sanitize filenames, stop path traversal, or pick a storage layout.
- Set `Content-Type` or decide how the file is served.
- Replace server-side auth, rate limits, or a content-security policy.

Those belong in the rest of the upload pipeline.

## Suggested pipeline

1. Validate the **bytes** with this library (`validateFile(buffer, { filename })`).
2. Store under a **generated name**, not the original filename.
3. Keep uploads **outside the webroot**.
4. Serve with a fixed `Content-Type` you chose, not one taken from the client.

## Install

```bash
npm install secure-file-validator
```

## Usage

```javascript
import { validateFile } from "secure-file-validator";

const result = await validateFile("path/to/your/file.pdf");

if (result.ok) {
  console.log("valid", result.code);
} else {
  console.log(result.code, result.message);
}
```

### In-memory bytes (multer / uploads)

```javascript
import { validateFile, validateBytes } from "secure-file-validator";

const result = await validateFile(req.file.buffer, {
  filename: req.file.originalname,
});

if (!result.ok) {
  throw new Error(result.code);
}

const sync = validateBytes(req.file.buffer, { extension: ".png" });
```

## PDF policy

Checks look for PDF **name objects**, including hex-escaped names (`/J#53` → `/JS`) and names inside inflated streams.

| Token | Default | Code |
| --- | --- | --- |
| `/Metadata` | allow | `PDF_METADATA` |
| `/Annots` | allow | `PDF_ANNOTS` |
| `/OpenAction` | allow | `PDF_OPEN_ACTION` |
| `/JS`, `/JavaScript` | deny | `PDF_JAVASCRIPT` |
| `/Launch` | deny | `PDF_LAUNCH` |
| `/EmbeddedFile` | deny | `PDF_EMBEDDED_FILE` |
| `/XFA` | deny | `PDF_XFA` |
| `/RichMedia` | deny | `PDF_RICH_MEDIA` |

```javascript
const strict = await validateFile(pdfPath, {
  pdf: { allowOpenAction: false },
});

// Dangerous: turns off the script check
const trusted = await validateFile(pdfPath, {
  pdf: { allowJavaScript: true },
});
```

`pdfWhitelist: ['JavaScript']` still works as a deprecated alias. Do **not** allow JavaScript just to silence a metadata hit — metadata is already allowed. See [#1](https://github.com/Naandalist/secure-file-validator/issues/1).

## SVG policy

Always denied: `<script>`, `javascript:`, event handlers (`onload=` …), `<!ENTITY`.

Denied by default, overridable with `options.svg`:

| Rule | Default | Code |
| --- | --- | --- |
| `foreignObject` | deny | `SVG_FOREIGN_OBJECT` |
| `data:` URI | deny | `SVG_DATA_URI` |
| external `href` | deny | `SVG_EXTERNAL_HREF` |

`DOCTYPE` without `ENTITY` and fragment `href="#id"` are allowed.

## API

### `validateFile(input, options)`

`input` is a path, `Buffer`, or `Uint8Array`.

| Parameter | Type | Default |
| --- | --- | --- |
| `options.maxSizeInBytes` | number | 5MB |
| `options.filename` | string | required for buffers if `extension` is omitted |
| `options.extension` | string | `.png` or `png` |
| `options.pdf` | `PdfPolicy` | see table |
| `options.svg` | `SvgPolicy` | see table |
| `options.pdfWhitelist` | string[] | deprecated alias |

`validateBytes(buffer, options)` is the sync form for in-memory bytes.

`validateFileContent` still exists and accepts the same input types.

### Result codes

`OK`, `UNSUPPORTED_TYPE`, `INVALID_EXTENSION`, `TOO_LARGE`, `INVALID_SIGNATURE`, `IO_ERROR`, plus the PDF/SVG codes in the tables above.

## FAQ

**Legitimate PDFs were rejected with `/JS/` or `/Metadata/`.**  
That was a substring false positive ([#1](https://github.com/Naandalist/secure-file-validator/issues/1)). Current builds match name tokens only. Metadata / Annots / OpenAction pass by default. Switch on `result.code` if a file still fails.

**Is this enough to call an upload “safe”?**  
No. It reduces *wrong-type* and *obvious active-content* mistakes. Combine it with generated names, isolated storage, and a tight serving policy.

## License

MIT
