# secure-file-validator

[![npm version](https://img.shields.io/npm/v/secure-file-validator.svg)](https://www.npmjs.com/package/secure-file-validator)
[![CI](https://github.com/Naandalist/secure-file-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/Naandalist/secure-file-validator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/node/v/secure-file-validator.svg)](https://nodejs.org)

Zero-dependency Node.js helper for **upload type checks**: extension, size, magic numbers, plus a small PDF and SVG content policy.

Aligned with the *file-type checking* part of [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) and [CWE-434](https://cwe.mitre.org/data/definitions/434.html). Not an antivirus. Not a complete upload-security stack.

**Current release: 2.0.0.** See [CHANGELOG.md](CHANGELOG.md).

## Install

```bash
npm install secure-file-validator
```

Requires Node.js 14.16+ (ESM).

## Quick start

```javascript
import { validateFile } from "secure-file-validator";

const result = await validateFile("uploads/photo.jpg");

if (result.ok) {
  // result.code === "OK"
} else {
  // result.code === "INVALID_SIGNATURE" | "PDF_JAVASCRIPT" | ...
  console.error(result.code, result.message);
}
```

`result.status` still exists as a deprecated alias of `result.ok`.

### From an upload buffer

```javascript
import { validateFile, validateBytes } from "secure-file-validator";

const result = await validateFile(req.file.buffer, {
  filename: req.file.originalname, // or extension: ".png"
});

if (!result.ok) {
  throw new Error(result.code);
}

const sync = validateBytes(req.file.buffer, { extension: ".png" });
```

Buffer / `Uint8Array` input must include `filename` or `extension`. Size is checked with `byteLength`.

## Supported types

| Extension | Magic check |
| --- | --- |
| `.jpg` / `.jpeg` | `FF D8 FF` (any marker after SOI) |
| `.png` | `89 50 4E 47` |
| `.gif` | `47 49 46 38` |
| `.pdf` | `%PDF` + `%%EOF`, then token policy |
| `.svg` | `<?xml` or `<svg`, then SVG policy |

Default size cap: 5MB (`options.maxSizeInBytes`).

## PDF policy

The checker looks for PDF **name tokens**, including hex-escaped names (`/J#53` → `/JS`) and names inside inflated Flate streams. The letters `JS` in ordinary text or XMP are not a hit.

| Token | Default | `code` |
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

// Dangerous: turns the script check off
const trusted = await validateFile(pdfPath, {
  pdf: { allowJavaScript: true },
});
```

`pdfWhitelist` still works as a deprecated alias (`JS` and `JavaScript` both set `allowJavaScript`). Do not allow JavaScript only to silence metadata — metadata already passes. See [#1](https://github.com/Naandalist/secure-file-validator/issues/1).

## SVG policy

Always denied: `<script>`, `javascript:`, event handlers (`onload=` …), `<!ENTITY`.

Denied by default, overridable with `options.svg`:

| Rule | Default | `code` |
| --- | --- | --- |
| `foreignObject` | deny | `SVG_FOREIGN_OBJECT` |
| `data:` URI | deny | `SVG_DATA_URI` |
| external `href` | deny | `SVG_EXTERNAL_HREF` |

Allowed: `DOCTYPE` without `ENTITY`, fragment `href="#id"`.

```javascript
await validateFile(svgPath, {
  svg: { allowDataUri: true },
});
```

## Result

```javascript
{
  ok: false,
  status: false,          // deprecated alias of ok
  code: "PDF_JAVASCRIPT",
  message: "Suspicious PDF name token detected: /JavaScript",
  details: { token: "JavaScript" }
}
```

| `code` | Meaning |
| --- | --- |
| `OK` | Passed |
| `UNSUPPORTED_TYPE` | Extension not in the allow list |
| `INVALID_EXTENSION` | Bad or missing extension (buffers need `filename` / `extension`) |
| `TOO_LARGE` | Over `maxSizeInBytes` |
| `INVALID_SIGNATURE` | Magic number does not match the extension |
| `IO_ERROR` | Missing file or unreadable input |
| `PDF_*` / `SVG_*` | See the policy tables |

Switch on `code`. Do not parse `message`.

## API

```ts
validateFile(input, options?): Promise<ValidationResult>
validateFileContent(input, options?): Promise<ValidationResult>
validateBytes(bytes, options?): ValidationResult
```

`input` is a filesystem path, `Buffer`, or `Uint8Array`.

| Option | Type | Default |
| --- | --- | --- |
| `maxSizeInBytes` | number | `5 * 1024 * 1024` |
| `filename` | string | required for buffers if `extension` is omitted |
| `extension` | string | `.png` or `png` |
| `pdf` | `PdfPolicy` | see table |
| `svg` | `SvgPolicy` | see table |
| `pdfWhitelist` | string[] | deprecated alias |

## Migrating from 1.x

| 1.x | 2.x |
| --- | --- |
| `result.status` | `result.ok` (`status` still works) |
| `result.message` only | also `result.code` |
| path string only | path, `Buffer`, or `Uint8Array` |
| JPEG only `FF D8 FF E0/E1` | any `FF D8 FF` |
| PDF substring `/JS/`, `/Metadata/` | name tokens; metadata allowed by default |
| `pdfWhitelist: ['JS']` to dodge false positives | not needed for metadata; use `pdf.allowJavaScript` only if you mean it |

## Scope

**Does:** type vs magic-number check, size cap, PDF name-token policy, SVG active-content policy.

**Does not:** antivirus, Office/ZIP unpacking, zip-bomb detection, filename sanitization, storage layout, `Content-Type` on the way out, auth, or rate limits.

Suggested pipeline:

1. Validate **bytes** (`validateFile(buffer, { filename })`).
2. Store under a **generated name**, not the client filename.
3. Keep files **outside the webroot**.
4. Serve a `Content-Type` you chose, not one taken from the client.

## FAQ

**Legitimate PDFs used to fail with `/JS/` or `/Metadata/`.**  
That was a substring false positive ([#1](https://github.com/Naandalist/secure-file-validator/issues/1)). 2.0.0 matches name tokens only. Metadata / Annots / OpenAction pass by default.

**Is a passing result enough to call an upload safe?**  
No. This reduces wrong-type and obvious active-content mistakes. Pair it with generated names, isolated storage, and a tight serving policy.

## License

MIT — see [LICENSE](LICENSE).
