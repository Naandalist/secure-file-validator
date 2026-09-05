# secure-file-validator

[![npm version](https://badge.fury.io/js/secure-file-validator.svg)](https://badge.fury.io/js/secure-file-validator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/secure-file-validator.svg)](https://nodejs.org)

A secure file validation library for Node.js that performs signature checking and content validation. It hardenings app from malicious file uploads by validating file types, checking file signatures, and scanning for suspicious patterns.

This library is built following industry-standard security guidelines:

- [OWASP Unrestricted File Upload Prevention](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [NIST Security Guidelines for File Uploads](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)

## Features

- Secure file signature validation
- Token-aware PDF policy and scoped SVG checks
- Accepts filesystem paths, Buffer, and Uint8Array
- Structured `{ ok, code, message }` results
- Zero runtime dependencies
- Customizable file size validation

## Installation

```bash
npm install secure-file-validator
```

## Usage

```javascript
import { validateFile } from "secure-file-validator";

const result = await validateFile("path/to/your/file.pdf");

if (result.ok) {
  console.log("File is valid:", result.code);
} else {
  console.log("File validation failed:", result.code, result.message);
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

### PDF policy

Allowed by default: `/Metadata`, `/Annots`, `/OpenAction`.
Denied by default: `/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFile`, `/XFA`, `/RichMedia`.

```javascript
const strict = await validateFile("path/to/file.pdf", {
  pdf: { allowOpenAction: false }
});

// Dangerous: disables the script check
const trusted = await validateFile("path/to/file.pdf", {
  pdf: { allowJavaScript: true }
});
```

## API Reference

### validateFile(input, options)

`input` is a filesystem path, `Buffer`, or `Uint8Array`.

| Parameter | Type | Description | Default |
| --- | --- | --- | --- |
| `input` | `string \| Buffer \| Uint8Array` | Path or in-memory bytes | required |
| `options.maxSizeInBytes` | number | Maximum file size in bytes | 5MB |
| `options.filename` | string | Required for buffer input if `extension` is omitted | — |
| `options.extension` | string | File type for buffer input (`.png` or `png`) | — |
| `options.pdf` | `PdfPolicy` | Structured allow/deny flags for PDF tokens | see defaults above |
| `options.svg` | `SvgPolicy` | Optional SVG allow flags | deny foreignObject / data / external href |
| `options.pdfWhitelist` | `string[]` | Deprecated alias mapped onto `pdf` allow flags | `[]` |

Returns `{ ok, status, code, message, details? }`. `status` is a deprecated alias of `ok`.

Use `validateBytes(buffer, options)` for a sync result when you already have bytes.

## FAQ

**Q: I'm getting false positives on legitimate PDFs. What should I do?**  
A: `/Metadata`, `/Annots`, and `/OpenAction` are allowed by default. If a PDF is still rejected, switch on `result.code` (`PDF_JAVASCRIPT`, `PDF_LAUNCH`, …). Only allow a denied token if you intentionally accept that feature.

## License

This project is licensed under the MIT License
