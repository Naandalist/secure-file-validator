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
- Content pattern scanning for malicious code
- Support for multiple file types (JPEG, PNG, GIF, PDF, SVG)
- Built-in security checks for PDF and SVG files
- Token-aware PDF policy with safe defaults
- Zero dependencies
- Customizable file size validation
## Installation

```bash
npm install secure-file-validator
```

## Usage

### Basic Usage (Default 5MB limit)

```javascript
import { validateFile } from "secure-file-validator";

try {
  const result = await validateFile("path/to/your/file.pdf");

  if (result.status) {
    console.log("File is valid:", result.message);
  } else {
    console.log("File validation failed:", result.message);
  }
} catch (error) {
  console.error("Error:", error);
}
```

### Custom File Size Limit

```javascript
import { validateFile } from "secure-file-validator";

const TEN_MB = 10 * 1024 * 1024;

try {
  const result = await validateFile("path/to/your/file.pdf", {
    maxSizeInBytes: TEN_MB,
  });

  if (result.status) {
    console.log("File is valid:", result.message);
  } else {
    console.log("File validation failed:", result.message);
  }
} catch (error) {
  console.error("Error:", error);
}
```

### PDF policy

PDF checks look for **name tokens** such as `/JavaScript` and `/JS` in the document and in inflated streams. They do not treat the letters `JS` or the word `Metadata` inside XMP as a hit.

Allowed by default: `/Metadata`, `/Annots`, `/OpenAction`.
Denied by default: `/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFile`, `/XFA`, `/RichMedia`.

`pdfWhitelist` is only needed to opt in to a denied token. Do not whitelist `JS` just to silence a metadata false positive — that case should already pass.

```javascript
import { validateFile } from "secure-file-validator";

// Rare: you fully trust a PDF that contains JavaScript
const result = await validateFile("path/to/file.pdf", {
  pdfWhitelist: ["JavaScript"]
});
```

**Denied tokens that can be opted into:**
- `JS` / `JavaScript`
- `Launch`
- `EmbeddedFile`
- `XFA`
- `RichMedia`

**Note:** Only whitelist tokens you intentionally accept. Whitelisting `JavaScript` disables that check.

## API Reference

### validateFile(filePath, options)

| Parameter | Type | Description | Default |
| --- | --- | --- | --- |
| `filePath` | string | Path to the file to validate | required |
| `options.maxSizeInBytes` | number | Maximum file size in bytes | 5MB |
| `options.pdfWhitelist` | `string[]` | Denied PDF tokens to allow (e.g. `['JavaScript']`). Metadata is already allowed. | `[]` |

Returns `{ status: boolean, message: string }`.

## FAQ

**Q: I'm getting false positives on legitimate PDFs. What should I do?**  
A: `/Metadata`, `/Annots`, and `/OpenAction` are allowed by default. A file should not be rejected just because it contains those tokens or the letters `JS` in ordinary text. If a PDF is still rejected, check the message for the actual name token (`/JavaScript`, `/Launch`, …). Only whitelist a denied token if you intentionally accept that feature.

## License

This project is licensed under the MIT License
