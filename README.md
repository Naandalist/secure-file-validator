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
- Whitelist feature to handle false positive detections
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

// Example: Set 10MB limit
const TEN_MB = 10 * 1024 * 1024; // 10MB in bytes

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

### PDF Whitelist for False Positive Handling

The library includes security checks for potentially dangerous PDF patterns. However, some legitimate PDFs may contain patterns like `/Metadata/`, `/OpenAction/`, or `/JS/` that are flagged as suspicious. You can use the `pdfWhitelist` option to allow specific patterns:

```javascript
import { validateFile } from "secure-file-validator";

// Allow Metadata and OpenAction patterns in PDFs
const result = await validateFile("path/to/file.pdf", {
  pdfWhitelist: ['Metadata', 'OpenAction', 'JS']
});

if (result.status) {
  console.log("File is valid:", result.message);
} else {
  console.log("File validation failed:", result.message);
}
```

**Available PDF patterns to whitelist:**
- `Metadata` - PDF metadata (commonly found in legitimate PDFs)
- `OpenAction` - Automatic actions when PDF is opened
- `JS` - JavaScript abbreviation
- `JavaScript` - JavaScript code
- `Launch` - Launch actions
- `EmbeddedFile` - Embedded files
- `XFA` - XML Forms Architecture
- `Annots` - Annotations

**Note:** Only whitelist patterns you trust. Whitelisting patterns reduces security checks and should be done carefully based on your specific use case.

### Using Size Constants

```javascript
// File size constants for convenience
const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

// Examples
const options = {
  maxSizeInBytes: 10 * MB, // 10MB
  // or
  // maxSizeInBytes: 1 * GB  // 1GB
};

const result = await validateFile("path/to/file.pdf", options);
```

### Advanced Usage

```javascript
import {
  validateFile,
  validateFileContent,
  checkFileSignature,
} from "secure-file-validator";

// Example: Custom validation pipeline with size limit
async function validateUserUpload(filePath) {
  const options = {
    maxSizeInBytes: 15 * 1024 * 1024, // 15MB limit
  };

  // First, validate the entire file
  const fileValidation = await validateFile(filePath, options);
  if (!fileValidation.status) {
    return fileValidation;
  }

  // Then, perform additional content validation if needed
  const contentValidation = await validateFileContent(filePath, options);
  return contentValidation;
}

// Example: PDF validation with whitelist for common patterns
async function validatePDFWithWhitelist(filePath) {
  const result = await validateFile(filePath, {
    maxSizeInBytes: 10 * 1024 * 1024, // 10MB
    pdfWhitelist: ['Metadata', 'OpenAction'], // Allow these common patterns
  });
  
  return result;
}
```

## Supported File Types

| Category        | File Type |
| --------------- | --------- |
| Images          | JPEG/JPG  |
| Images          | PNG       |
| Images          | GIF       |
| Documents       | PDF       |
| Vector Graphics | SVG       |

## API Reference

### validateFile(filePath, options)

Main validation function that performs all checks.

| Parameter                | Type       | Description                                                     | Default  |
| ------------------------ | ---------- | --------------------------------------------------------------- | -------- |
| `filePath`               | string     | Path to the file to validate                                    | required |
| `options `               | Object     | Configuration options                                           | `{}`     |
| `options.maxSizeInBytes` | number     | Maximum file size in bytes                                      | 5MB      |
| `options.pdfWhitelist`   | `string[]` | Array of PDF patterns to whitelist (e.g., `['Metadata', 'JS']`) | `[]`     |

<br>

| Return Type               | Description                          |
| ------------------------- | ------------------------------------ |
| `Promise<Object>`         | Async result object                  |
| `Promise<Object>.status`  | boolean indicating validation result |
| `Promise<Object>.message` | string containing detailed message   |

### validateFileContent(filePath, options)

Performs content-specific validation.

| Parameter              | Type       | Description                                                     | Default  |
| ---------------------- | ---------- | --------------------------------------------------------------- | -------- |
| `filePath`             | string     | Path to the file to validate                                    | required |
| `options `             | Object     | Configuration options                                           | `{}`     |
| `options.pdfWhitelist` | `string[]` | Array of PDF patterns to whitelist (e.g., `['Metadata', 'JS']`) | `[]`     |

<br>

| Return Type               | Description                          |
| ------------------------- | ------------------------------------ |
| `Promise<Object>`         | Async result object                  |
| `Promise<Object>.status`  | boolean indicating validation result |
| `Promise<Object>.message` | string containing detailed message   |

### checkFileSignature(buffer, signatures)

Checks file buffer against known signatures.

| Parameter    | Type                   | Description                       | Default  |
| ------------ | ---------------------- | --------------------------------- | -------- |
| `buffer`     | Buffer                 | File buffer to check              | required |
| `signatures` | `Array<Array<number>>` | Valid signatures to check against | required |

<br>

| Return Type | Description                                |
| ----------- | ------------------------------------------ |
| `boolean`   | True if signature matches, false otherwise |

## File Size Configuration

The file size limit is configurable through the `maxSizeInBytes` option:

```javascript
// Common file size limits
const limits = {
  small: 1 * 1024 * 1024, // 1MB
  medium: 10 * 1024 * 1024, // 10MB
  large: 100 * 1024 * 1024, // 100MB
  custom: 15.5 * 1024 * 1024, // 15.5MB
};

// Usage
const result = await validateFile("file.pdf", {
  maxSizeInBytes: limits.medium,
});
```

## Example Results

```javascript
// Successful validation
{
  status: true,
  message: "Content validation passed"
}

// Failed validation (file size)
{
  status: false,
  message: "File size exceeds limit of 5MB"
}

// Failed validation (invalid file type)
{
  status: false,
  message: "Invalid file extension"
}

// Failed validation (malicious content)
{
  status: false,
  message: "Suspicious pattern detected: /<script/i"
}
```

## Limitations

- Only supports specified file types
- No stream processing support
- Binary file content is not deeply analyzed
- Pattern matching is done on string representation of files

## Error Handling

```javascript
try {
  const options = { maxSizeInBytes: 10 * 1024 * 1024 }; // 10MB
  const result = await validateFile("path/to/file.pdf", options);

  if (!result.status) {
    // Handle invalid file
    console.error("Validation failed:", result.message);
    // Take appropriate action (e.g., delete file, notify user)
  }
} catch (error) {
  // Handle system errors
  console.error("System error:", error.message);
  // Take appropriate action (e.g., log error, notify admin)
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## FAQ

**Q: How can I set a custom file size limit?**  
A: You can pass the limit in bytes using the options parameter:

```javascript
const limit = 10 * 1024 * 1024; // 10MB
const result = await validateFile("file.pdf", { maxSizeInBytes: limit });
```

**Q: What's the default file size limit?**  
A: The default limit is 5MB if no custom limit is specified.

**Q: Can I set unlimited file size?**  
A: While technically possible by setting a very large number, it's not recommended as files are read into memory during validation.

**Q: I'm getting false positives on legitimate PDFs. What should I do?**  
A: Some legitimate PDFs contain patterns like `/Metadata/` or `/OpenAction/` that are flagged as suspicious. You can use the `pdfWhitelist` option to allow these specific patterns:

```javascript
const result = await validateFile("file.pdf", {
  pdfWhitelist: ['Metadata', 'OpenAction', 'JS']
});
```

Only whitelist patterns you understand and trust, as this reduces security checks.

**Q: How can I handle different size limits for different file types?**  
A: You can create a wrapper function:

```javascript
async function validateWithTypeLimit(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  const limits = {
    ".pdf": 10 * 1024 * 1024, // 10MB for PDFs
    ".jpg": 5 * 1024 * 1024, // 5MB for JPGs
    ".svg": 2 * 1024 * 1024, // 2MB for SVGs
  };

  return validateFile(filePath, {
    maxSizeInBytes: limits[extension] || 5 * 1024 * 1024,
  });
}
```

## License

This project is licensed under the MIT License

Thank you 😀
