# secure-file-validator

Secure file validation library with file signature checking and content validation for Node.js. Built with ES Modules and TypeScript support.

[![npm version](https://badge.fury.io/js/secure-file-validator.svg)](https://badge.fury.io/js/secure-file-validator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- File signature validation for common file types (JPEG, PNG, GIF, PDF, ZIP)
- Malicious content detection
- Customizable file size limits
- validation reporting
- TypeScript support
- Zero dependencies
- ES Modules support

## Installation

```bash
npm install secure-file-validator
```

## Basic Usage

```javascript
import { validateFile } from 'secure-file-validator';
import { readFile } from 'fs/promises';

const checkMyFile = async () => {
  const buffer = await readFile('image.jpg');
  const result = await validateFile(buffer, 'jpeg');
  console.log(result);
  // { status: true, message: 'File validation passed' }
};
```

## API Reference

### 1. validateFile()

Primary function for validating files with comprehensive checks.

```javascript
import { validateFile } from 'secure-file-validator';
import { readFile } from 'fs/promises';

// Example 1: Basic validation
const basicValidation = async () => {
  const buffer = await readFile('document.pdf');
  const result = await validateFile(buffer, 'pdf');
  console.log(result);
};

// Example 2: With custom options
const advancedValidation = async () => {
  const buffer = await readFile('large-image.jpg');
  const result = await validateFile(buffer, 'jpeg', {
    maxSize: 10 * 1024 * 1024, // 10MB
    checkContent: true
  });
  console.log(result);
};

// Example 3: Handling errors
const handleValidation = async () => {
  try {
    const buffer = await readFile('suspicious.pdf');
    const result = await validateFile(buffer, 'pdf');
    if (!result.status) {
      console.error('Validation failed:', result.message);
    }
  } catch (error) {
    console.error('Error during validation:', error);
  }
};
```

### 2. validateFileContent()

Specifically checks file content for malicious patterns.

```javascript
import { validateFileContent } from 'secure-file-validator';
import { readFile } from 'fs/promises';

// Example 1: Check for malicious content
const checkContent = async () => {
  const buffer = await readFile('test.pdf');
  const result = validateFileContent(buffer);
  console.log(result);
  // { status: true/false, message: 'Content validation passed/failed' }
};

// Example 2: Content validation in pipeline
const validateUpload = async (fileBuffer) => {
  // First check content
  const contentCheck = validateFileContent(fileBuffer);
  if (!contentCheck.status) {
    return contentCheck;
  }
  // Proceed with other validations...
};
```

### 3. matchesFileType()

Verifies if a file matches a specific type's signature.

```javascript
import { matchesFileType } from 'secure-file-validator';
import { readFile } from 'fs/promises';

// Example 1: Simple type check
const checkFileType = async () => {
  const buffer = await readFile('image.png');
  const isPNG = matchesFileType(buffer, 'png');
  console.log('Is PNG:', isPNG);
};

// Example 2: Multiple type checking
const findFileType = async (buffer) => {
  const types = ['jpeg', 'png', 'gif', 'pdf'];
  for (const type of types) {
    if (matchesFileType(buffer, type)) {
      return type;
    }
  }
  return 'unknown';
};
```

### 4. getSupportedTypes()

Returns a list of all supported file types.

```javascript
import { getSupportedTypes } from 'secure-file-validator';

// Example 1: Get all supported types
const types = getSupportedTypes();
console.log('Supported types:', types);

// Example 2: Check if file type is supported
const isTypeSupported = (type) => {
  const supported = getSupportedTypes();
  return supported.includes(type);
};
```

### 5. compareSignature()

Low-level function to compare file signatures.

```javascript
import { compareSignature, FILE_SIGNATURES } from 'secure-file-validator';
import { readFile } from 'fs/promises';

// Example 1: Manual signature comparison
const checkSignature = async () => {
  const buffer = await readFile('test.jpg');
  const jpegSignature = FILE_SIGNATURES.jpeg[0]; // Standard JPEG signature
  const matches = compareSignature(buffer, jpegSignature);
  console.log('Signature matches:', matches);
};
```

## TypeScript Support

The package includes TypeScript definitions:

```typescript
import type { 
  ValidationResult, 
  ValidationOptions, 
  FileTypes 
} from 'secure-file-validator';

// Type-safe validation
const validateImage = async (buffer: Buffer): Promise<ValidationResult> => {
  const options: ValidationOptions = {
    maxSize: 5 * 1024 * 1024,
    checkContent: true
  };
  
  const fileType: FileTypes = 'jpeg';
  return await validateFile(buffer, fileType, options);
};
```

## Full Example

```javascript
import { 
  validateFile, 
  validateFileContent, 
  matchesFileType, 
  getSupportedTypes 
} from 'secure-file-validator';
import { readFile } from 'fs/promises';

const validateUpload = async (filePath) => {
  try {
    // Read file
    const buffer = await readFile(filePath);
    
    // Check supported types
    const supportedTypes = getSupportedTypes();
    console.log('Supported types:', supportedTypes);
    
    // Try to match file type
    let fileType = 'unknown';
    for (const type of supportedTypes) {
      if (matchesFileType(buffer, type)) {
        fileType = type;
        break;
      }
    }
    
    if (fileType === 'unknown') {
      return { status: false, message: 'Unsupported file type' };
    }
    
    // Validate content first
    const contentCheck = validateFileContent(buffer);
    if (!contentCheck.status) {
      return contentCheck;
    }
    
    // Full validation
    const result = await validateFile(buffer, fileType, {
      maxSize: 5 * 1024 * 1024,
      checkContent: true
    });
    
    return result;
  } catch (error) {
    return {
      status: false,
      message: `Validation failed: ${error.message}`
    };
  }
};

// Usage
const main = async () => {
  const result = await validateUpload('test-file.pdf');
  console.log('Validation result:', result);
};

main().catch(console.error);
```

## Security Considerations

- Always validate files on server side
- Use content validation for untrusted files
- Consider implementing file type whitelisting
- Monitor file size limits
- Implement rate limiting for file upload
- Store validated files securely

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT