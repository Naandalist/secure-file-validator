import { promises as fs } from "fs";
import path from "path";
import zlib from "node:zlib";

/**
 * File signatures based on file format specification
 * Reference: https://en.wikipedia.org/wiki/List_of_file_signatures
 */
const FILE_SIGNATURES = {
  // Image signatures
  JPEG: [
    [0xff, 0xd8, 0xff, 0xe0], // JPEG/JFIF
    [0xff, 0xd8, 0xff, 0xe1], // JPEG/Exif
  ],
  PNG: [[0x89, 0x50, 0x4e, 0x47]], // PNG signature
  GIF: [[0x47, 0x49, 0x46, 0x38]], // GIF87a or GIF89a
  // PDF signature
  PDF: [[0x25, 0x50, 0x44, 0x46]], // %PDF
  // SVG signatures - checking for XML and SVG tags
  SVG: [
    [0x3c, 0x3f, 0x78, 0x6d, 0x6c], // <?xml
    [0x3c, 0x73, 0x76, 0x67], // <svg
  ],
};

/**
 * Check if file buffer match with any specified signatures.
 *
 * @param {Buffer} buffer - File buffer to check
 * @param {Array<Array<number>>} signatures - Array of valid signatures for file type
 * @returns {boolean} True if buffer match with any of signatures, false otherwise
 */
const checkFileSignature = (buffer, signatures) => {
  return signatures.some((signature) => {
    return signature.every((byte, index) => buffer[index] === byte);
  });
};

const PDF_NAME_RE = /\/([A-Za-z0-9_.+#\-]+)/g;
const PDF_DENY_NAMES = [
  "JavaScript",
  "JS",
  "Launch",
  "EmbeddedFile",
  "XFA",
  "RichMedia",
];

const decodePdfName = (raw) =>
  raw.replace(/#([0-9A-Fa-f]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

const collectPdfNamesFromString = (text, names) => {
  PDF_NAME_RE.lastIndex = 0;
  let match;
  while ((match = PDF_NAME_RE.exec(text))) {
    names.add(decodePdfName(match[1]));
  }
};

const stripStreamWrappers = (payload) => {
  if (
    payload.length >= 2 &&
    payload[payload.length - 2] === 0x0d &&
    payload[payload.length - 1] === 0x0a
  ) {
    return payload.subarray(0, payload.length - 2);
  }
  if (
    payload.length >= 1 &&
    (payload[payload.length - 1] === 0x0a ||
      payload[payload.length - 1] === 0x0d)
  ) {
    return payload.subarray(0, payload.length - 1);
  }
  return payload;
};

const tryInflate = (payload) => {
  try {
    return zlib.inflateSync(payload);
  } catch {
    try {
      return zlib.inflateRawSync(payload);
    } catch {
      return null;
    }
  }
};

const inflatePdfStreams = (buffer) => {
  const texts = [];
  let idx = 0;

  while (idx < buffer.length) {
    const start = buffer.indexOf("stream", idx);
    if (start === -1) break;

    let payloadStart = start + 6;
    if (buffer[payloadStart] === 0x0d && buffer[payloadStart + 1] === 0x0a) {
      payloadStart += 2;
    } else if (buffer[payloadStart] === 0x0a || buffer[payloadStart] === 0x0d) {
      payloadStart += 1;
    }

    const end = buffer.indexOf("endstream", payloadStart);
    if (end === -1) break;

    const inflated = tryInflate(
      stripStreamWrappers(buffer.subarray(payloadStart, end))
    );
    if (inflated) {
      texts.push(inflated.toString("latin1"));
    }
    idx = end + 9;
  }

  return texts;
};

const collectPdfNames = (buffer) => {
  const names = new Set();
  collectPdfNamesFromString(buffer.toString("latin1"), names);
  for (const inflated of inflatePdfStreams(buffer)) {
    collectPdfNamesFromString(inflated, names);
  }
  return names;
};

const isPdfNameWhitelisted = (name, whitelist) => {
  if (whitelist.has(name)) return true;
  if (name === "JS" && whitelist.has("JavaScript")) return true;
  if (name === "JavaScript" && whitelist.has("JS")) return true;
  return false;
};

const inspectPdfTokens = (buffer, options = {}) => {
  const whitelist = new Set(options.pdfWhitelist || []);
  const names = collectPdfNames(buffer);

  for (const name of PDF_DENY_NAMES) {
    if (!names.has(name)) continue;
    if (isPdfNameWhitelisted(name, whitelist)) continue;
    return {
      status: false,
      message: `Suspicious PDF name token detected: /${name}`,
    };
  }

  return null;
};

/**
 * Validates content of a file by checking its signature and scanning for suspicious patterns.
 *
 * @param {string} filePath - Path to the file to validate
 * @param {Object} options - Validation options
 * @param {Array<string>} [options.pdfWhitelist=[]] - Array of PDF patterns to whitelist (e.g., ['Metadata', 'OpenAction'])
 * @returns {Promise<Object>} Object containing status (boolean) and message (string)
 */
const validateFileContent = async (filePath, options = {}) => {
  try {
    // Read file buffer and get extension
    const fileBuffer = await fs.readFile(filePath);
    const fileExtension = path.extname(filePath).toLowerCase();

    // Convert buffer to different string formats for content checking
    const fileContent = fileBuffer.toString();
    const base64Content = fileBuffer.toString("base64");
    const decodedContent = Buffer.from(base64Content, "base64").toString(
      "utf8"
    );

    // Patterns that might indicate malicious content
    const suspiciousPatterns = [
      /<script/i, // Scripting tags
      /javascript:/i, // JavaScript protocol
      /<\?php/i, // PHP code
      /eval\(/i, // JavaScript eval
      /exec\(/i, // Command execution
      /system\(/i, // System commands
      /function\s*\(/i, // Function declarations
      /setTimeout/i, // JavaScript timing functions
      /setInterval/i, // JavaScript timing functions
      /onload/i, // Event handlers
      /onerror/i, // Error handlers
      /ActiveXObject/i, // ActiveX objects
    ];

    // Validate file signatures based on extension
    let isValidSignature = false;
    switch (fileExtension) {
      case ".jpg":
      case ".jpeg":
        isValidSignature = checkFileSignature(fileBuffer, FILE_SIGNATURES.JPEG);
        break;

      case ".png":
        isValidSignature = checkFileSignature(fileBuffer, FILE_SIGNATURES.PNG);
        break;

      case ".gif":
        isValidSignature = checkFileSignature(fileBuffer, FILE_SIGNATURES.GIF);
        break;

      case ".svg":
        isValidSignature = checkFileSignature(fileBuffer, FILE_SIGNATURES.SVG);

        // SVG validation
        const hasSVGTag = /<svg[^>]*>/i.test(fileContent);
        const hasValidXML =
          fileContent.trim().startsWith("<?xml") ||
          fileContent.trim().startsWith("<svg");
        isValidSignature = isValidSignature || (hasSVGTag && hasValidXML);
        break;

      case ".pdf":
        isValidSignature = checkFileSignature(fileBuffer, FILE_SIGNATURES.PDF);

        // PDF validation
        const hasPDFSignature = fileContent.includes("%PDF-");
        const hasEOFMarker = fileContent.includes("%%EOF");
        isValidSignature = isValidSignature && hasPDFSignature && hasEOFMarker;
        break;

      default:
        return {
          status: false,
          message: "Unsupported file type",
        };
    }

    // Check if file signature is valid
    if (!isValidSignature) {
      return {
        status: false,
        message: "Invalid file signature detected",
      };
    }

    // Check for suspicious patterns in content
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(decodedContent) || pattern.test(fileContent)) {
        return {
          status: false,
          message: `Suspicious pattern detected: ${pattern}`,
        };
      }
    }

    // SVG-specific security checks
    if (fileExtension === ".svg") {
      const svgSuspiciousPatterns = [
        /xlink:href/i, // External references
        /[^a-z]href=/i, // Hyperlinks
        /data:/i, // Data URLs
        /import/i, // Import statements
        /foreignObject/i, // Foreign objects
        /onload/i, // Event handlers
        /onclick/i, // Click handlers
        /onmouseover/i, // Mouse event handlers
        /<!ENTITY/i, // XML entities
        /<!DOCTYPE/i, // DOCTYPE declarations
      ];

      for (const pattern of svgSuspiciousPatterns) {
        if (pattern.test(fileContent)) {
          return {
            status: false,
            message: `Suspicious SVG pattern detected: ${pattern}`,
          };
        }
      }
    }

    // PDF-specific security checks: name tokens in the body and inflated streams.
    // Metadata / Annots / OpenAction are allowed by default. See #1, #3, #4.
    if (fileExtension === ".pdf") {
      const pdfResult = inspectPdfTokens(fileBuffer, options);
      if (pdfResult) return pdfResult;
    }

    return {
      status: true,
      message: "Content validation passed",
    };
  } catch (error) {
    return {
      status: false,
      message: `Content validation failed: ${error.message}`,
    };
  }
};

/**
 * Main file validation function that checks file existence, size, extension, and content.
 *
 * @param {string} filePath - Path of file to validate
 * @param {Object} options - Validation options
 * @param {number} [options.maxSizeInBytes=5242880] - Maximum file size in bytes (default: 5MB)
 * @param {Array<string>} [options.pdfWhitelist=[]] - Array of PDF patterns to whitelist (e.g., ['Metadata', 'OpenAction'])
 * @returns {Promise<Object>} Object containing status (boolean) and message (string)
 */
const validateFile = async (filePath, options = {}) => {
  try {
    // Default size limit: 5MB
    const DEFAULT_MAX_SIZE = 5 * 1024 * 1024;
    const maxSizeInBytes = options.maxSizeInBytes ?? DEFAULT_MAX_SIZE;

    // Check if file exists
    const stats = await fs.stat(filePath);

    // Check file size with configurable limit
    if (stats.size > maxSizeInBytes) {
      const sizeMB = Math.round(maxSizeInBytes / (1024 * 1024));
      return {
        status: false,
        message: `File size exceeds limit of ${sizeMB}MB`,
      };
    }

    // Rest of the validation code remains the same...
    const allowedExtensions = [".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg"];
    const fileExtension = path.extname(filePath).toLowerCase();
    if (!allowedExtensions.includes(fileExtension)) {
      return {
        status: false,
        message: "Invalid file extension",
      };
    }

    const contentValidation = await validateFileContent(filePath, options);
    return contentValidation;
  } catch (error) {
    return {
      status: false,
      message: `File validation failed: ${error.message}`,
    };
  }
};

export { validateFile, validateFileContent, checkFileSignature };
