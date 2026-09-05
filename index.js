import { promises as fs } from "fs";
import path from "path";
import { inspectPdfTokens } from "./pdf-policy.js";

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

/**
 * Validates content of a file by checking its signature and scanning for suspicious patterns.
 *
 * @param {string} filePath - Path to the file to validate
 * @param {Object} options - Validation options
 * @returns {Promise<Object>} Object containing status (boolean) and message (string)
 */
const validateFileContent = async (filePath, options = {}) => {
  try {
    const fileBuffer = await fs.readFile(filePath);
    const fileExtension = path.extname(filePath).toLowerCase();
    const fileContent = fileBuffer.toString();
    const decodedContent = fileContent;

    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /<\?php/i,
      /eval\(/i,
      /exec\(/i,
      /system\(/i,
      /function\s*\(/i,
      /setTimeout/i,
      /setInterval/i,
      /onload/i,
      /onerror/i,
      /ActiveXObject/i,
    ];

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
        const hasSVGTag = /<svg[^>]*>/i.test(fileContent);
        const hasValidXML =
          fileContent.trim().startsWith("<?xml") ||
          fileContent.trim().startsWith("<svg");
        isValidSignature = isValidSignature || (hasSVGTag && hasValidXML);
        break;
      case ".pdf":
        isValidSignature = checkFileSignature(fileBuffer, FILE_SIGNATURES.PDF);
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

    if (!isValidSignature) {
      return {
        status: false,
        message: "Invalid file signature detected",
      };
    }

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(decodedContent) || pattern.test(fileContent)) {
        return {
          status: false,
          message: `Suspicious pattern detected: ${pattern}`,
        };
      }
    }

    if (fileExtension === ".svg") {
      const svgSuspiciousPatterns = [
        /xlink:href/i,
        /[^a-z]href=/i,
        /data:/i,
        /import/i,
        /foreignObject/i,
        /onload/i,
        /onclick/i,
        /onmouseover/i,
        /<!ENTITY/i,
        /<!DOCTYPE/i,
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

const validateFile = async (filePath, options = {}) => {
  try {
    const DEFAULT_MAX_SIZE = 5 * 1024 * 1024;
    const maxSizeInBytes = options.maxSizeInBytes ?? DEFAULT_MAX_SIZE;
    const stats = await fs.stat(filePath);

    if (stats.size > maxSizeInBytes) {
      const sizeMB = Math.round(maxSizeInBytes / (1024 * 1024));
      return {
        status: false,
        message: `File size exceeds limit of ${sizeMB}MB`,
      };
    }

    const allowedExtensions = [".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg"];
    const fileExtension = path.extname(filePath).toLowerCase();
    if (!allowedExtensions.includes(fileExtension)) {
      return {
        status: false,
        message: "Invalid file extension",
      };
    }

    return validateFileContent(filePath, options);
  } catch (error) {
    return {
      status: false,
      message: `File validation failed: ${error.message}`,
    };
  }
};

export { validateFile, validateFileContent, checkFileSignature };
