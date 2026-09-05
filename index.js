import { promises as fs } from "fs";
import path from "path";
import { inspectPdfTokens } from "./pdf-policy.js";
import { inspectSvg } from "./svg-policy.js";

const DEFAULT_MAX_SIZE = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg"];

const FILE_SIGNATURES = {
  JPEG: [[0xff, 0xd8, 0xff]],
  PNG: [[0x89, 0x50, 0x4e, 0x47]],
  GIF: [[0x47, 0x49, 0x46, 0x38]],
  PDF: [[0x25, 0x50, 0x44, 0x46]],
  SVG: [
    [0x3c, 0x3f, 0x78, 0x6d, 0x6c],
    [0x3c, 0x73, 0x76, 0x67],
  ],
};

const result = (ok, code, message, details) => ({
  ok,
  status: ok,
  code,
  message,
  ...(details ? { details } : {}),
});

const checkFileSignature = (buffer, signatures) => {
  return signatures.some((signature) => {
    return signature.every((byte, index) => buffer[index] === byte);
  });
};

const toBuffer = (input) => {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  return null;
};

const normalizeExtension = (value) => {
  if (!value) return "";
  const lower = String(value).toLowerCase();
  return lower.startsWith(".") ? lower : `.${lower}`;
};

const resolveExtension = (input, options = {}) => {
  if (typeof input === "string") {
    return path.extname(input).toLowerCase();
  }
  if (options.extension) return normalizeExtension(options.extension);
  if (options.filename) return path.extname(options.filename).toLowerCase();
  return "";
};

const inspectSignature = (fileBuffer, fileExtension) => {
  const fileContent = fileBuffer.toString();

  switch (fileExtension) {
    case ".jpg":
    case ".jpeg":
      return checkFileSignature(fileBuffer, FILE_SIGNATURES.JPEG);
    case ".png":
      return checkFileSignature(fileBuffer, FILE_SIGNATURES.PNG);
    case ".gif":
      return checkFileSignature(fileBuffer, FILE_SIGNATURES.GIF);
    case ".svg": {
      const headerOk = checkFileSignature(fileBuffer, FILE_SIGNATURES.SVG);
      const hasSVGTag = /<svg[^>]*>/i.test(fileContent);
      const hasValidXML =
        fileContent.trim().startsWith("<?xml") ||
        fileContent.trim().startsWith("<svg");
      return headerOk || (hasSVGTag && hasValidXML);
    }
    case ".pdf":
      return (
        checkFileSignature(fileBuffer, FILE_SIGNATURES.PDF) &&
        fileContent.includes("%PDF-") &&
        fileContent.includes("%%EOF")
      );
    default:
      return null;
  }
};

const validateBytes = (input, options = {}) => {
  const fileBuffer = toBuffer(input);
  if (!fileBuffer) {
    return result(false, "IO_ERROR", "Expected a Buffer or Uint8Array");
  }

  const maxSizeInBytes = options.maxSizeInBytes ?? DEFAULT_MAX_SIZE;
  if (fileBuffer.byteLength > maxSizeInBytes) {
    const sizeMB = Math.round(maxSizeInBytes / (1024 * 1024));
    return result(false, "TOO_LARGE", `File size exceeds limit of ${sizeMB}MB`, {
      maxSizeInBytes,
      size: fileBuffer.byteLength,
    });
  }

  const fileExtension = resolveExtension(null, options);
  if (!fileExtension) {
    return result(
      false,
      "INVALID_EXTENSION",
      "Missing filename or extension for in-memory input"
    );
  }
  if (!ALLOWED_EXTENSIONS.includes(fileExtension)) {
    return result(false, "UNSUPPORTED_TYPE", "Unsupported file type", {
      extension: fileExtension,
    });
  }

  const signatureOk = inspectSignature(fileBuffer, fileExtension);
  if (!signatureOk) {
    return result(false, "INVALID_SIGNATURE", "Invalid file signature detected");
  }

  if (fileExtension === ".svg") {
    const svgResult = inspectSvg(fileBuffer.toString(), options);
    if (svgResult) return svgResult;
  }

  if (fileExtension === ".pdf") {
    const pdfResult = inspectPdfTokens(fileBuffer, options);
    if (pdfResult) return pdfResult;
  }

  return result(true, "OK", "Content validation passed");
};

const validateFileContent = async (input, options = {}) => {
  try {
    if (typeof input !== "string") {
      return validateBytes(input, options);
    }

    const fileBuffer = await fs.readFile(input);
    return validateBytes(fileBuffer, {
      ...options,
      filename: options.filename || input,
      extension: options.extension || path.extname(input),
    });
  } catch (error) {
    return result(false, "IO_ERROR", `Content validation failed: ${error.message}`);
  }
};

const validateFile = async (input, options = {}) => {
  try {
    if (typeof input !== "string") {
      return validateBytes(input, options);
    }

    const maxSizeInBytes = options.maxSizeInBytes ?? DEFAULT_MAX_SIZE;
    const stats = await fs.stat(input);
    if (stats.size > maxSizeInBytes) {
      const sizeMB = Math.round(maxSizeInBytes / (1024 * 1024));
      return result(false, "TOO_LARGE", `File size exceeds limit of ${sizeMB}MB`, {
        maxSizeInBytes,
        size: stats.size,
      });
    }

    const fileExtension = resolveExtension(input, options);
    if (!ALLOWED_EXTENSIONS.includes(fileExtension)) {
      return result(false, "INVALID_EXTENSION", "Invalid file extension", {
        extension: fileExtension,
      });
    }

    return validateFileContent(input, options);
  } catch (error) {
    return result(false, "IO_ERROR", `File validation failed: ${error.message}`);
  }
};

export {
  validateFile,
  validateFileContent,
  validateBytes,
  checkFileSignature,
};
