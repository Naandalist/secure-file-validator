import { promises as fs } from "fs";
import path from "path";
import { inspectPdfTokens } from "./pdf-policy.js";
import { inspectSvg } from "./svg-policy.js";

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

const checkFileSignature = (buffer, signatures) => {
  return signatures.some((signature) => {
    return signature.every((byte, index) => buffer[index] === byte);
  });
};

const validateFileContent = async (filePath, options = {}) => {
  try {
    const fileBuffer = await fs.readFile(filePath);
    const fileExtension = path.extname(filePath).toLowerCase();
    const fileContent = fileBuffer.toString();

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
        return { status: false, message: "Unsupported file type" };
    }

    if (!isValidSignature) {
      return { status: false, message: "Invalid file signature detected" };
    }

    if (fileExtension === ".svg") {
      const svgResult = inspectSvg(fileContent, options);
      if (svgResult) return svgResult;
    }

    if (fileExtension === ".pdf") {
      const pdfResult = inspectPdfTokens(fileBuffer, options);
      if (pdfResult) return pdfResult;
    }

    return { status: true, message: "Content validation passed" };
  } catch (error) {
    return { status: false, message: `Content validation failed: ${error.message}` };
  }
};

const validateFile = async (filePath, options = {}) => {
  try {
    const DEFAULT_MAX_SIZE = 5 * 1024 * 1024;
    const maxSizeInBytes = options.maxSizeInBytes ?? DEFAULT_MAX_SIZE;
    const stats = await fs.stat(filePath);

    if (stats.size > maxSizeInBytes) {
      const sizeMB = Math.round(maxSizeInBytes / (1024 * 1024));
      return { status: false, message: `File size exceeds limit of ${sizeMB}MB` };
    }

    const allowedExtensions = [".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg"];
    const fileExtension = path.extname(filePath).toLowerCase();
    if (!allowedExtensions.includes(fileExtension)) {
      return { status: false, message: "Invalid file extension" };
    }

    return validateFileContent(filePath, options);
  } catch (error) {
    return { status: false, message: `File validation failed: ${error.message}` };
  }
};

export { validateFile, validateFileContent, checkFileSignature };
