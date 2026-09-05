/**
 * Structured PDF token policy.
 * Defaults allow Metadata / Annots / OpenAction and deny script, launch,
 * embedded-file, XFA, and RichMedia tokens.
 */
export interface PdfPolicy {
  allowMetadata?: boolean;
  allowAnnots?: boolean;
  allowOpenAction?: boolean;
  /** Covers both `/JS` and `/JavaScript`. */
  allowJavaScript?: boolean;
  allowLaunch?: boolean;
  allowEmbeddedFile?: boolean;
  allowXfa?: boolean;
  allowRichMedia?: boolean;
}

/**
 * Options for file validation
 */
export interface ValidateFileOptions {
  maxSizeInBytes?: number;
  pdf?: PdfPolicy;
  /**
   * @deprecated Use `pdf` instead. Listed names are mapped to allow* flags.
   * `JS` and `JavaScript` both set `allowJavaScript`.
   */
  pdfWhitelist?: string[];
}

/**
 * Validation result object
 */
export interface ValidationResult {
  status: boolean;
  message: string;
}

/**
 * Validates a file with optional configuration
 * @param filePath - Path to the file to validate
 * @param options - Optional configuration object
 * @returns Promise resolving to validation result
 */
export function validateFile(
  filePath: string,
  options?: ValidateFileOptions
): Promise<ValidationResult>;

/**
 * Validates file content
 * @param filePath - Path to the file to validate
 * @param options - Optional configuration object
 * @returns Promise resolving to validation result
 */
export function validateFileContent(
  filePath: string,
  options?: ValidateFileOptions
): Promise<ValidationResult>;

/**
 * Checks file signature against known signatures
 * @param buffer - File buffer to check
 * @param signatures - Array of valid signatures
 * @returns Boolean indicating if signature matches
 */
export function checkFileSignature(
  buffer: Buffer,
  signatures: number[][]
): boolean;
