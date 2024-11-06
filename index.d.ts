/**
 * Options for file validation
 */
export interface ValidateFileOptions {
  maxSizeInBytes?: number;
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
 * @returns Promise resolving to validation result
 */
export function validateFileContent(
  filePath: string
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
