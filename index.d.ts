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

export interface SvgPolicy {
  allowForeignObject?: boolean;
  allowDataUri?: boolean;
  allowExternalHref?: boolean;
}

export interface ValidateFileOptions {
  maxSizeInBytes?: number;
  pdf?: PdfPolicy;
  svg?: SvgPolicy;
  /**
   * @deprecated Use `pdf` instead. Listed names are mapped to allow* flags.
   * `JS` and `JavaScript` both set `allowJavaScript`.
   */
  pdfWhitelist?: string[];
}

export interface ValidationResult {
  status: boolean;
  message: string;
}

export function validateFile(
  filePath: string,
  options?: ValidateFileOptions
): Promise<ValidationResult>;

export function validateFileContent(
  filePath: string,
  options?: ValidateFileOptions
): Promise<ValidationResult>;

export function checkFileSignature(
  buffer: Buffer,
  signatures: number[][]
): boolean;
