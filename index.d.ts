export type ValidationCode =
  | "OK"
  | "UNSUPPORTED_TYPE"
  | "INVALID_EXTENSION"
  | "TOO_LARGE"
  | "INVALID_SIGNATURE"
  | "PDF_JAVASCRIPT"
  | "PDF_LAUNCH"
  | "PDF_EMBEDDED_FILE"
  | "PDF_XFA"
  | "PDF_RICH_MEDIA"
  | "PDF_OPEN_ACTION"
  | "PDF_ANNOTS"
  | "PDF_METADATA"
  | "PDF_TOKEN"
  | "SVG_SCRIPT"
  | "SVG_EVENT_HANDLER"
  | "SVG_XXE"
  | "SVG_FOREIGN_OBJECT"
  | "SVG_DATA_URI"
  | "SVG_EXTERNAL_HREF"
  | "IO_ERROR";

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
  filename?: string;
  extension?: string;
  pdf?: PdfPolicy;
  svg?: SvgPolicy;
  /**
   * @deprecated Use `pdf` instead. Listed names are mapped to allow* flags.
   * `JS` and `JavaScript` both set `allowJavaScript`.
   */
  pdfWhitelist?: string[];
}

export interface ValidationResult {
  ok: boolean;
  /** @deprecated Use `ok`. Kept as an alias. */
  status: boolean;
  code: ValidationCode;
  message: string;
  details?: Record<string, unknown>;
}

export type FileInput = string | Buffer | Uint8Array;

export function validateFile(
  input: FileInput,
  options?: ValidateFileOptions
): Promise<ValidationResult>;

export function validateFileContent(
  input: FileInput,
  options?: ValidateFileOptions
): Promise<ValidationResult>;

export function validateBytes(
  bytes: Buffer | Uint8Array,
  options?: ValidateFileOptions
): ValidationResult;

export function checkFileSignature(
  buffer: Buffer,
  signatures: number[][]
): boolean;
