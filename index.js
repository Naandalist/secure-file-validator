/**
 * File signatures based on file format specification
 * Reference: https://en.wikipedia.org/wiki/List_of_file_signatures
 */
export const FILE_SIGNATURES = {
    // Image formats
    'jpeg': [
        // Standard JPEG/JFIF
        [255, 216, 255, 224],
        // JPEG with EXIF
        [255, 216, 255, 225],
        // SPIFF JPEG
        [255, 216, 255, 232],
        // JPEG-LS
        [255, 216, 255, 238]
    ],
    'png': [
        // Standard PNG signature
        [137, 80, 78, 71, 13, 10, 26, 10]
    ],
    'gif': [
        // GIF87a format
        [71, 73, 70, 56, 55, 97],
        // GIF89a format
        [71, 73, 70, 56, 57, 97]
    ],
    // Document formats
    'pdf': [
        // Standard PDF signature
        [37, 80, 68, 70, 45] // %PDF-
    ],
    // Archive formats
    'zip': [
        // Standard ZIP signature
        [80, 75, 3, 4]
    ],
    // Additional security patterns to check
    SUSPICIOUS_PATTERNS: [
        /<script/i,
        /javascript:/i,
        /<\?php/i,
        /eval\(/i,
        /exec\(/i,
        /system\(/i,
        /function\s*\(/i,
        /setTimeout/i,
        /setInterval/i
    ]
};

/**
 * Compare a buffer with expected file signature
 * @param {Buffer} buffer - File buffer to check
 * @param {Array} signature - Expected signature pattern
 * @returns {boolean} - What is signature match?
 */
export const compareSignature = (buffer, signature) => {
    if (buffer.length < signature.length) return false;
    return signature.every((byte, index) => buffer[index] === byte);
};

/**
 * Check if a buffer matches a specific file type signature
 * @param {Buffer} buffer - File buffer to check
 * @param {string} type - File type to check against
 * @returns {boolean} - What is file match the type?
 */
export const matchesFileType = (buffer, type) => {
    const signatures = FILE_SIGNATURES[type];
    if (!signatures) throw new Error(`Unsupported file type: ${type}`);
    return signatures.some(sig => compareSignature(buffer, sig));
};

/**
 * Validate file content for identify suspicious pattern
 * @param {Buffer} buffer - File buffer to check
 * @returns {Object} - Validation result with status and message
 */
export const validateFileContent = (buffer) => {
    try {
        const content = buffer.toString();
        const base64Content = buffer.toString('base64');
        const decodedContent = Buffer.from(base64Content, 'base64').toString('utf8');

        // Check for suspicious patterns
        for (const pattern of FILE_SIGNATURES.SUSPICIOUS_PATTERNS) {
            if (pattern.test(content) || pattern.test(decodedContent)) {
                return {
                    status: false,
                    message: `Suspicious pattern detected: ${pattern}`
                };
            }
        }

        return {
            status: true,
            message: 'Content validation passed'
        };
    } catch (error) {
        return {
            status: false,
            message: `Content validation failed: ${error.message}`
        };
    }
};

/**
 * File validation including type checking and content validation
 * @param {Buffer} buffer - File buffer to validate
 * @param {string} expectedType - Expected file type
 * @param {Object} options - Validation options
 * @returns {Object} - Validation result
 */
export const validateFile = (buffer, expectedType, options = {}) => {
    const {
        maxSize = 5 * 1024 * 1024, // Default 5MB
        checkContent = true
    } = options;

    try {
        // Check file size
        if (buffer.length > maxSize) {
            return {
                status: false,
                message: 'File size exceeds limit'
            };
        }

        // Check file signature
        if (!matchesFileType(buffer, expectedType)) {
            return {
                status: false,
                message: `Invalid file signature for type: ${expectedType}`
            };
        }

        // Validate content if required
        if (checkContent) {
            const contentValidation = validateFileContent(buffer);
            if (!contentValidation.status) {
                return contentValidation;
            }
        }

        return {
            status: true,
            message: 'File validation passed'
        };
    } catch (error) {
        return {
            status: false,
            message: `Validation failed: ${error.message}`
        };
    }
};

/**
 * Get supported file types
 * @returns {Array} - List of supported file types
 */
export const getSupportedTypes = () => {
    return Object.keys(FILE_SIGNATURES).filter(key => key !== 'SUSPICIOUS_PATTERNS');
};