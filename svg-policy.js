const ALWAYS_DENY = [
  { pattern: /<script[\s>]/i, message: "Suspicious SVG pattern detected: script" },
  { pattern: /javascript:/i, message: "Suspicious SVG pattern detected: javascript URI" },
  { pattern: /\son[a-z]+\s*=/i, message: "Suspicious SVG pattern detected: event handler" },
  { pattern: /<!ENTITY/i, message: "Suspicious SVG pattern detected: ENTITY" },
];

const DEFAULT_DENY = [
  { pattern: /<foreignObject[\s>]/i, flag: "allowForeignObject", message: "Suspicious SVG pattern detected: foreignObject" },
  { pattern: /\bdata:/i, flag: "allowDataUri", message: "Suspicious SVG pattern detected: data URI" },
];

const EXTERNAL_HREF = /\b(?:xlink:)?href\s*=\s*["'](?!#|$)([^"']+)["']/i;

const resolveSvgPolicy = (options = {}) => ({
  allowForeignObject: false,
  allowDataUri: false,
  allowExternalHref: false,
  ...(options.svg && typeof options.svg === "object" ? options.svg : {}),
});

export const inspectSvg = (fileContent, options = {}) => {
  const policy = resolveSvgPolicy(options);

  for (const rule of ALWAYS_DENY) {
    if (rule.pattern.test(fileContent)) {
      return { status: false, message: rule.message };
    }
  }

  for (const rule of DEFAULT_DENY) {
    if (policy[rule.flag]) continue;
    if (rule.pattern.test(fileContent)) {
      return { status: false, message: rule.message };
    }
  }

  if (!policy.allowExternalHref && EXTERNAL_HREF.test(fileContent)) {
    return { status: false, message: "Suspicious SVG pattern detected: external href" };
  }

  return null;
};
