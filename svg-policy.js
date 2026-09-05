const fail = (code, message, details) => ({
  ok: false,
  status: false,
  code,
  message,
  ...(details ? { details } : {}),
});

const ALWAYS_DENY = [
  { pattern: /<script[\s>]/i, code: "SVG_SCRIPT", message: "Suspicious SVG pattern detected: script" },
  { pattern: /javascript:/i, code: "SVG_SCRIPT", message: "Suspicious SVG pattern detected: javascript URI" },
  { pattern: /\son[a-z]+\s*=/i, code: "SVG_EVENT_HANDLER", message: "Suspicious SVG pattern detected: event handler" },
  { pattern: /<!ENTITY/i, code: "SVG_XXE", message: "Suspicious SVG pattern detected: ENTITY" },
];

const DEFAULT_DENY = [
  { pattern: /<foreignObject[\s>]/i, flag: "allowForeignObject", code: "SVG_FOREIGN_OBJECT", message: "Suspicious SVG pattern detected: foreignObject" },
  { pattern: /\bdata:/i, flag: "allowDataUri", code: "SVG_DATA_URI", message: "Suspicious SVG pattern detected: data URI" },
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
      return fail(rule.code, rule.message);
    }
  }

  for (const rule of DEFAULT_DENY) {
    if (policy[rule.flag]) continue;
    if (rule.pattern.test(fileContent)) {
      return fail(rule.code, rule.message);
    }
  }

  if (!policy.allowExternalHref && EXTERNAL_HREF.test(fileContent)) {
    return fail("SVG_EXTERNAL_HREF", "Suspicious SVG pattern detected: external href");
  }

  return null;
};
