import zlib from "node:zlib";

const PDF_NAME_RE = /\/([A-Za-z0-9_.+#\-]+)/g;
const PDF_DEFAULT_POLICY = {
  allowMetadata: true,
  allowAnnots: true,
  allowOpenAction: true,
  allowJavaScript: false,
  allowLaunch: false,
  allowEmbeddedFile: false,
  allowXfa: false,
  allowRichMedia: false,
};
const PDF_TOKEN_FLAG = {
  JavaScript: "allowJavaScript",
  JS: "allowJavaScript",
  Launch: "allowLaunch",
  EmbeddedFile: "allowEmbeddedFile",
  XFA: "allowXfa",
  RichMedia: "allowRichMedia",
  OpenAction: "allowOpenAction",
  Annots: "allowAnnots",
  Metadata: "allowMetadata",
};
const PDF_WHITELIST_ALIAS = {
  Metadata: "allowMetadata",
  Annots: "allowAnnots",
  OpenAction: "allowOpenAction",
  JS: "allowJavaScript",
  JavaScript: "allowJavaScript",
  Launch: "allowLaunch",
  EmbeddedFile: "allowEmbeddedFile",
  XFA: "allowXfa",
  RichMedia: "allowRichMedia",
};
const PDF_TOKEN_CHECK_ORDER = [
  "JavaScript",
  "JS",
  "Launch",
  "EmbeddedFile",
  "XFA",
  "RichMedia",
  "OpenAction",
  "Annots",
  "Metadata",
];

const decodePdfName = (raw) =>
  raw.replace(/#([0-9A-Fa-f]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

const collectPdfNamesFromString = (text, names) => {
  PDF_NAME_RE.lastIndex = 0;
  let match;
  while ((match = PDF_NAME_RE.exec(text))) {
    names.add(decodePdfName(match[1]));
  }
};

const stripStreamWrappers = (payload) => {
  if (
    payload.length >= 2 &&
    payload[payload.length - 2] === 0x0d &&
    payload[payload.length - 1] === 0x0a
  ) {
    return payload.subarray(0, payload.length - 2);
  }
  if (
    payload.length >= 1 &&
    (payload[payload.length - 1] === 0x0a ||
      payload[payload.length - 1] === 0x0d)
  ) {
    return payload.subarray(0, payload.length - 1);
  }
  return payload;
};

const tryInflate = (payload) => {
  try {
    return zlib.inflateSync(payload);
  } catch {
    try {
      return zlib.inflateRawSync(payload);
    } catch {
      return null;
    }
  }
};

const inflatePdfStreams = (buffer) => {
  const texts = [];
  let idx = 0;

  while (idx < buffer.length) {
    const start = buffer.indexOf("stream", idx);
    if (start === -1) break;

    let payloadStart = start + 6;
    if (buffer[payloadStart] === 0x0d && buffer[payloadStart + 1] === 0x0a) {
      payloadStart += 2;
    } else if (buffer[payloadStart] === 0x0a || buffer[payloadStart] === 0x0d) {
      payloadStart += 1;
    }

    const end = buffer.indexOf("endstream", payloadStart);
    if (end === -1) break;

    const inflated = tryInflate(
      stripStreamWrappers(buffer.subarray(payloadStart, end))
    );
    if (inflated) {
      texts.push(inflated.toString("latin1"));
    }
    idx = end + 9;
  }

  return texts;
};

const collectPdfNames = (buffer) => {
  const names = new Set();
  collectPdfNamesFromString(buffer.toString("latin1"), names);
  for (const inflated of inflatePdfStreams(buffer)) {
    collectPdfNamesFromString(inflated, names);
  }
  return names;
};

const resolvePdfPolicy = (options = {}) => {
  const policy = { ...PDF_DEFAULT_POLICY };
  const overrides = options.pdf;

  if (overrides && typeof overrides === "object") {
    for (const key of Object.keys(PDF_DEFAULT_POLICY)) {
      if (typeof overrides[key] === "boolean") {
        policy[key] = overrides[key];
      }
    }
  }

  for (const name of options.pdfWhitelist || []) {
    const flag = PDF_WHITELIST_ALIAS[name];
    if (flag) policy[flag] = true;
  }

  return policy;
};

export const inspectPdfTokens = (buffer, options = {}) => {
  const policy = resolvePdfPolicy(options);
  const names = collectPdfNames(buffer);

  for (const name of PDF_TOKEN_CHECK_ORDER) {
    if (!names.has(name)) continue;
    const flag = PDF_TOKEN_FLAG[name];
    if (policy[flag]) continue;
    return {
      status: false,
      message: `Suspicious PDF name token detected: /${name}`,
    };
  }

  return null;
};
