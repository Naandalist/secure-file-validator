# Changelog

## Unreleased (2.x)

### Breaking / notable

- Results are `{ ok, code, message, details? }`. `status` remains as a deprecated alias of `ok`.
- `validateFile` accepts a path, `Buffer`, or `Uint8Array`. Buffer input needs `filename` or `extension`.
- New sync helper: `validateBytes`.

### PDF false positives ([#1](https://github.com/Naandalist/secure-file-validator/issues/1))

- Replaced substring regexes (`/JS/`, `/Metadata/`, `/OpenAction/`) with PDF name-token detection, including `#HH` escapes and inflated Flate streams.
- Default policy allows `/Metadata`, `/Annots`, and `/OpenAction`.
- Default policy still denies `/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFile`, `/XFA`, `/RichMedia`.
- New structured option: `options.pdf.allowJavaScript` (covers both `/JS` and `/JavaScript`).
- `pdfWhitelist` is deprecated and mapped onto those flags.

Do not whitelist `JS` to silence a metadata hit. That case now passes with no options.

### Other

- JPEG accepted on SOI `FF D8 FF` (not only JFIF/Exif).
- Raster images are no longer scanned for HTML/JS substrings.
- SVG policy no longer flags a bare `DOCTYPE` or fragment `href="#id"`.
- README threat model is scoped to file-type checks, not full OWASP/NIST coverage.
