# Starter: parser and decoder library

Status: draft for comment. Replace the bracketed parts.

## Starter text

The bullets under "What we do not consider a vulnerability" are starting defaults for the maintainer to edit. They rest on few or no rows (see Basis and Limits).

```markdown
## Security model

[Project] is a parser and decoder library. It reads [formats] and turns them into [what it returns].

### What we treat as untrusted

The contents of any file or data you pass to [project]. We assume it may have been crafted by an attacker, even if your application got it from somewhere you trust. Reading it should never:

- read or write memory out of bounds, or crash the process
- hang, recurse without limit, or allocate memory far beyond the size of the input
- reach outside the input, for example by fetching URLs, resolving external entities or reading local files
- change objects or settings outside the parsed result

If [project] reads formats that can carry code, such as pickled objects or YAML tags, loading a file should not run that code unless you have turned it on. [Safe option] is on by default.

### What we treat as trusted

- Which file you open and where it comes from on disk.
- The options you set, including raising or removing our limits, or turning off a safe default.
- What your application does with the result.

### What we do not consider a vulnerability

- Problems that only happen after you turn off a safe default or raise a limit.
- Problems that need an attacker to control your options or the file path.

[Optional] Adapted from the security model starter, version [X], [link].
```

## Basis

From the 22 library rows with file or config input that parse, decode or load files (`docs/security-model/draft-outline.md` lists the rows). No pushback was recorded; the field is only filled when a discussion thread is visible, and 1 of 694 rows has one. 13 of the 22 fixes added a test.

| Starter line | Rows | Examples |
|---|---|---|
| Memory out of bounds or crash | 7 | Pillow TIFF and JPEG (149, 229), LIEF Mach-O (144, 257), iText (278), bundled libwebp (216), kin-openapi nil ref (488) |
| Hang, recursion or allocation | 6 | Pillow PDF (156, 203), pypdf outlines (217), JSONReader nesting (161), imagemeta EXIF (400), excelize rows (467) |
| Reaching outside the input | 4 | Batik SVG URLs (273), CoreNLP XXE (308, 313), MPXJ XXE (789) |
| Changing objects outside the result | 1 | protobufjs option paths (103) |
| Code in the file runs on load | 4 | keras safe_mode (223), keras HDF5 local files (234), pyarrow pickle (230), parlai yaml.load (772) |

The 18 parser rows split 7, 6, 4 and 1 across the first four lines. The grouping into starter lines is a hand sort of the 22 listed rows (18 parser, 4 model and data loader), not a labeled field. It stands until library_role is labeled.

Trusted input and non-bugs are not measured directly, since pushback was not observed. They follow from what the fixes did: they set safe defaults (Pillow nesting limit 900, pyarrow auto-loading off, secure XML parser factories, keras fail closed) and left the option in the caller's hands.

## Limits

- Built from file input only. Decoders of network or caller data (XML and JSON parsers, protocol decoders, deserializers, decompressors) likely share this boundary but are not measured yet.
- Pillow is 4 of the 22 rows.
- Limits shared by all starters are in `docs/security-model/README.md`.
