# Security model starter text: draft outline

Status: draft for comment. Open decisions are listed at the end.

## Goal

A short security model section that a maintainer can drop into SECURITY.md, with starter text for each library type. Each starter says what the project treats as untrusted, what it treats as the caller's responsibility, and what it does not consider a vulnerability. The starters are backed by the labeled advisory data in `results/`.

## Prior art

- Apache asks projects to document their security model, for example in SECURITY.md.
- Chromium's SECURITY.md guidelines cover boundaries, threat assumptions and explicit non-bugs per component.
- The CNCF vulnerability reporting recipe lists a threat model or accepted vulnerability bar.
- An OpenSSF disclosures WG thread (wg-vulnerability-disclosures #95) suggested giving maintainers a closed list of what counts, since most will not know what to write.

These ask for a security model. None gives ready text per library type grounded in what maintainers actually accepted.

## Structure, same for each type

1. What this project is. One line naming the type.
2. Untrusted input. What the project defends against.
3. Trusted input. What is the caller's responsibility, such as compiler options, nonces and app configuration.
4. Not vulnerabilities. Explicit non-bugs, such as a setting that only fails when the app misconfigures it.
5. Attribution, optional. One line naming the starter, its version and a link, with no data. Evidence stays on the page that hosts the starters.

## Starters suggested by the data

Counts are from the 380 in-scope AI labels (`results/crosstab_v1_input_source.csv`), with the reviewer reading from `docs/findings/documented-job-split.md` where it differs.

- Library. Strings the function is documented to parse, such as ranges, patterns, key paths and names passed to the operating system, may come from end users. End-user via caller is the largest source for libraries (120 of 225 library rows under the reviewer reading; npm libraries 51 of 63).
- Framework. All network input is untrusted. App configuration is trusted. Network is the main source for frameworks in every ecosystem (Maven 35 of 39).
- Tool. Files and config the tool reads, and content it fetches or serves, may be supplied by an attacker. Tool rows split between file or config (29 of 60) and network (22). File or config leads clearly only for Go (17 of 27).
- Parser and decoder library. The contents of files the library parses or decodes are untrusted. 18 of the 37 library rows with file or config input, from 13 packages (rows 103, 144, 149, 156, 161, 203, 216, 217, 229, 257, 273, 278, 308, 313, 400, 467, 488, 789). Pillow alone is 4 rows. Fixes: validation added 10, internal hardening 6, other 1, fix not readable 1. Includes a short note for model and data loaders that can run code (rows 223, 230, 234, 772; 3 packages, all PyPI), too few for a type of their own.
- Archive and file-tree extractor library. Entry names inside an archive or a fetched tree are untrusted; the target directory is the caller's. 11 rows, 11 packages: 6 with file or config input (215, 477, 563, 572, 639, 650) and 5 with network input (105, 151, 454, 598, 679). Fixes: validation added 10, docs only 1. This type crosses input_source. go-getter (429) left out, since symlink copies are one of several issues in that advisory.
- Not a type: the other 9 file or config library rows. 6 run config or policy the library reads (322, 347, 348, 627, 663, 677) and 3 involve local filesystem state, not file contents (182, 227, 698). Neither fits the parser or extractor boundary. The sample has no path helper libraries; path hits were route matching, property paths or URL paths.

Starter drafts: `docs/security-model/starters/library.md`, `docs/security-model/starters/framework.md`, `docs/security-model/starters/tool.md`, `docs/security-model/starters/parser-decoder.md`, `docs/security-model/starters/archive-extractor.md`.

Later, not started: a library_role field (what the library does with the input, such as parse, decode, deserialize, render or escape), with written criteria in `docs/labeling-criteria.md`, AI-labeled on all 225 library rows and blind-checked on a sample. This would settle whether decoders of network or caller data and short string parsers join the parser and decoder type, and whether output encoders form a type. A hand sort on 2026-11-23 was not kept as data.

## Where it goes

Here first, then proposed to the OpenSSF Best Practices WG through the collaboration guide work and issue #1163.

## Open decisions

1. Decided 2026-11-23: separate short templates, one per type, so each is ready to copy.
2. Decided 2026-11-23: two more types, parser and decoder (18 rows) and archive and file-tree extractor (11 rows, across file and network input). Model and data loaders get a short note inside the parser type.
3. Wording for each starter. First drafts done 2026-11-23, wording not settled.
4. Decided 2026-11-23: one optional attribution line, no data. Evidence stays on the page that hosts the starters.
5. Decided 2026-11-23: one shared limits section in `docs/security-model/README.md`, the page that hosts the starters. Each starter keeps only its type-specific limits.
