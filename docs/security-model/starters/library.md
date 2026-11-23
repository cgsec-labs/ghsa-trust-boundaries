# Starter: library

Status: draft for comment. Replace the bracketed parts.

## Starter text

The bullets under "What we do not consider a vulnerability" are starting defaults for the maintainer to edit. They rest on few or no rows (see Basis and Limits).

```markdown
## Security model

[Project] is a library. Its job is to [what it does with the values you pass it, for example parse version ranges, match route patterns or read key paths].

### What we treat as untrusted

The values that [project] exists to process, even when your own code is the one that passes them in. Apps often forward these from end users, so we assume they may have been crafted by an attacker. These are:

- [the arguments, for example range strings, patterns, key paths, template text, interface or command names]

Processing them should never:

- hang or take time far beyond the size of the input
- change objects or settings outside the result, for example through `__proto__` in a key path
- run as a shell command, or reach a file path, beyond what the function is documented to do
- run script in a page where the output is shown

### What we treat as trusted

- [the options that are developer settings, for example compiler or formatting options]. These are never meant to carry end-user data.
- What your application does with the result.

### What we do not consider a vulnerability

- Problems that only happen when your application passes attacker data into one of the trusted options above.

[Optional] Adapted from the security model starter, version [X], [link].
```

## Basis

End-user via caller is the largest input source for libraries: 120 of 225 library rows under the reviewer reading, 109 under the AI labels (`docs/findings/documented-job-split.md`). The two readings differ only on npm: 51 of 63 npm library rows under the reviewer reading, 40 under the AI labels.

| Ecosystem | Reviewer reading | AI labels |
|---|---|---|
| npm | 51 | 40 |
| Maven | 27 | 27 |
| PyPI | 25 | 25 |
| Go | 17 | 17 |
| All | 120 | 109 |

The 120 rows come from 112 packages. No pushback was recorded; the field is only filled when a discussion thread is visible, and 1 of 694 rows has one. 80 of the 120 fixes added a test, 34 did not, and 6 are not known. Fixes: internal hardening 54, validation added 49, feature removed 12, docs only 1, fix not readable 4.

The examples come from the 14 rows the AI labeled caller code, which the reviewer checked (`docs/findings/documented-job-split.md`).

| Starter line | Rows | Examples |
|---|---|---|
| Strings the utility exists to parse | 6 | semver range (11), path-to-regexp route pattern (24), handlebars raw block (88), property-expr, set-in and doc-path key paths (34, 61, 65) |
| Names that reach a shell or the file system | 3 | macaddress (22), systeminformation (30), p4 (110) |
| Template and widget content | 2 | jquery-ui datepicker text options (95), handlebars AST (51) |
| Trusted developer setting | 1 | pug `pretty` option (13) |

The trusted and not-a-bug lines rest on one library row. The other row both labelers kept as caller code, the quasar SSR nonce (85), is a framework.

## Limits

- The untrusted and trusted lists are examples. The 120 rows cover many kinds of weakness, and no grouping of them by what the library does exists yet. The planned library_role field would supply one.
- The npm count depends on the reading. 8 of the reviewer labels behind it were made knowing the AI label.
- Limits shared by all starters are in `docs/security-model/README.md`.
