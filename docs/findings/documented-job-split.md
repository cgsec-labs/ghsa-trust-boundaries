# The documented-job split: end-user via caller or caller code

This finding is about one question: when a library function takes a string that the caller passes in, is that string the caller's own code, or is it end-user data that the caller forwards? The codebook calls these `caller code` and `end-user via caller` (see `docs/labeling-criteria.md`). The documented-job test says a value is end-user data if processing it is what the library is documented to do.

The two labelers applied that test differently, and the difference is consistent enough to report as a result.

## What was compared

The AI labeler marked 14 in-scope rows as `caller code`, out of 380. Every one of them has a human label:

- 5 rows from the first blind review (`results/blind_review_human.csv`)
- 1 row from the second blind review (`results/blind_review2_human.csv`)
- 8 rows from a third review (`results/review3_human.csv`). Those labels were AI-assisted and confirmed by the author, and the reviewer knew the AI label. This round is not blind and is not part of the agreement numbers.

| n | Package | Input | AI | Reviewer | Review |
|---|---|---|---|---|---|
| 11 | semver | range string | caller code | end-user via caller | r1 |
| 24 | path-to-regexp | route pattern, matched against the URL path | caller code | end-user via caller | r3 |
| 88 | handlebars | template raw block (ReDoS) | caller code | end-user via caller | r1 |
| 34 | property-expr | property path | caller code | end-user via caller | r3 |
| 61 | set-in | key path | caller code | end-user via caller | r3 |
| 65 | doc-path | key path | caller code | end-user via caller | r3 |
| 22 | macaddress | interface name, reaches a shell command | caller code | end-user via caller | r2 |
| 30 | systeminformation | interface name, reaches a file path | caller code | end-user via caller | r1 |
| 110 | p4 | Perforce command and arguments | caller code | end-user via caller | r1 |
| 95 | jquery-ui | datepicker text options | caller code | end-user via caller | r1 |
| 51 | handlebars | crafted AST passed through a helper | caller code | end-user via caller | r3 |
| 13 | pug | `pretty` compiler option | caller code | caller code | r3 |
| 85 | @quasar/app-vite | `ssrContext.nonce` | caller code | caller code | r3 |
| 287 | spring-security-config | servlet request matchers | caller code | not boundary | r3 |

The reviewer kept `caller code` on 2 of the 14 rows. In the 6 blind rows the two labels never matched, and no row anywhere went the other way, with the AI saying end-user via caller and the reviewer saying caller code.

## How the cases group

**Strings the utility exists to parse.** semver ranges, route patterns, property and key paths. The docs mostly describe these as values the developer writes. The reviewer's reading is that parsing them is the function's whole job, apps do pass user values to them in practice, and the maintainers accepted the report and fixed it in the library. Six rows, mostly ReDoS (CWE-1333) and prototype pollution (CWE-1321).

**Names that reach a shell or the file system.** macaddress, systeminformation and p4 take an interface name or a command line and hand it to the operating system. systeminformation already sanitized the name before the fix, which shows the maintainer expected bad values. Three rows.

**Template and widget content.** jquery-ui datepicker text options and a handlebars AST. The maintainers fixed both even though their docs treat the content as developer-written. Two rows.

**Pure developer settings.** pug's `pretty` option and quasar's SSR nonce are only exploitable if the app wires attacker data into a setting that is never meant to carry it. Both labelers agree these are `caller code`. Two rows.

**A setting that did not apply.** The spring-security row is a matcher that silently covered the wrong servlets. Under the v1.3 rule for settings that do not take effect it is `not boundary`. The linked fix is a change to a sample config. One row.

## Effect on the counts

The input_source counts in `results/crosstab_v1_input_source.csv` use the AI labels. Only two cells change under the reviewer's reading.

| Cell | Reading | caller code | end-user via caller | not boundary |
|---|---|---|---|---|
| npm library | AI | 12 | 40 | 5 |
| npm library | reviewer | 1 | 51 | 5 |
| Maven framework | AI | 1 | 2 | 0 |
| Maven framework | reviewer | 0 | 2 | 1 |
| All 380 rows | AI | 14 | 114 | 40 |
| All 380 rows | reviewer | 2 | 125 | 41 |

Both readings should be reported. npm stands out either way: 13 of the 14 AI `caller code` rows are npm, and most of them are small single-purpose utilities.

## Limits

- The reviewer labels on 8 of the 14 rows were made knowing the AI label, so they show how far the reviewer's reading reaches. They are not independent agreement.
- Only rows the AI marked `caller code` were checked for this split. Rows the AI marked `end-user via caller` were checked only where a blind review happened to include them.
- Like every result here, this describes what maintainers accepted and fixed, not where the line ought to be.

## What it means for a security model

Docs that say "developers set this" did not stop users from reaching these functions, and they did not stop maintainers from fixing them. A SECURITY.md security model for a utility library should say directly which arguments it treats as untrusted, for example "range strings and key paths may come from end users", and which ones it does not, such as compiler options and nonces. That one sentence would have settled most of the rows above.
