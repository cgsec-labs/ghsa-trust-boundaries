# Labeling criteria (v1.4)

These rules exist so that two labelers looking at the same advisory reach the same answer. Version 1.1 includes the changes from the 32-row pilot. Version 1.2 adds a tie-break for `input_source` and fixes the agreement plan before the human review. Version 1.3 follows the first blind review: escaping and safe parser settings move to `internal hardening`, and `input_source` gets two rules for files and for settings that do not take effect. Version 1.4 adds one `fix_type` rule for crash guards, after the second blind review.

## General rules

- Use only the advisory and the fix, PR or issue it links to. Do not search elsewhere.
- Spend at most 10 minutes per advisory. If a field is still undecided, mark it `unclear`.
- Weigh evidence in this order: advisory text, proof of concept, fix diff, discussion thread.
- Label the merged fix. If the first fix link was never merged or is only part of the fix, use the merged change the advisory or thread points to, and put that link in `fix_link_used`.

## package_type

Decides whether the advisory is in the core analysis. Library, framework and tool are in. Application and plugin are out.

| Value | Meaning | Examples |
|---|---|---|
| library | Imported by other code through an API | merge utilities, parsers, HTTP clients, crypto providers, ML libraries |
| framework | A library that receives network input itself, such as HTTP requests | express, next, hono, Django, netty |
| tool | Run by a developer or operator on project files and config, not a deployed service | vite, pnpm, ansible, helm, runc |
| application | Deployed and run as a service or product. Excluded from the core analysis | n8n, gitea, servers, dashboards |
| plugin | An add-on for an application. Excluded from the core analysis | Jenkins plugins |

Framework is about trust boundaries, not about who owns the program's lifecycle. A package that runs your code but never receives network input itself, such as TensorFlow or LangChain, is a library here.

The package tag in `results/package_tags.csv` is the default for every advisory on that package. When an advisory clearly hits the other role of a mixed package, such as the server inside an inference library, set package_type on that row and note why.

## input_source

Where the attacker's data comes from before it reaches the vulnerable code. Judge by what the parameter is documented to be for, not by whether some application could misuse it.

| Value | Meaning |
|---|---|
| end-user via caller | The parameter exists to carry untrusted data. Example: `qs.parse(req.query)`, a sanitizer's input, a JSON body passed to merge |
| caller code | The parameter is meant for the developer, such as an options object, a regex pattern or a template setting |
| file or config | The library reads the data itself from disk, an rc file, environment variables or archive contents, or opens and parses a file format itself |
| network | The package receives the data itself: a request reaching its own listener, handler or middleware, or a response, message or file it fetches over its own connection |
| stored data | The library reads the data itself from a database, cache, message queue or other datastore, such as deserializing rows it loads through JDBC |
| not boundary | No outside input is involved, such as logging secrets, a weak crypto default, an insecure file permission or a developer setting that does not take effect |
| unclear | Cannot be decided within the time limit |

The test question for the first two values: is processing untrusted data the documented job of this argument? If yes, `end-user via caller`. If no, `caller code`.

Tie-break between `network` and `end-user via caller`: ask who hands the data to the vulnerable code. If the package takes it off the wire itself, it is `network`. If the caller parses or receives it and then passes it in, it is `end-user via caller`. A SAML library that is given the posted response string is `end-user via caller`; a framework middleware that reads the request is `network`.

Tie-break for auth, authorization and race bugs: if an attacker triggers the bug by sending requests or messages to the package, it is `network`, even when the flaw is in auth logic or a race between requests. Use `not boundary` only when no outside input plays a part.

Files a parser opens (v1.3): when the library opens or parses a file itself, such as an archive, an executable, an image, a PDF, an XML document or a project file, use `file or config`. A string or message the caller passes in, such as a JSON body, Markdown text, a token or a SAML response, stays `end-user via caller`. If the package first fetches the file over its own connection, `network` wins.

Settings that do not take effect (v1.3): when the bug is a developer-configured setting failing to take effect, such as a logger redaction list, a sandbox allowlist or a sensitive-field setting, use `not boundary`. If an attacker's input is what gets past the setting, such as a crafted file or request, label that input instead.

The documented-job test stays as written. Splits between `end-user via caller` and `caller code` on utilities such as version parsers, widget options and template sources are part of what this study measures, so they are reported, not ruled away.

## fix_type

What the fix diff actually changed. If several apply, take the first match in this order: feature removed, validation added, internal hardening, docs only.

| Value | Meaning |
|---|---|
| feature removed | An option or function was removed or turned off by default |
| validation added | A new check rejects, blocks or aborts on bad input, such as refusing `__proto__`, a length limit that throws or path containment |
| internal hardening | Bad input becomes harmless without being rejected, such as escaping or encoding output, sanitizing markup, safe parser settings like XXE-safe flags, `Object.create(null)`, a rewritten regex or `execFile` in place of `exec`. A crash guard that catches a panic or exception and returns an error is here too, since it never inspects the input |
| docs only | Only docs, comments, types or warnings changed. No behavior change |
| other | Dependency bump only, a mixed change, not clear from the diff, or a change that does not actually remove the weakness (say which in notes) |

## fix_has_test

`yes` if the linked fix adds or changes a test that exercises the bad input, otherwise `no`.

## maintainer_pushback

Optional. Fill it only when a discussion thread about the report or fix is visible. Otherwise leave it blank.

| Value | Meaning |
|---|---|
| yes | The maintainer says it is the caller's responsibility, intended behavior, not a vulnerability, or disputes the severity |
| no | Accepted without dispute |
| unknown | A thread exists but does not show the maintainer's position |

## fix_link_used

The fix link actually labeled, when it differs from the pre-filled `fix_url`. Leave blank otherwise.

## minutes

Total time spent on the advisory, including opening links.

## Pre-filled fields

Taken from the advisory record, not labeled by hand: GHSA ID, package, ecosystem, CWE, year, severity, CVSS vector, CVE ID, fix link.

## How labeling is done

- The 32 pilot rows were labeled with help from an AI assistant and reviewed by the project author. They were used to test and revise these rules, and are kept separate from the main results.
- The remaining rows are labeled by an AI labeler (Claude) following these rules. The labeler reads a digest of each fix that shows at most three source files and about 36 changed lines. After the second blind review, every in-scope row whose digest was cut off or unreadable was checked against the full source diff, and `fix_type` was corrected where a full-diff signal contradicted the label. That recheck was not measured again; the agreement figures below are from the blind reviews.
- A human reviewer then labels a random subset blind, without seeing the AI labels. Agreement is reported per field. A field with low agreement has its rule revised and is relabeled.

### Agreement plan

Fixed before the human review starts.

- Rows: 30 per ecosystem, 120 in total, drawn with a fixed seed from the AI-labeled rows by `scripts/draw_blind_review.py`. The draw ignores the AI labels, so it includes out-of-scope rows and `package_type` gets its own agreement score.
- Excluded from the draw: the 32 pilot rows, which are AI-assisted and author-reviewed, and row 99, which is close to a report by the project author.
- The reviewer labels `package_type` on every row, and the other fields on rows they judge in scope. Each other field is compared on rows both labelers put in scope.
- Measure: Cohen's kappa per field, with raw agreement alongside.
- Pass mark: kappa 0.6. A field below it gets a rule fix, then a second round on fresh rows not yet reviewed.
- Every published number states which labels it rests on and the measured agreement for that field.

### First blind review (v1.2 rules)

120 rows, labeled blind by the project author against the AI labels under rules v1.2. These are the reported agreement figures. Rows rechecked after the review under v1.3 are not counted again here, because the AI labeler had seen the human labels by then.

| Field | Rows compared | Raw agreement | Cohen's kappa |
|---|---|---|---|
| package_type (5 values) | 120 | 0.93 | 0.91 |
| in or out of scope | 120 | 0.98 | 0.96 |
| input_source | 73 | 0.74 | 0.64 |
| fix_type | 73 | 0.77 | 0.63 |
| fix_has_test | 70 | 0.93 | 0.85 |

All fields passed the 0.6 mark. 15 of the 17 fix_type disagreements were escaping or safe parser settings, which led to the v1.3 change.

### Second blind review (v1.3 rules)

Fixed before the review starts. It checks the two fields whose rules changed in v1.3.

- Rows: 10 per ecosystem, 40 in total, drawn with a fixed seed by `scripts/draw_blind_review_r2.py` from rows the AI labeler put in scope. Rows from the first review, pilot rows and row 99 are excluded. package_type and fix_has_test are not relabeled; they passed the first review and their rules did not change.
- Fields: `input_source` and `fix_type`, using only this codebook at v1.3.
- The reviewer does not look at the AI labels for these rows, which are now in `results/ai_labels.csv` and the sheet. A row the reviewer thinks is out of scope is marked so in notes and left out of the comparison.
- Measure and pass mark: Cohen's kappa per field, raw agreement alongside, pass at 0.6. A field below it gets a rule fix and another round on fresh rows.

Result, labeled blind by the project author against the AI labels under rules v1.3:

| Field | Rows compared | Raw agreement | Cohen's kappa |
|---|---|---|---|
| input_source | 40 | 0.95 | 0.93 |
| fix_type | 36 | 0.78 | 0.62 |

Both fields passed. fix_type left out 4 rows where the AI label was blank because the fix diff could not be read.

