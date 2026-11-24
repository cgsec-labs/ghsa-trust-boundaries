# Starter: framework

Status: draft for comment. Replace the bracketed parts.

## Starter text

The bullets under "What we do not consider a vulnerability" are starting defaults for the maintainer to edit. They rest on few or no rows (see Basis and Limits).

```markdown
## Security model

[Project] is a framework. It receives [requests, messages or connections] from the network and passes them to the application code you write.

### What we treat as untrusted

Everything that arrives over the network: [request lines, headers, paths, bodies, messages or frames]. We assume any client may be an attacker. Handling it should never:

- skip the authentication, authorization or origin checks you configured
- use memory or CPU far beyond the size of the input, or crash the process
- serve or write files outside the directories you configured
- let one request see another request's data

Values you pass to our helpers, such as [validators, URL builders or redirect and header helpers], may also come from end users, and we treat them as untrusted.

### What we treat as trusted

- Your application code, including the controllers and handlers the framework loads.
- Your configuration, including authorization rules and values you set for rendering, such as nonces.
- What your application does with a request after the framework hands it over.

### What we do not consider a vulnerability

- Problems that need an attacker to change your application code or configuration.
- Problems caused by authorization rules or settings your application wrote incorrectly.

[Optional] Adapted from the security model starter, version 0.1.1, https://doi.org/10.5281/zenodo.24498888.
```

## Basis

Network is the largest input source for frameworks in every ecosystem: 78 of 95 framework rows (`results/crosstab_v1_input_source.csv`).

| Ecosystem | Network | Framework rows |
|---|---|---|
| Maven | 35 | 39 |
| Go | 18 | 21 |
| PyPI | 15 | 19 |
| npm | 10 | 16 |
| All | 78 | 95 |

The 78 network rows come from 71 packages. No pushback was recorded on them; the field is only filled when a discussion thread is visible, and 1 of 694 rows has one. 59 of the 78 fixes added a test, 13 did not, and 6 are not known. Fixes: validation added 42, internal hardening 30, other 3, feature removed 1, fix not readable 2.

These lines are examples drawn from the network rows, not a counted grouping. No field sorts the rows by them yet.

| Untrusted line | Example rows |
|---|---|
| Skip the authentication, authorization or origin checks you configured | Spring Web Services X.509 auth skipped account status checks (567), Wails origin check matched suffixes (664) |
| Memory or CPU far beyond the input, or a crash | quic-go QPACK headers expanded past the header size limit (729), Fiber BodyParser crashed on a huge slice index (692) |
| Files outside the configured directories | http4s static services decoded `%2F` after the traversal check (368), Vert.x static handler normalized before decoding (600) |
| One request sees another's data | Angular SSR shared a global injector across concurrent requests (15), Quarkus request data leaked between duplicated contexts (565) |

The helper line rests on the 5 framework rows labeled end-user via caller: Django URLValidator (157), bottle redirect and header values (174), Spring UriComponentsBuilder (323), Gin FileAttachment (654), Camel XSD validator (280).

| Starter line | Rows | Examples |
|---|---|---|
| Application code is trusted | 1 | sails (12): the fix is a docs note to never replace controller or action files with untrusted code. This is the one row in the dataset with pushback. |
| Values the app sets are trusted | 1 | quasar SSR nonce (85). Both labelers agree it is caller code. |
| Boundary case: rules that are easy to write wrong | 1 | spring-security servlet matchers (287). An accepted advisory whose only linked fix updates a sample config. The AI labeled it caller code and the reviewer not boundary (`docs/findings/documented-job-split.md`). It sits between rules the application wrote incorrectly and checks the framework did not apply. |

## Limits

- The untrusted list is examples. The 78 network rows cover many kinds of weakness, and they are not grouped into starter lines.
- The trusted lines rest on 2 rows (12, 85). The not-a-bug line for rules the application wrote incorrectly rests on 1 boundary case (287), which was still accepted as an advisory. 4 of the 5 framework rows with file or config input were fixed in the framework (connect 82, electron 89, PraisonAI 154, Emissary 617), so files on disk are not trusted in general.
- Limits shared by all starters are in `docs/security-model/README.md`.
