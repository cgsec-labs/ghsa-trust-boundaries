# Starter: tool

Status: draft for comment. Replace the bracketed parts.

## Starter text

The bullets under "What we do not consider a vulnerability" are starting defaults for the maintainer to edit. They rest on few or no rows (see Basis and Limits).

```markdown
## Security model

[Project] is a tool that developers run on their own machines or in CI. It reads [projects, repositories, charts, specs or config files] and [what it does with them, for example fetches, serves or builds].

### What we treat as untrusted

The files and config [project] reads, such as [project files, repositories, charts, modules or specs], and values from the CI environment, such as branch names. We assume someone else may have written them, even when they sit in your own checkout. Reading them should never:

- run commands or code that you did not choose to run
- read or write files outside the project or output directory
- hang or crash on deeply nested or cyclic input

Content [project] fetches from the network, such as [package indexes, git URLs, archives or schemas], and requests to any server it runs on your machine, including requests sent by web pages open in your browser. Handling it should never:

- let another website talk to or read from a server [project] runs locally
- read or write local files beyond what [project] is meant to
- treat a download or artifact as verified when it has not passed the check

### What we treat as trusted

- Code you write that calls [project]'s own API, if it has one.
- Command-line flags and your own project's config: [trusted or not trusted].
- What you do with the output.

### What we do not consider a vulnerability

- Problems that need an attacker to change code you wrote that calls [project].

[Optional] Adapted from the security model starter, version 0.1.1, https://doi.org/10.5281/zenodo.24498888.
```

## Basis

Tools split between file or config input (29 of 60 tool rows) and network input (22) (`results/crosstab_v1_input_source.csv`). Only Go is clearly led by file or config.

| Ecosystem | File or config | Network | Not boundary | Tool rows |
|---|---|---|---|---|
| Go | 17 | 9 | 1 | 27 |
| npm | 6 | 8 | 1 | 15 |
| PyPI | 6 | 5 | 6 | 17 |
| Maven | 0 | 0 | 1 | 1 |
| All | 29 | 22 | 9 | 60 |

The 29 file or config rows come from 26 packages and the 22 network rows from 22 packages. No pushback was recorded on them; the field is only filled when a discussion thread is visible, and 1 of 694 rows has one.

| Input | Tests added | Fixes |
|---|---|---|
| File or config (29) | 22 yes, 6 no, 1 not known | validation added 14, internal hardening 13, feature removed 1, fix not readable 1 |
| Network (22) | 12 yes, 9 no, 1 not known | internal hardening 9, validation added 7, feature removed 4, other 1, fix not readable 1 |

These lines are examples drawn from the file or config and network rows, not a counted grouping. No field sorts the rows by them yet.

| Untrusted line | Example rows |
|---|---|
| Files: commands or code you did not choose to run | argos CI branch names reached a shell (74), git-lfs passed an ssh URL from repo config as an option (740) |
| Files: outside the project or output directory | Terraform module names wrote outside the module directory during init (437), melange license-path read outside the workspace (685) |
| Files: hang or crash | dasel JSON and XML readers overflowed the stack on deep nesting (675), docker2aci looped on a cyclic image chain (723) |
| Network: another website reaches a local server | parcel dev server accepted any origin on its HMR websocket (107), Tilt served its CSRF token to any page (449) |
| Network: local files beyond what the tool is meant to | Vite dev server WebSocket skipped the file system check (77), aqua followed symlinks planted in downloaded archives (703) |
| Network: treated as verified without passing the check | GitHub CLI built an unescaped regex from the expected repo URL, so other repos could match (514), cosign verify-attestation with `--type` passed if any attestation existed (721) |

The trusted line rests on one note. PraisonAI (538) now checks MCP server commands from the CLI and agent config against an allowlist, and leaves its SDK class open since developers control it. Projects in the sample answered differently whether command-line flags and a project's own config are trusted (538, 102).

## Limits

- The untrusted lists are examples, not counted lines.
- The trusted line rests on one labeling note (538), not on a label. The not-a-vulnerability line has no example row. The command line is not listed as trusted, since 538 restricted commands from the CLI, and ng-packagr (102) fixed a command injection from the project's own config.
- 3 rows are weaknesses in code the tool generates, not in how it reads input: generator-jhipster-kotlin (9), generator-jhipster (100), PEAR archetype (594, not boundary). They are not in the starter.
- Maven has 1 tool row.
- Limits shared by all starters are in `docs/security-model/README.md`.
