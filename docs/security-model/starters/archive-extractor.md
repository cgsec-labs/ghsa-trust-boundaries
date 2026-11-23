# Starter: archive and file-tree extractor library

Status: draft for comment. Replace the bracketed parts.

## Starter text

The bullets under "What we do not consider a vulnerability" are starting defaults for the maintainer to edit. They rest on few or no rows (see Basis and Limits).

```markdown
## Security model

[Project] is an archive and file-tree extractor library. It extracts [archives, repositories or artifacts] and writes their contents to a directory you choose.

### What we treat as untrusted

The archive or tree itself, including every entry name, path and link inside it. We assume it may have been crafted by an attacker, even if you downloaded it from somewhere you trust. Extracting it should never:

- write, create or overwrite anything outside the target directory, whether through `../` segments, absolute paths or symlinks

### What we treat as trusted

- The target directory you pass, and everything outside it.
- What your application does with the extracted files.

### What we do not consider a vulnerability

- Problems that need an attacker to choose the target directory.

[Optional] Adapted from the security model starter, version [X], [link].
```

## Basis

From 11 library rows, 11 packages (`docs/security-model/draft-outline.md` lists the rows). 6 have file or config input and 5 have network input. No pushback was recorded; the field is only filled when a discussion thread is visible, and 1 of 694 rows has one. 5 of the 11 fixes added a test.

| Starter line | Rows | Examples |
|---|---|---|
| `../` or absolute paths in entry names | 9 | plexus-archiver (572), plexus-utils (563), go-rpmutils (477), Kubernetes Java client tar copy (598), sigstore TUF cache (679), isomorphic-git (105) |
| Symlinks in the tree | 2 | GitPython submodule (151), oras-go file store (454) |

Fixes: 10 reject or confine the path, 1 is docs only (mholt/archiver, deprecated). MPXJ (215) is worth keeping as an example: its check compared string prefixes, and the fix compares canonical paths.

The trusted and not-a-bug lines are not measured, since pushback was not observed. They follow from every fix confining writes to the target directory the caller passed.

## Limits

- Write location only. Decompression bombs and other resource use are not in these rows.
- 11 rows is a thin base.
- Limits shared by all starters are in `docs/security-model/README.md`.
