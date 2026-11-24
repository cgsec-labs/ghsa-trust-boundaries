# ghsa-trust-boundaries

Most library vulnerability disputes come down to one question: was the library supposed to handle that input safely, or was the caller supposed to validate it first? Almost no project writes the answer down, and no advisory database records it.

This repo studies that question using GitHub-reviewed security advisories. For each sampled advisory we read the fix and record where the attacker-controlled input came from, what the fix actually did, and whether the maintainer pushed back.

The goal is practical. The labeled data feeds short, evidence-based starter text that library maintainers can drop into the security model section of their SECURITY.md, organized by type: [library](docs/security-model/starters/library.md), [framework](docs/security-model/starters/framework.md), [tool](docs/security-model/starters/tool.md), [parser and decoder library](docs/security-model/starters/parser-decoder.md) and [archive and file-tree extractor library](docs/security-model/starters/archive-extractor.md). The limits shared by all five are in [docs/security-model/README.md](docs/security-model/README.md).

## Status

Baseline counts across all ecosystems are refreshed weekly. The labeling sample (snapshot `3d08969`, 805 rows across npm, PyPI, Maven and Go) is drawn and labeled: 380 in-scope rows by an AI labeler, checked in two blind human reviews (see [docs/labeling-criteria.md](docs/labeling-criteria.md)). The overview tables below move with each weekly refresh; the sample does not.

## Data source

[github/advisory-database](https://github.com/github/advisory-database), GitHub-reviewed advisories only, and MITRE's [CWE-1400](https://cwe.mitre.org/data/definitions/1400.html) view for grouping CWEs. A GitHub Action refreshes all counts weekly from the latest versions of both. Each run records the exact advisory commit and CWE version it used.

## Scope of the findings

The labeled sample covers accepted GitHub-reviewed advisories only. Withdrawn advisories are left out, so the results describe what maintainers accepted as the library's job, not where the line between library and caller truly lies. The sample also needs a GitHub commit or pull request among the advisory's references, which holds for about half to two thirds of advisories in the four sampled ecosystems (the Fix link column in [docs/overview.md](docs/overview.md)). Advisories without a public fix link are not represented.

<!-- overview:start -->
## Overview across all ecosystems

Advisory snapshot `98c0a2c011297d26f20a03c9d22bb3023da125ab` (2026-11-24), CWE 5.0 (2026-10-28). Refreshed weekly by a GitHub Action.

38030 unique GitHub-reviewed advisories. One advisory can cover more than one ecosystem, so the rows add up to more than that. Each breakdown page covers MITRE CWE-1400 categories, top CWEs, CVSS v3 and v4 metrics, the most common full vectors, severity, years and the packages with the most advisories.

| Ecosystem | Advisories | Largest CWE-1400 category | Details |
|---|---|---|---|
| npm | 8182 | Injection (CWE-1409) | [breakdown](docs/ecosystems/npm.md) |
| Maven | 7259 | Access Control (CWE-1396) | [breakdown](docs/ecosystems/maven.md) |
| PyPI | 6948 | Access Control (CWE-1396) | [breakdown](docs/ecosystems/pypi.md) |
| Packagist | 6630 | Injection (CWE-1409) | [breakdown](docs/ecosystems/packagist.md) |
| Go | 5147 | Access Control (CWE-1396) | [breakdown](docs/ecosystems/go.md) |
| crates.io | 1642 | Memory Safety (CWE-1399) | [breakdown](docs/ecosystems/crates-io.md) |
| NuGet | 1237 | Memory Safety (CWE-1399) | [breakdown](docs/ecosystems/nuget.md) |
| RubyGems | 1215 | Injection (CWE-1409) | [breakdown](docs/ecosystems/rubygems.md) |
| Hex | 122 | Resource Lifecycle Management (CWE-1416) | [breakdown](docs/ecosystems/hex.md) |
| GitHub Actions | 64 | Injection (CWE-1409) | [breakdown](docs/ecosystems/github-actions.md) |
| SwiftURL | 64 | Injection (CWE-1409) | [breakdown](docs/ecosystems/swifturl.md) |
| Pub | 14 | Encryption (CWE-1402) | [breakdown](docs/ecosystems/pub.md) |

The full comparison table is in [docs/overview.md](docs/overview.md). Weekly history is in [results/history.csv](results/history.csv).
<!-- overview:end -->

## Layout

- `scripts/` analysis and sampling scripts
- `.github/workflows/weekly-refresh.yml` the weekly refresh, which also posts what changed to the "Weekly delta" issue
- `results/` measured counts, `history.csv` with one set of counts per weekly run, and `cwe1400_map.csv`, the MITRE CWE-1400 category for every CWE weakness
- `docs/overview.md` and `docs/ecosystems/` generated breakdowns per ecosystem
- `docs/labeling-criteria.md` the labeling rules and how labeling is done (v1.4)
- `results/sample_v1.csv` the labeling sample from npm, PyPI, Maven and Go (805 rows, extended after the pilot and again for PyPI and Maven so each ecosystem can reach 100 in-scope rows; earlier rows never change), drawn by `scripts/draw_sample_v1.py` with settings in `results/sample_v1_meta.json`
- `results/pilot_labels.csv` the 32 pilot labels used to revise the criteria
- `results/ai_labels.csv` the 694 AI labels (380 in scope), rechecked under rules v1.4; labeling stopped at row 111 for npm, 773 for PyPI, 792 for Maven and 740 for Go
- `results/blind_review_rows.csv` the 120 rows for the blind human review, drawn by `scripts/draw_blind_review.py`
- `results/blind_review_human.csv` the human blind labels, and `results/agreement_blind_v1.json` their agreement with the AI labels under rules v1.2, from `scripts/agreement.py`
- `results/blind_review2_rows.csv` the 40 rows for the second blind review, drawn by `scripts/draw_blind_review_r2.py`
- `results/blind_review2_human.csv` the second-review human labels, and `results/agreement_blind_v2.json` their agreement with the AI labels under rules v1.3
- `results/snapshots/` the AI labels as they stood at each blind review: `ai_labels_round1.csv` (rules v1.2) and `ai_labels_round2.csv` (after the v1.3 recheck). `scripts/agreement.py` reproduces both agreement files from them
- `results/validation_cases.csv` case studies from the project author's own reports, added only once each advisory is fixed and public, using only what the public advisory and fix show. They are kept apart from the sample and its counts

## Reproduce

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database data/advisory-database
git -C data/advisory-database sparse-checkout set advisories/github-reviewed
python3 -I scripts/npm_baseline.py data/advisory-database/advisories/github-reviewed results/npm_baseline.json
# CWE-1400 XML: download from https://cwe.mitre.org/data/definitions/1400.html (Downloads, XML) and unzip into data/
python3 -I scripts/cwe1400_map.py data/1400.xml results/cwe1400_map.csv
python3 -I scripts/ghsa_overview.py data/advisory-database/advisories/github-reviewed 3d089691861074f29c73f30805dea0c1d2ac4e83 .
```

## Early observations (npm, advisory snapshot 3d08969, 2026-11-15)

- 8,138 GitHub-reviewed npm advisories in total.
- The most common MITRE CWE-1400 categories are Injection (26%), Access Control (20%) and Resource Lifecycle Management (13%).
- CVSS barely separates cases. Of npm advisories with any CVSS vector, 92% have attack vector Network.
- 2026 has 3,754 advisories, but a large share comes from a few applications. One package, openclaw, accounts for 758 of them. The study focuses on libraries for that reason.

## License

The code in `scripts/` and `.github/workflows/` is under the MIT License (`LICENSE`). The data in `results/`, the text in `docs/` and this README are under CC-BY-4.0 (`LICENSE-DATA`). The advisory data comes from [github/advisory-database](https://github.com/github/advisory-database), which is under CC-BY-4.0.

To cite the data or the starter texts, use [CITATION.cff](CITATION.cff). DOI for all versions: [10.5281/zenodo.24498888](https://doi.org/10.5281/zenodo.24498888).
