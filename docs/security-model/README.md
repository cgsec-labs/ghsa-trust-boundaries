# Security model starters

Status: draft for comment.

These are short security model sections that a maintainer can copy into SECURITY.md. Each one says what the project treats as untrusted, what it treats as the caller's responsibility, and what it does not consider a vulnerability. There is one starter per type, and each is built from the labeled advisory data in `results/`. The plan and the decisions behind them are in `draft-outline.md`.

- `starters/library.md`
- `starters/framework.md`
- `starters/tool.md`
- `starters/parser-decoder.md`
- `starters/archive-extractor.md`

Each starter has the starter text, a Basis section with the rows behind it, and the limits that apply only to that type. The limits below apply to all of them.

## Limits

- The data is accepted advisories with a public fix link, in npm, PyPI, Maven and Go. It says nothing about rejected reports.
- Labels are AI labels with one human reviewer. Round 3 (`results/review3_human.csv`) was AI-assisted and not blind, and is excluded from agreement.
- Agreement between the AI labels and the blind reviews, as Cohen's kappa: package_type 0.91 and scope 0.96 (round 1, 120 rows). input_source was 0.64 in round 1 (73 rows); the criteria were revised to v1.3 after it, and round 2 gave 0.93 (40 rows). fix_type 0.62 (round 2, 36 rows; 0.63 in round 1). fix_type is the weakest field. Figures are from `results/agreement_blind_v1.json` and `results/agreement_blind_v2.json`.
- Agreement was measured against the AI labels as they stood at each blind review. After round 1 the labels were rechecked under v1.3 and v1.4. After round 2 they were rechecked under v1.4 and four single rows were fixed. Rerunning `scripts/agreement.py` on the current `ai_labels.csv` therefore gives higher figures that are not blind agreement. Round 1 reproduces from `results/snapshots/ai_labels_round1.csv` (criteria v1.2) and round 2 from `results/snapshots/ai_labels_round2.csv` (after the v1.3 recheck), each with `scripts/agreement.py` and that round's human labels (`results/blind_review_human.csv` and `results/blind_review2_human.csv`). The round 2 rows do not overlap the round 1 rows, and the v1.3 recheck was merged before the round 2 rows were chosen.
- The starter lines rest on package_type and input_source, and on the fixes and notes named in each starter's Basis. Fix counts are descriptive only. Lines drawn from fixes rest on reading the named fixes, not on the fix_type category.
