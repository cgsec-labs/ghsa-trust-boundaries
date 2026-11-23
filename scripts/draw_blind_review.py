"""Draw the rows for the blind human review.

30 rows per ecosystem from the AI-labeled rows, with a fixed seed. The draw looks only at which
rows were labeled, never at the labels, so out-of-scope rows are included at their natural rate.
Pilot rows and row 99 are excluded (see docs/labeling-criteria.md, Agreement plan).

Usage: python3 scripts/draw_blind_review.py <sample_v1.csv> <labeled_rows.txt> <out.csv>
labeled_rows.txt lists the labeled row numbers, one per line.
"""
import csv
import random
import sys

SEED = 20261118
PER_ECO = 30
ECOS = ["npm", "PyPI", "Maven", "Go"]
EXCLUDE = {"99"}

sample_path, labeled_path, out_path = sys.argv[1:4]
rows = {r["n"]: r for r in csv.DictReader(open(sample_path, newline=""))}
labeled = sorted({line.strip() for line in open(labeled_path) if line.strip()}, key=int)

rng = random.Random(SEED)
picked = []
for e in ECOS:
    pool = [n for n in labeled
            if rows[n]["ecosystem"] == e and rows[n]["pilot"] not in ("1", "yes", "True")
            and n not in EXCLUDE]
    picked += [(e, n) for n in sorted(rng.sample(pool, PER_ECO), key=int)]

order = list(range(len(picked)))
rng.shuffle(order)
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["review_order", "n", "ecosystem"])
    for pos, i in enumerate(order, 1):
        e, n = picked[i]
        w.writerow([pos, n, e])
print(f"{len(picked)} rows written to {out_path}")
