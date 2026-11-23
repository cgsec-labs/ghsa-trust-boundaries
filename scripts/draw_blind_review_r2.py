"""Draw the rows for the second blind review, which checks rules v1.3.

10 rows per ecosystem, 40 in total, with a fixed seed, from rows the AI labeler put in scope
(library, framework or tool). Rows from the first blind review, pilot rows and row 99 are left out.
Only input_source and fix_type are relabeled (see docs/labeling-criteria.md, Second blind review).

Usage: python3 scripts/draw_blind_review_r2.py <sample_v1.csv> <ai_labels.csv> <blind_review_rows.csv> <out.csv>
"""
import csv
import random
import sys

SEED = 20261121
PER_ECO = 10
ECOS = ["npm", "PyPI", "Maven", "Go"]
IN_SCOPE = {"library", "framework", "tool"}
EXCLUDE = {"99"}

sample_path, ai_path, first_path, out_path = sys.argv[1:5]
rows = {r["n"]: r for r in csv.DictReader(open(sample_path, newline=""))}
ai = {r["n"]: r for r in csv.DictReader(open(ai_path, newline=""))}
first = {r["n"] for r in csv.DictReader(open(first_path, newline=""))}

rng = random.Random(SEED)
picked = []
for e in ECOS:
    pool = sorted((n for n, a in ai.items()
                   if rows[n]["ecosystem"] == e and a["package_type"] in IN_SCOPE
                   and rows[n]["pilot"] != "yes" and n not in first and n not in EXCLUDE), key=int)
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
