"""Count in-scope labels by ecosystem and package_type, for input_source and for fix_type.

Usage: python3 -I scripts/crosstab_v1.py <sample_v1.csv> <ai_labels.csv> <pilot_labels.csv> <out-dir>

In scope means package_type is library, framework or tool. AI labels get their ecosystem from
sample_v1.csv by n; pilot rows carry their own. The two sources are counted separately
(source = ai or pilot) and are never added together. A blank fix_type is written as
"fix not readable" and is never imputed. Every ecosystem, package_type and value combination
is written, including zero counts, so each table is complete.

Writes <out-dir>/crosstab_v1_input_source.csv and <out-dir>/crosstab_v1_fix_type.csv in long
format (source, ecosystem, package_type, field_value, count), and prints the same counts as
wide tables for reading.
"""
import csv
import os
import sys
from collections import Counter

sample_path, ai_path, pilot_path, out_dir = sys.argv[1:5]
ECOS = ["npm", "PyPI", "Maven", "Go"]
TYPES = ["library", "framework", "tool"]
FIELDS = ["input_source", "fix_type"]
BLANK = {"input_source": "(blank)", "fix_type": "fix not readable"}


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


eco_by_n = {r["n"]: r["ecosystem"] for r in read(sample_path)}
rows = []
for r in read(ai_path):
    if r["package_type"] in TYPES:
        if r["n"] not in eco_by_n:
            sys.exit(f"AI row {r['n']} is not in {sample_path}")
        rows.append(("ai", eco_by_n[r["n"]], r))
for r in read(pilot_path):
    if r["package_type"] in TYPES:
        rows.append(("pilot", r["ecosystem"], r))

for field in FIELDS:
    counts = Counter()
    values = set()
    for src, eco, r in rows:
        v = r[field].strip() or BLANK[field]
        values.add(v)
        counts[(src, eco, r["package_type"], v)] += 1
    values = sorted(values, key=lambda v: (v == BLANK[field], v))

    path = os.path.join(out_dir, f"crosstab_v1_{field}.csv")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "ecosystem", "package_type", "field_value", "count"])
        for src in ["ai", "pilot"]:
            for eco in ECOS:
                for t in TYPES:
                    for v in values:
                        w.writerow([src, eco, t, v, counts[(src, eco, t, v)]])

    for src in ["ai", "pilot"]:
        n_src = sum(1 for s, _, _ in rows if s == src)
        print(f"\n{field}, source={src}, rows={n_src}")
        print(" | ".join(["ecosystem", "package_type"] + values + ["n"]))
        for eco in ECOS:
            for t in TYPES:
                cells = [counts[(src, eco, t, v)] for v in values]
                print(" | ".join([eco, t] + [str(c) for c in cells] + [str(sum(cells))]))
        tot = [sum(counts[(src, e, t, v)] for e in ECOS for t in TYPES) for v in values]
        print(" | ".join(["all", ""] + [str(c) for c in tot] + [str(sum(tot))]))
    print(f"wrote {path}")
