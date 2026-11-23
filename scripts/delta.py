"""Summarize what changed between the last two runs in results/history.csv.

Usage: python3 -I scripts/delta.py <repo-root> <out.md>
Writes a short markdown summary to <out.md>, or nothing if the counts did not change.
"""
import csv, os, sys
from collections import defaultdict

repo, out = sys.argv[1], sys.argv[2]
with open(os.path.join(repo, "results", "history.csv"), encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

runs = []
for r in rows:
    key = (r["advisory_commit"], r["cwe_version"])
    if key not in [k for k, _ in runs]:
        runs.append((key, r))
if len(runs) < 2:
    sys.exit(0)

(prev_key, _), (cur_key, cur_row) = runs[-2], runs[-1]
data = {prev_key: defaultdict(int), cur_key: defaultdict(int)}
for r in rows:
    key = (r["advisory_commit"], r["cwe_version"])
    if key in data:
        data[key][(r["ecosystem"], r["metric"])] = int(r["value"])
prev, cur = data[prev_key], data[cur_key]

def diff(eco, metric):
    return cur[(eco, metric)] - prev[(eco, metric)]

ecos = sorted({e for e, _ in cur} | {e for e, _ in prev}, key=lambda e: -cur[(e, "total")])
eco_parts = []
for e in ecos:
    d, w = diff(e, "total"), diff(e, "withdrawn")
    if d or w:
        eco_parts.append(f"{e} {d:+d}" + (f" (withdrawn {w:+d})" if w else ""))

cats = defaultdict(int)
for (e, m) in set(cur) | set(prev):
    if m.startswith("cwe1400:"):
        cats[m.split(":", 1)[1]] += diff(e, m)
moves = sorted(((c, v) for c, v in cats.items() if v), key=lambda kv: (-abs(kv[1]), kv[0]))[:3]

lines = []
if eco_parts:
    lines.append("Advisories: " + ", ".join(eco_parts))
if moves:
    lines.append("Biggest category moves: " + ", ".join(f"{c} {v:+d}" for c, v in moves))
if prev_key[1] != cur_key[1]:
    lines.append(f"CWE version changed: {prev_key[1]} to {cur_key[1]}")
if not lines:
    sys.exit(0)

header = f"**Week of {cur_row['run_date']}** (advisory-database {cur_key[0][:7]}, CWE {cur_key[1]}, compared with {prev_key[0][:7]})"
with open(out, "w", encoding="utf-8") as f:
    f.write(header + "\n\n" + "\n\n".join(lines) + "\n")
print(open(out).read())
