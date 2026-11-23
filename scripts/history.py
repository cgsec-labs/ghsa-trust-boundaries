"""Append the current overview counts to results/history.csv, one row per ecosystem and metric.

Usage: python3 -I scripts/history.py <repo-root> <run-date>
Reads results/ghsa_overview.json. Skips the run if this advisory snapshot and CWE version are already recorded.
"""
import csv, json, os, sys

repo, run_date = sys.argv[1], sys.argv[2]
src = os.path.join(repo, "results", "ghsa_overview.json")
dst = os.path.join(repo, "results", "history.csv")
with open(src, encoding="utf-8") as f:
    o = json.load(f)

cols = ["run_date", "advisory_commit", "advisory_date", "cwe_version", "ecosystem", "metric", "value"]
if os.path.exists(dst):
    with open(dst, encoding="utf-8") as f:
        done = {(r["advisory_commit"], r["cwe_version"]) for r in csv.DictReader(f)}
    if (o["snapshot"], o["cwe_version"]) in done:
        print("already recorded, nothing to add")
        sys.exit(0)

rows = []
for eco, s in sorted(o["ecosystems"].items()):
    metrics = {k: s.get(k, 0) for k in ("total", "distinct_packages", "withdrawn", "fix_link", "cve_alias", "no_cwe",
                                       "v3_only", "v4_only", "v3_and_v4", "no_cvss", "av_v3_v4_differ")}
    for k, v in s.get("av_v3_else_v4", {}).items():
        metrics[f"attack_vector:{k}"] = v
    for k, v in s.get("severity", {}).items():
        metrics[f"severity:{k}"] = v
    for k, v in s.get("group", {}).items():
        metrics[f"cwe1400:{k}"] = v
    for y, v in s.get("year", {}).items():
        metrics[f"published:{y}"] = v
    for k, v in sorted(metrics.items()):
        rows.append([run_date, o["snapshot"], o.get("snapshot_date", ""), o["cwe_version"], eco, k, v])

new = not os.path.exists(dst)
with open(dst, "a", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    if new:
        w.writerow(cols)
    w.writerows(rows)
print(f"added {len(rows)} rows")
