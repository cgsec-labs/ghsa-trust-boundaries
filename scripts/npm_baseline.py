"""Baseline counts for GitHub-reviewed npm advisories. Read-only over the advisory-database checkout."""
import json, os, re, sys
from collections import Counter

root = sys.argv[1]
out_json = sys.argv[2]

commit_re = re.compile(r"github\.com/[^/]+/[^/]+/(commit|pull)/")
total_files = 0
npm = []
for dp, _, fns in os.walk(root):
    for fn in fns:
        if not fn.endswith(".json"):
            continue
        total_files += 1
        with open(os.path.join(dp, fn), encoding="utf-8") as f:
            a = json.load(f)
        if any(x.get("package", {}).get("ecosystem") == "npm" for x in a.get("affected", [])):
            npm.append(a)

n = len(npm)
cwe = Counter()
no_cwe = 0
fix_any = fix_typed = fix_commit_url = 0
withdrawn = 0
av3 = Counter(); av4 = Counter(); no_cvss = 0
sev = Counter()
years = Counter()
withdrawn_cwe = Counter()

for a in npm:
    ids = a.get("database_specific", {}).get("cwe_ids") or []
    if ids:
        for c in set(ids):
            cwe[c] += 1
    else:
        no_cwe += 1
    refs = a.get("references", [])
    t = any(r.get("type") == "FIX" for r in refs)
    u = any(commit_re.search(r.get("url", "")) for r in refs)
    fix_typed += t; fix_commit_url += u; fix_any += (t or u)
    if a.get("withdrawn"):
        withdrawn += 1
        for c in set(ids) or {"(none)"}:
            withdrawn_cwe[c] += 1
    got = False
    for s in a.get("severity", []):
        m = re.search(r"AV:([NALP])", s.get("score", ""))
        if not m:
            continue
        got = True
        (av3 if s.get("type") == "CVSS_V3" else av4)[m.group(1)] += 1
    if not got:
        no_cvss += 1
    sev[a.get("database_specific", {}).get("severity", "UNKNOWN")] += 1
    years[(a.get("published") or "????")[:4]] += 1

res = {
    "reviewed_files_all_ecosystems": total_files,
    "npm_advisories": n,
    "with_cwe": n - no_cwe, "no_cwe": no_cwe,
    "top_cwe": cwe.most_common(30),
    "fix_ref_any": fix_any, "fix_ref_typed_FIX": fix_typed, "fix_commit_or_pr_url": fix_commit_url,
    "withdrawn": withdrawn, "withdrawn_by_cwe": withdrawn_cwe.most_common(15),
    "cvss_v3_AV": dict(av3), "cvss_v4_AV": dict(av4), "no_cvss_vector": no_cvss,
    "severity": dict(sev), "published_by_year": dict(sorted(years.items())),
}
with open(out_json, "w") as f:
    json.dump(res, f, indent=2)
print(json.dumps(res, indent=2))
