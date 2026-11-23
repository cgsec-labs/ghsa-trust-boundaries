"""Draw a reproducible stratified sample of npm advisories with fix links (excl. withdrawn, CWE-506)."""
import csv, json, os, random, re, sys

root, out_csv, n_total, seed = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
exclude = set()
if len(sys.argv) > 5:
    with open(sys.argv[5], encoding="utf-8") as ef:
        exclude = {r["ghsa_id"] for r in csv.DictReader(ef)}
commit_re = re.compile(r"github\.com/[^/]+/[^/]+/(commit|pull)/")

pool = []
for dp, _, fns in os.walk(root):
    for fn in fns:
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(dp, fn), encoding="utf-8") as f:
            a = json.load(f)
        npm_pkgs = [x["package"]["name"] for x in a.get("affected", []) if x.get("package", {}).get("ecosystem") == "npm"]
        if not npm_pkgs or a.get("withdrawn"):
            continue
        cwes = a.get("database_specific", {}).get("cwe_ids") or []
        if "CWE-506" in cwes:
            continue
        fixes = [r["url"] for r in a.get("references", []) if commit_re.search(r.get("url", ""))]
        if not fixes or a["id"] in exclude:
            continue
        vec = next((x.get("score", "") for x in a.get("severity", []) if x.get("type") == "CVSS_V3"), "") or next((x.get("score", "") for x in a.get("severity", [])), "")
        cve = next((x for x in a.get("aliases", []) if x.startswith("CVE-")), "")
        pool.append({
            "ghsa_id": a["id"],
            "package": ", ".join(sorted(set(npm_pkgs))),
            "cwe": ", ".join(cwes) or "(none)",
            "year": (a.get("published") or "")[:4],
            "severity": a.get("database_specific", {}).get("severity", ""),
            "summary": (a.get("summary") or "").strip(),
            "advisory_url": f"https://github.com/advisories/{a['id']}",
            "fix_url": fixes[0],
            "other_fix_urls": len(fixes) - 1,
            "cvss_vector": vec,
            "cve_id": cve,
        })

pool.sort(key=lambda r: r["ghsa_id"])  # deterministic order before sampling
rng = random.Random(seed)
strata = {"2026": [r for r in pool if r["year"] == "2026"], "pre-2026": [r for r in pool if r["year"] != "2026"]}
sample = []
for name, rows in strata.items():
    k = round(n_total * len(rows) / len(pool))
    sample += rng.sample(rows, k)
sample = sample[:n_total]
sample.sort(key=lambda r: (r["year"], r["ghsa_id"]))

cols = ["n", "ghsa_id", "package", "cwe", "year", "severity", "summary", "advisory_url", "fix_url", "other_fix_urls", "cvss_vector", "cve_id",
        "entry_point", "input_source", "fix_type", "fix_has_test", "maintainer_pushback", "minutes", "notes"]
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for i, r in enumerate(sample, 1):
        w.writerow({"n": i, **r, "entry_point": "", "input_source": "", "fix_type": "", "fix_has_test": "", "maintainer_pushback": "", "minutes": "", "notes": ""})

print(json.dumps({"pool": len(pool), **{k: len(v) for k, v in strata.items()}, "sample": len(sample),
                  "sample_2026": sum(r["year"] == "2026" for r in sample)}, indent=2))
