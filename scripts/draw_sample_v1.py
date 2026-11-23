"""Draw the v1 labeling sample: npm, PyPI, Maven and Go, libraries, frameworks and tools only.

Usage: python3 -I scripts/draw_sample_v1.py <advisories/github-reviewed> <snapshot-commit> <repo-root> [per-ecosystem] [seed]

The first 130 rows per ecosystem were drawn first. Each extension round in EXTEND adds rows after all
earlier rows without changing any of them, so existing labels stay valid. Rounds 2 and 3 top up PyPI and Maven,
whose in-scope rates were lower than planned.

Pool per ecosystem: GitHub-reviewed, not withdrawn, not CWE-506, references a GitHub commit or PR,
and affects at least one package in that ecosystem whose tag in results/package_tags.csv is not
application, plugin or unsure. Untagged packages stay in the pool; their package_type is set while labeling.
Each advisory is drawn at most once overall, and at most 2 advisories are drawn per package.
Rows are in random order. Label from the top, skip rows whose package_type turns out to be
application or plugin, and stop after 100 in-scope rows per ecosystem.
"""
import csv, json, os, random, re, sys

root, snapshot, repo = sys.argv[1], sys.argv[2], sys.argv[3]
per_eco = int(sys.argv[4]) if len(sys.argv) > 4 else 130
seed = int(sys.argv[5]) if len(sys.argv) > 5 else 20261116
ECOS = ["npm", "PyPI", "Maven", "Go"]
PILOT_PER_ECO = 8
EXTEND = [{"npm": 140, "PyPI": 140, "Maven": 210, "Go": 280}, {"PyPI": 150}, {"Maven": 235}]
CAP = 2
OUT_OF_SCOPE = {"application", "plugin", "unsure"}
LINK_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/(commit|pull)/")

tags = {}
with open(os.path.join(repo, "results", "package_tags.csv"), encoding="utf-8") as f:
    for r in csv.DictReader(f):
        tags[(r["ecosystem"], r["package"])] = r["tag"]
cwe_cat = {}
with open(os.path.join(repo, "results", "cwe1400_map.csv"), encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cwe_cat[r["cwe_id"]] = f'{r["category_name"]} ({r["category_id"]})'

pools = {e: [] for e in ECOS}
for dp, dirs, fns in os.walk(root):
    dirs.sort()
    for fn in sorted(fns):
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(dp, fn), encoding="utf-8") as f:
            a = json.load(f)
        cwes = a.get("database_specific", {}).get("cwe_ids") or []
        if a.get("withdrawn") or "CWE-506" in cwes:
            continue
        fixes = [r["url"] for r in a.get("references", []) if LINK_RE.search(r.get("url", ""))]
        if not fixes:
            continue
        sev = {s.get("type"): s.get("score", "") for s in a.get("severity", [])}
        for e in ECOS:
            pk = sorted({x["package"]["name"] for x in a.get("affected", []) if x.get("package", {}).get("ecosystem") == e})
            if not pk:
                continue
            ptags = [tags.get((e, p), "untagged") for p in pk]
            if all(t in OUT_OF_SCOPE for t in ptags):
                continue
            pools[e].append({
                "ghsa_id": a["id"], "packages": pk, "package_tag": ", ".join(sorted(set(ptags))),
                "cwe": ", ".join(cwes) or "(none)",
                "cwe1400_category": ", ".join(sorted({cwe_cat.get(c, "Not a CWE-1400 weakness") for c in cwes})) or "(no CWE)",
                "year": (a.get("published") or "")[:4],
                "severity": a.get("database_specific", {}).get("severity", ""),
                "cvss_vector": sev.get("CVSS_V3") or sev.get("CVSS_V4", ""),
                "cve_id": next((x for x in a.get("aliases", []) if x.startswith("CVE-")), ""),
                "summary": (a.get("summary") or "").strip(),
                "advisory_url": f"https://github.com/advisories/{a['id']}",
                "fix_url": fixes[0], "other_fix_urls": len(fixes) - 1,
            })

rng = random.Random(seed)
drawn_ids, stats, picked, state = set(), {}, {}, {}
for e in ECOS:
    pool = sorted(pools[e], key=lambda r: r["ghsa_id"])
    rng.shuffle(pool)
    state[e] = {"pool": pool, "pos": 0, "per_pkg": {}}
    picked[e] = []


def take(e, target):
    st = state[e]
    while len(picked[e]) < target and st["pos"] < len(st["pool"]):
        r = st["pool"][st["pos"]]
        st["pos"] += 1
        if r["ghsa_id"] in drawn_ids or any(st["per_pkg"].get(p, 0) >= CAP for p in r["packages"]):
            continue
        picked[e].append(r)
        drawn_ids.add(r["ghsa_id"])
        for p in r["packages"]:
            st["per_pkg"][p] = st["per_pkg"].get(p, 0) + 1


for e in ECOS:
    take(e, per_eco)
base = {e: len(picked[e]) for e in ECOS}
bounds = [dict(base)]
for rnd in EXTEND:
    for e in ECOS:
        take(e, max(rnd.get(e, 0), bounds[-1][e]))
    bounds.append({e: len(picked[e]) for e in ECOS})
out = []
for k in range(len(bounds)):
    for e in ECOS:
        start = 0 if k == 0 else bounds[k - 1][e]
        rows = picked[e][start:bounds[k][e]]
        for i, r in enumerate(rows, start + 1):
            out.append({"ecosystem": e, "order": i, "pilot": "yes" if i <= PILOT_PER_ECO else "", **r,
                        "packages": ", ".join(r["packages"])})
for e in ECOS:
    stats[e] = {"pool": len(state[e]["pool"]), "drawn": len(picked[e]), "base": base[e]}

cols = ["n", "ecosystem", "order", "pilot", "ghsa_id", "packages", "package_tag", "cwe", "cwe1400_category", "year",
        "severity", "cvss_vector", "cve_id", "summary", "advisory_url", "fix_url", "other_fix_urls",
        "package_type", "input_source", "fix_type", "fix_has_test", "maintainer_pushback", "minutes", "notes"]
path = os.path.join(repo, "results", "sample_v1.csv")
with open(path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for n, r in enumerate(out, 1):
        w.writerow({c: r.get(c, "") for c in cols} | {"n": n})
with open(os.path.join(repo, "results", "sample_v1_meta.json"), "w") as f:
    json.dump({"snapshot": snapshot, "seed": seed, "per_ecosystem": per_eco, "extension_targets": EXTEND, "cap_per_package": CAP,
               "pilot_per_ecosystem": PILOT_PER_ECO, "ecosystems": stats}, f, indent=2, sort_keys=True)
print(json.dumps(stats))
