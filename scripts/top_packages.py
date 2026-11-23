"""List the packages with the most labelable advisories per ecosystem, for tagging as library, framework or application.

Usage: python3 -I scripts/top_packages.py <advisories/github-reviewed> <out.csv> <top-n> <ecosystem>...
Labelable: GitHub-reviewed, not withdrawn, not CWE-506, references a GitHub commit or PR.
"""
import csv, json, os, re, sys
from collections import Counter, defaultdict

root, out, top_n, ecos = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
link_re = re.compile(r"https://github\.com/([^/]+/[^/]+)/(commit|pull)/")

count = defaultdict(Counter)
repos = defaultdict(Counter)
latest = {}
pool = Counter()
for dp, dirs, fns in os.walk(root):
    dirs.sort()
    for fn in sorted(fns):
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(dp, fn), encoding="utf-8") as f:
            a = json.load(f)
        if a.get("withdrawn") or "CWE-506" in (a.get("database_specific", {}).get("cwe_ids") or []):
            continue
        links = [m.group(1) for r in a.get("references", []) for m in [link_re.search(r.get("url", ""))] if m]
        if not links:
            continue
        pkgs = {(x["package"]["ecosystem"], x["package"]["name"]) for x in a.get("affected", []) if x.get("package", {}).get("ecosystem") in ecos}
        for e in {e for e, _ in pkgs}:
            pool[e] += 1
        for e, p in pkgs:
            count[e][p] += 1
            for r in links:
                repos[(e, p)][r.lower()] += 1
            pub = a.get("published", "")
            if pub > latest.get((e, p), ("", ""))[0]:
                latest[(e, p)] = (pub, (a.get("summary") or "").strip())

with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["ecosystem", "rank", "package", "labelable_advisories", "repo", "latest_summary", "tag", "notes"])
    for e in ecos:
        ranked = sorted(count[e].items(), key=lambda kv: (-kv[1], kv[0]))
        covered = sum(c for _, c in ranked[:top_n])
        for i, (p, c) in enumerate(ranked[:top_n], 1):
            repo = repos[(e, p)].most_common(1)[0][0] if repos[(e, p)] else ""
            w.writerow([e, i, p, c, f"https://github.com/{repo}" if repo else "", latest[(e, p)][1], "", ""])
        print(f"{e}: {pool[e]} labelable advisories across {len(ranked)} packages; top {top_n} hold {covered} "
              f"({100 * covered / sum(count[e].values()):.0f}% of package-advisory pairs); "
              f"packages with 1 advisory: {sum(1 for _, c in ranked if c == 1)}")
