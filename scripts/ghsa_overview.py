"""Overview of all GitHub-reviewed advisories by ecosystem: counts, CWE, CVSS metrics and vectors.

Usage: python3 -I scripts/ghsa_overview.py <advisories/github-reviewed> <snapshot-commit> <repo-root> [snapshot-date]
Needs results/cwe1400_map.csv (from scripts/cwe1400_map.py) for CWE names and categories.
Writes results/ghsa_overview.json, docs/overview.md and docs/ecosystems/<ecosystem>.md
"""
import json, os, re, sys
from collections import Counter, defaultdict

root, snapshot, repo = sys.argv[1], sys.argv[2], sys.argv[3]
snapshot_date = sys.argv[4] if len(sys.argv) > 4 else ""

COMMIT_RE = re.compile(r"github\.com/[^/]+/[^/]+/(commit|pull)/")
V3_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
V4_KEYS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

import csv
CWE_MAP = {}
with open(os.path.join(repo, "results", "cwe1400_map.csv"), encoding="utf-8") as _f:
    for _r in csv.DictReader(_f):
        CWE_MAP[_r["cwe_id"]] = (_r["cwe_name"], f'{_r["category_name"]} ({_r["category_id"]})')
NOT_IN_1400 = "Not a CWE-1400 weakness"
with open(os.path.join(repo, "results", "cwe1400_meta.json"), encoding="utf-8") as _f:
    CWE_META = json.load(_f)


def cwe_name(c):
    return CWE_MAP.get(c, ("", ""))[0]


def categories_of(cwes):
    if not cwes:
        return {"No CWE"}
    return {CWE_MAP[c][1] if c in CWE_MAP else NOT_IN_1400 for c in cwes}


def parse_vector(vec):
    return dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)


def top(counter, n=None):
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return items if n is None else items[:n]


def slug(eco):
    return re.sub(r"[^a-z0-9]+", "-", eco.lower()).strip("-")


eco = defaultdict(lambda: defaultdict(Counter))
unique_total = 0
for dp, dirs, fns in os.walk(root):
    dirs.sort()
    for fn in sorted(fns):
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(dp, fn), encoding="utf-8") as f:
            a = json.load(f)
        unique_total += 1
        ecos = {x.get("package", {}).get("ecosystem") or "(none)" for x in a.get("affected", [])} or {"(none)"}
        cwes = set(a.get("database_specific", {}).get("cwe_ids") or [])
        year = (a.get("published") or "????")[:4]
        sev = a.get("database_specific", {}).get("severity") or "UNKNOWN"
        fix = any(COMMIT_RE.search(r.get("url", "")) for r in a.get("references", []))
        withdrawn = bool(a.get("withdrawn"))
        cve = any(x.startswith("CVE-") for x in a.get("aliases", []))
        v3 = next((s["score"] for s in a.get("severity", []) if s.get("type") == "CVSS_V3"), None)
        v4 = next((s["score"] for s in a.get("severity", []) if s.get("type") == "CVSS_V4"), None)
        pkgs_by_eco = defaultdict(set)
        for x in a.get("affected", []):
            pk = x.get("package", {})
            if pk.get("name"):
                pkgs_by_eco[pk.get("ecosystem") or "(none)"].add(pk["name"])
        for e in ecos:
            d = eco[e]
            d["n"]["total"] += 1
            d["n"]["withdrawn"] += withdrawn
            d["n"]["fix_link"] += fix
            d["n"]["cve_alias"] += cve
            d["n"]["no_cwe"] += not cwes
            d["n"]["cvss_v3"] += v3 is not None
            d["n"]["cvss_v4"] += v4 is not None
            d["n"]["no_cvss"] += v3 is None and v4 is None
            d["year"][year] += 1
            d["severity"][sev] += 1
            for g in categories_of(cwes):
                d["group"][g] += 1
            for c in cwes:
                d["cwe"][c] += 1
                if c not in CWE_MAP:
                    d["cwe_not_in_1400"][c] += 1
            d["n"]["v3_only"] += v3 is not None and v4 is None
            d["n"]["v4_only"] += v4 is not None and v3 is None
            d["n"]["v3_and_v4"] += v3 is not None and v4 is not None
            av = parse_vector(v3).get("AV") if v3 else (parse_vector(v4).get("AV") if v4 else None)
            if av:
                d["av_any"][av] += 1
            if v3 and v4 and parse_vector(v3).get("AV") != parse_vector(v4).get("AV"):
                d["n"]["av_v3_v4_differ"] += 1
            if v3:
                m = parse_vector(v3)
                for k in V3_KEYS:
                    d["v3_" + k][m.get(k, "?")] += 1
                d["v3_vector"]["/".join(f"{k}:{m.get(k, '?')}" for k in V3_KEYS)] += 1
            if v4:
                m = parse_vector(v4)
                for k in V4_KEYS:
                    d["v4_" + k][m.get(k, "?")] += 1
                d["v4_vector"]["/".join(f"{k}:{m.get(k, '?')}" for k in V4_KEYS)] += 1
            for p in pkgs_by_eco.get(e, ()):
                d["package"][p] += 1

out = {"snapshot": snapshot, "snapshot_date": snapshot_date, "cwe_version": CWE_META["cwe_version"], "cwe_date": CWE_META["cwe_date"], "unique_advisories": unique_total, "ecosystems": {}}
for e, d in eco.items():
    out["ecosystems"][e] = {
        **dict(d["n"]),
        "distinct_packages": len(d["package"]),
        "year": dict(sorted(d["year"].items())),
        "severity": dict(d["severity"]),
        "group": dict(d["group"]),
        "cwe_top": top(d["cwe"], 30),
        "cwe_not_in_1400": top(d["cwe_not_in_1400"]),
        "av_v3_else_v4": dict(d["av_any"]),
        "packages_top": top(d["package"], 15),
        **{k: dict(v) for k, v in d.items() if k.startswith("v3_") or k.startswith("v4_")},
    }
    out["ecosystems"][e]["v3_vector"] = top(d["v3_vector"], 15)
    out["ecosystems"][e]["v4_vector"] = top(d["v4_vector"], 15)

os.makedirs(os.path.join(repo, "results"), exist_ok=True)
with open(os.path.join(repo, "results", "ghsa_overview.json"), "w") as f:
    json.dump(out, f, indent=2, sort_keys=True)


def pct(x, n):
    return f"{100 * x / n:.1f}%" if n else "0%"


def table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


METRIC_NAMES = {"AV": "Attack Vector", "AC": "Attack Complexity", "AT": "Attack Requirements", "PR": "Privileges Required",
                "UI": "User Interaction", "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability",
                "VC": "Vulnerable System Confidentiality", "VI": "Vulnerable System Integrity",
                "VA": "Vulnerable System Availability", "SC": "Subsequent System Confidentiality",
                "SI": "Subsequent System Integrity", "SA": "Subsequent System Availability"}
SEV_ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]

order = sorted(out["ecosystems"].items(), key=lambda kv: (-kv[1]["total"], kv[0]))
eco_dir = os.path.join(repo, "docs", "ecosystems")
os.makedirs(eco_dir, exist_ok=True)

for e, s in order:
    n = s["total"]
    L = [f"# {e}", "",
         f"GitHub-reviewed advisories affecting the {e} ecosystem. Snapshot `{snapshot}`. Generated by `scripts/ghsa_overview.py`.",
         "", "[Back to overview](../overview.md)", "", "## Summary", "",
         table(["Measure", "Count", "Share"], [
             ["Advisories", n, "100%"],
             ["Distinct packages", s["distinct_packages"], ""],
             ["Withdrawn", s["withdrawn"], pct(s["withdrawn"], n)],
             ["Has a GitHub commit or PR link", s["fix_link"], pct(s["fix_link"], n)],
             ["Has a CVE alias", s["cve_alias"], pct(s["cve_alias"], n)],
             ["No CWE", s["no_cwe"], pct(s["no_cwe"], n)],
             ["CVSS v3 vector only", s.get("v3_only", 0), pct(s.get("v3_only", 0), n)],
             ["CVSS v4 vector only", s.get("v4_only", 0), pct(s.get("v4_only", 0), n)],
             ["Both CVSS v3 and v4", s.get("v3_and_v4", 0), pct(s.get("v3_and_v4", 0), n)],
             ["No CVSS vector", s["no_cvss"], pct(s["no_cvss"], n)],
             ["v3 and v4 disagree on attack vector", s.get("av_v3_v4_differ", 0), pct(s.get("av_v3_v4_differ", 0), s.get("v3_and_v4", 0)) + " of both"]]),
         "", "## Attack vector, any CVSS version", "",
         "Attack Vector has the same values in CVSS v3 and v4, so this uses the v3 vector where present and the v4 vector otherwise.", "",
         table(["Attack vector", "Advisories", "Share of scored"], [[k, v, pct(v, sum(s["av_v3_else_v4"].values()))] for k, v in sorted(s["av_v3_else_v4"].items(), key=lambda kv: (-kv[1], kv[0]))]),
         "", "## Published by year", "",
         table(["Year", "Advisories"], [[y, c] for y, c in s["year"].items()]),
         "", "## Severity", "",
         table(["Severity", "Advisories", "Share"], [[k, s["severity"].get(k, 0), pct(s["severity"].get(k, 0), n)] for k in SEV_ORDER if s["severity"].get(k)]),
         "", "## MITRE CWE-1400 categories", "",
         f"Each CWE belongs to exactly one category in MITRE's CWE-1400 Comprehensive Categorization (CWE {CWE_META['cwe_version']}). An advisory with CWEs in several categories is counted once under each, so shares can add up to more than 100%.", "",
         table(["Category", "Advisories", "Share"], [[g, c, pct(c, n)] for g, c in sorted(s["group"].items(), key=lambda kv: (-kv[1], kv[0]))]),
         "", "## Top CWEs", "",
         "An advisory with several CWEs is counted once under each.", "",
         table(["CWE", "Name", "CWE-1400 category", "Advisories", "Share"], [[c, cwe_name(c), CWE_MAP.get(c, ("", NOT_IN_1400))[1], k, pct(k, n)] for c, k in s["cwe_top"]]),
         ]
    if s["cwe_not_in_1400"]:
        L += ["", "IDs used in these advisories that are not CWE-1400 weaknesses (usually CWE categories, views or retired IDs): " + ", ".join(f"{c} ({k})" for c, k in s["cwe_not_in_1400"]) + "."]
    for ver, keys, cnt in (("v3", V3_KEYS, s["cvss_v3"]), ("v4", V4_KEYS, s["cvss_v4"])):
        if not cnt:
            continue
        L += ["", f"## CVSS {ver} metrics", "", f"Out of {cnt} advisories with a CVSS {ver} vector.", ""]
        rows = []
        for k in keys:
            dist = s.get(f"{ver}_{k}", {})
            rows.append([f"{k} ({METRIC_NAMES[k]})", ", ".join(f"{v}: {c} ({pct(c, cnt)})" for v, c in sorted(dist.items(), key=lambda kv: (-kv[1], kv[0])))])
        L += [table(["Metric", "Values"], rows), "", f"### Most common CVSS {ver} vectors", "",
              table(["Vector", "Advisories", "Share"], [[f"`{v}`", c, pct(c, cnt)] for v, c in s[f"{ver}_vector"]])]
    L += ["", "## Packages with the most advisories", "",
          table(["Package", "Advisories"], [[f"`{p}`", c] for p, c in s["packages_top"]]), ""]
    with open(os.path.join(eco_dir, slug(e) + ".md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))

rows = []
for e, s in order:
    n = s["total"]
    top = min(s["group"].items(), key=lambda kv: (-kv[1], kv[0]))
    scored = sum(s["av_v3_else_v4"].values())
    rows.append([f"[{e}](ecosystems/{slug(e)}.md)", n, s["year"].get("2026", 0), s["distinct_packages"],
                 pct(s["fix_link"], n), pct(s["withdrawn"], n), f"{top[0]} ({pct(top[1], n)})",
                 pct(s["av_v3_else_v4"].get("N", 0), scored)])
cats = sorted({g for _, s in order for g in s["group"]}, key=lambda g: (-sum(s["group"].get(g, 0) for _, s in order), g))
main = [e for e, _ in order][:8]
cat_rows = [[g] + [pct(dict(order)[e]["group"].get(g, 0), dict(order)[e]["total"]) for e in main] for g in cats]
O = ["# GitHub-reviewed advisories by ecosystem", "",
     f"Snapshot `{snapshot}` of github/advisory-database, `advisories/github-reviewed` only. Generated by `scripts/ghsa_overview.py`.", "",
     f"{unique_total} unique advisories. One advisory can affect packages in more than one ecosystem, so the ecosystem totals add up to more than that.", "",
     "The labeling sample does not use all of these. It draws only accepted advisories, leaving out withdrawn ones, and only those whose references include a GitHub commit or pull request (the Fix link column). So its findings describe what maintainers accepted as the library's job, not where the line between library and caller truly lies, and they say nothing about advisories without a public fix link.", "",
     table(["Ecosystem", "Advisories", "Published 2026", "Packages", "Fix link", "Withdrawn", "Largest CWE-1400 category", "AV:N"], rows), "",
     "Column notes:", "",
     "- Fix link: advisory references at least one GitHub commit or pull request.",
     "- Largest CWE-1400 category: the MITRE category that the most advisories in the ecosystem touch.",
     "- AV:N: share of scored advisories whose attack vector is Network, using the CVSS v3 vector where present and v4 otherwise.", "",
     "## MITRE CWE-1400 categories by ecosystem", "",
     "Share of each ecosystem's advisories that touch each category. An advisory with CWEs in several categories counts under each.", "",
     table(["Category"] + main, cat_rows), "",
     "## About the CWE grouping", "",
     f"Categories come from MITRE's CWE-1400 Comprehensive Categorization for Software Assurance Trends, CWE version {CWE_META['cwe_version']} ({CWE_META['cwe_date']}). Every CWE weakness belongs to exactly one category. The mapping is in `results/cwe1400_map.csv`, extracted from MITRE's view XML by `scripts/cwe1400_map.py`.", "",
     "The categories describe the kind of weakness, not who controls the input. For example, SSRF (CWE-918) and open redirect (CWE-601) sit under Access Control, prototype pollution (CWE-1321) and deserialization (CWE-502) under Resource Control, and ReDoS (CWE-1333) under Resource Lifecycle Management.", "",
     "CWE content is from the MITRE Common Weakness Enumeration, https://cwe.mitre.org, used under the CWE terms of use.", ""]
with open(os.path.join(repo, "docs", "overview.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(O))
snap_label = f"`{snapshot}`" + (f" ({snapshot_date})" if snapshot_date else "")
R = ["<!-- overview:start -->", "## Overview across all ecosystems", "",
     f"Advisory snapshot {snap_label}, CWE {CWE_META['cwe_version']} ({CWE_META['cwe_date']}). Refreshed weekly by a GitHub Action.", "",
     f"{unique_total} unique GitHub-reviewed advisories. One advisory can cover more than one ecosystem, so the rows add up to more than that. Each breakdown page covers MITRE CWE-1400 categories, top CWEs, CVSS v3 and v4 metrics, the most common full vectors, severity, years and the packages with the most advisories.", "",
     table(["Ecosystem", "Advisories", "Largest CWE-1400 category", "Details"],
           [[e, s["total"], f"{min(s['group'].items(), key=lambda kv: (-kv[1], kv[0]))[0]}", f"[breakdown](docs/ecosystems/{slug(e)}.md)"] for e, s in order]), "",
     "The full comparison table is in [docs/overview.md](docs/overview.md). Weekly history is in [results/history.csv](results/history.csv).",
     "<!-- overview:end -->"]
readme = os.path.join(repo, "README.md")
with open(readme, encoding="utf-8") as f:
    txt = f.read()
a, b = txt.index("<!-- overview:start -->"), txt.index("<!-- overview:end -->") + len("<!-- overview:end -->")
with open(readme, "w", encoding="utf-8") as f:
    f.write(txt[:a] + "\n".join(R) + txt[b:])
print(json.dumps({"unique": unique_total, "ecosystems": {e: s["total"] for e, s in order}}, indent=1))
