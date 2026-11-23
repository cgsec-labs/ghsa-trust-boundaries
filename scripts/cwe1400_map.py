"""Extract the CWE-1400 Comprehensive Categorization mapping from MITRE's view XML.

Usage: python3 -I scripts/cwe1400_map.py <1400.xml> <out.csv> [<1400.xml.zip> <source-url>]
The XML comes from https://cwe.mitre.org/data/definitions/1400.html (Downloads, XML).
Writes one row per weakness: cwe_id, cwe_name, status, category_id, category_name.
Also writes cwe1400_meta.json (CWE version and date) next to the CSV, plus the sha256 and
source URL of the downloaded zip when those are given.
"""
import csv, hashlib, json, os, sys
import xml.etree.ElementTree as ET

src, out = sys.argv[1], sys.argv[2]
root = ET.parse(src).getroot()
ns = {"c": root.tag.split("}")[0].strip("{")}

weak = {w.get("ID"): (w.get("Name"), w.get("Status")) for w in root.iterfind("c:Weaknesses/c:Weakness", ns)}
rows, seen = [], {}
for g in root.iterfind("c:Groupings/c:Grouping", ns):
    gname = g.get("Name").replace("Comprehensive Categorization: ", "")
    for m in g.iterfind("c:Relationships/c:Has_Member", ns):
        cid = m.get("CWE_ID")
        if cid in weak:
            if cid in seen:
                sys.exit(f"CWE-{cid} is in more than one category: {seen[cid]} and {gname}")
            seen[cid] = gname
            rows.append([f"CWE-{cid}", weak[cid][0], weak[cid][1], f"CWE-{g.get('ID')}", gname])

missing = sorted(set(weak) - set(seen), key=int)
rows.sort(key=lambda r: int(r[0].split("-")[1]))
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["cwe_id", "cwe_name", "status", "category_id", "category_name"])
    w.writerows(rows)
with open(os.path.join(os.path.dirname(out), "cwe1400_meta.json"), "w") as f:
    meta = {"cwe_version": root.get("Version"), "cwe_date": root.get("Date"), "weaknesses": len(weak)}
    if len(sys.argv) > 4:
        meta["zip_sha256"] = hashlib.sha256(open(sys.argv[3], "rb").read()).hexdigest()
        meta["zip_url"] = sys.argv[4]
    json.dump(meta, f, indent=2)
print(f"catalog version {root.get('Version')} dated {root.get('Date')}: {len(weak)} weaknesses, {len(rows)} mapped, {len(missing)} unmapped {missing[:10]}")
