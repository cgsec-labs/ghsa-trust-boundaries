"""Build the labeling workbook from the two sample CSVs."""
import csv, sys
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Alignment

s100, s500, out = sys.argv[1], sys.argv[2], sys.argv[3]
order = ["n", "ghsa_id", "package", "cwe", "fix_url",
         "input_source", "entry_point", "fix_type", "fix_has_test", "maintainer_pushback", "minutes", "notes",
         "year", "severity", "cvss_vector", "cve_id", "summary", "other_fix_urls", "advisory_url"]
widths = {"n": 5, "ghsa_id": 22, "package": 22, "cwe": 14, "fix_url": 40, "input_source": 18, "entry_point": 24,
          "fix_type": 18, "fix_has_test": 12, "maintainer_pushback": 18, "minutes": 9, "notes": 30, "year": 7,
          "severity": 11, "cvss_vector": 44, "cve_id": 16, "summary": 50, "other_fix_urls": 8, "advisory_url": 40}
fill = PatternFill("solid", fgColor="F3F3F3")
label_fill = PatternFill("solid", fgColor="E8F0FE")

wb = Workbook()
wb.remove(wb.active)
for title, path in (("Sample 100", s100), ("Sample 500", s500)):
    ws = wb.create_sheet(title)
    ws.append(order)
    for c in ws[1]:
        c.fill = label_fill if c.value in order[5:12] else fill
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            row = []
            for k in order:
                v = r[k]
                if k in ("n", "year", "other_fix_urls") and v.isdigit():
                    v = int(v)
                row.append(v)
            ws.append(row)
    for i, k in enumerate(order, 1):
        ws.column_dimensions[ws.cell(1, i).column_letter].width = widths[k]
    ws.freeze_panes = "C2"

ws = wb.create_sheet("Schema v0")
rows = [
    ["field", "who fills", "values", "meaning"],
    ["input_source", "you", "caller code / end-user via caller / file or config / network / not boundary / unclear",
     "Where the attacker-controlled input comes from before it reaches the vulnerable code"],
    ["entry_point", "you", "free text", "Exported function and parameter that carried the input, e.g. merge(target, source)"],
    ["fix_type", "you", "validation added / internal hardening / docs only / feature removed / other",
     "What the fix diff actually did"],
    ["fix_has_test", "you", "yes / no", "Fix commit or PR adds or changes a test"],
    ["maintainer_pushback", "you", "yes / no / unknown",
     "Maintainer argued it was the caller's responsibility or not a vulnerability (from the PR or issue thread)"],
    ["minutes", "you", "number", "Time spent on this row"],
    ["notes", "you", "free text", "Anything that did not fit"],
    ["cvss_vector", "pre-filled", "", "CVSS v3 vector (v4 if no v3) from the advisory: the reporter's assumed attacker position"],
    ["cve_id", "pre-filled", "", "CVE alias if the advisory has one"],
    ["source", "pre-filled", "", "github/advisory-database snapshot 3d08969 (2026-11-15); GitHub-reviewed npm, has commit/PR link, not withdrawn, no CWE-506"],
    ["sampling", "pre-filled", "", "Sample 100: seed 20261115. Sample 500: seed 20261116, excludes the 100. Both split 2026 vs earlier in proportion"],
]
for r in rows:
    ws.append(r)
for c in ws[1]:
    c.fill = fill
for col, w in zip("ABCD", (20, 12, 60, 90)):
    ws.column_dimensions[col].width = w
for row in ws.iter_rows(min_row=2):
    for c in row:
        c.alignment = Alignment(wrap_text=True, vertical="top")
wb.save(out)
print("ok")
