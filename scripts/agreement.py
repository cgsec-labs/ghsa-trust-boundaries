"""Per-field agreement between the human blind labels and the AI labels.

Usage: python3 scripts/agreement.py <blind_review_human.csv> <ai_labels.csv> <out.json>
package_type is compared on every row. The other fields are compared on rows that both
labelers put in scope (library, framework or tool) and that both filled in. A human file with no
package_type column (the second review) is compared on every row both filled in.
"""
import csv
import json
import sys
from collections import Counter

IN_SCOPE = {"library", "framework", "tool"}
FIELDS = ["input_source", "fix_type", "fix_has_test"]


def kappa(pairs):
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return {"rows": n, "raw": round(po, 3), "kappa": round((po - pe) / (1 - pe), 3) if pe < 1 else 1.0}


human_path, ai_path, out_path = sys.argv[1:4]
norm = lambda v: (v or "").strip().lower()
human = list(csv.DictReader(open(human_path, newline="")))
ai = {r["n"]: r for r in csv.DictReader(open(ai_path, newline=""))}

result = {}
if "package_type" in human[0]:
    pt = [(norm(h["package_type"]), norm(ai[h["n"]]["package_type"])) for h in human]
    result["package_type"] = kappa(pt)
    result["scope"] = kappa([(a in IN_SCOPE, b in IN_SCOPE) for a, b in pt])
    both = [h for h in human if norm(h["package_type"]) in IN_SCOPE and norm(ai[h["n"]]["package_type"]) in IN_SCOPE]
else:
    both = human
for f in (x for x in FIELDS if x in human[0]):
    pairs = [(norm(h[f]), norm(ai[h["n"]][f])) for h in both if norm(h[f]) and norm(ai[h["n"]][f])]
    result[f] = kappa(pairs)
json.dump(result, open(out_path, "w"), indent=2, sort_keys=True)
print(json.dumps(result, indent=2, sort_keys=True))
