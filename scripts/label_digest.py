"""Print a compact digest of sample rows for labeling: advisory text plus the fix diff (source and test files). Used by the AI labeler; it shows at most 3 source files and about 36 changed lines, see docs/labeling-criteria.md.

Usage: python3 -I digest.py <sample.csv> <advisories-root> <work-dir> <n> [<n> ...]
"""
import csv, json, os, re, subprocess, sys, glob, datetime

sample, adv_root, work = sys.argv[1], sys.argv[2], sys.argv[3]
want = [int(x) for x in sys.argv[4:]]
rows = {int(r["n"]): r for r in csv.DictReader(open(sample, encoding="utf-8"))}


def git(d, *a, timeout=300):
    try:
        p = subprocess.run(["git", "-C", d, *a], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 1, ""


def repo_dir(o):
    d = os.path.join(work, o.replace("/", "__"))
    if not os.path.isdir(os.path.join(d, ".git")):
        os.makedirs(d, exist_ok=True)
        git(d, "init", "-q")
        git(d, "remote", "add", "origin", f"https://github.com/{o}")
    return d


def rng(o, kind, ref):
    d = repo_dir(o)
    if kind == "commit":
        if git(d, "fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", ref)[0]:
            return d, None
        if git(d, "rev-parse", "--verify", "-q", f"{ref}^")[0]:
            git(d, "fetch", "-q", "--deepen", "1", "--filter=blob:none", "origin", ref)
        return d, (f"{ref}^", ref) if git(d, "rev-parse", "--verify", "-q", f"{ref}^")[0] == 0 else (None, ref)
    if git(d, "fetch", "-q", "--depth", "300", "--filter=blob:none", "origin", f"refs/pull/{ref}/head:refs/remotes/pr/{ref}")[0]:
        return d, None
    _, date = git(d, "log", "-1", "--format=%cI", f"refs/remotes/pr/{ref}")
    _, sym = git(d, "ls-remote", "--symref", "origin", "HEAD", timeout=60)
    m = re.search(r"ref: refs/heads/(\S+)\s+HEAD", sym)
    br = m.group(1) if m else "main"
    try:
        day = datetime.date.fromisoformat(date.strip()[:10])
    except ValueError:
        day = datetime.date.today()
    for days in (120, 400):
        git(d, "fetch", "-q", f"--shallow-since={(day - datetime.timedelta(days=days)).isoformat()}", "--filter=blob:none", "origin", f"{br}:refs/remotes/base/{br}", timeout=420)
        rc, base = git(d, "merge-base", f"refs/remotes/base/{br}", f"refs/remotes/pr/{ref}")
        if rc == 0 and base.strip():
            break
    else:
        return d, None
    head = git(d, "rev-parse", f"refs/remotes/pr/{ref}")[1].strip()
    if base.strip() != head:
        return d, (base.strip(), head)
    # merged PR: find where the PR branched off the base branch's first-parent line
    chain = set(git(d, "rev-list", "--first-parent", f"refs/remotes/base/{br}")[1].split())
    if head in chain:
        return d, (f"{head}^", head)  # rebase or fast-forward merge: last commit only
    for c in git(d, "rev-list", "--topo-order", head)[1].split():
        if c in chain:
            return d, (c, head)
    return d, None


SKIP = re.compile(r"(?i)(\.(md|rst|txt|lock|min\.js|map|snap|svg|png|json)$|(^|/)(dist|vendor|node_modules|docs?)/|package-lock|yarn\.lock|go\.sum)")
TEST = re.compile(r"(?i)(^|/)(tests?|spec|__tests__|testdata)(/|$)|_test\.(go|py)$|\.(test|spec)\.[jt]sx?$|Test\.java$|(^|/)test_[^/]*$|(^|/)tests?\.[cm]?[jt]s$")

for n in want:
    r = rows[n]
    paths = glob.glob(os.path.join(adv_root, "*", "*", r["ghsa_id"], r["ghsa_id"] + ".json"))
    a = json.load(open(paths[0])) if paths else {}
    print(f"===== n={n} {r['ecosystem']} {r['ghsa_id']} pkg={r['packages']} tag={r['package_tag']} cwe={r['cwe']}")
    print("SUMMARY:", r["summary"])
    det = re.sub(r"\s+", " ", a.get("details", ""))[:600]
    print("DETAILS:", det)
    refs = [x["url"] for x in a.get("references", []) if re.search(r"github\.com/[^/]+/[^/]+/(commit|pull|issues)/", x.get("url", ""))]
    print("LINKS:", " ".join(refs[:6]))
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/(commit|pull)/([0-9a-fA-F]+|\d+)", r["fix_url"])
    if not m:
        print("DIFF: link not recognized")
        continue
    d, rg = rng(m.group(1), m.group(2), m.group(3))
    if not rg:
        print("DIFF: not fetchable")
        continue
    a_, b_ = rg
    args = ["show", "--format=", b_] if a_ is None else ["diff", a_, b_]
    _, names = git(d, *(args[:1] + ["--name-only"] + args[1:]))
    files = [f for f in names.splitlines() if f.strip()]
    tests = [f for f in files if TEST.search(f)]
    print(f"FILES ({len(files)}):", ", ".join(files[:12]), "..." if len(files) > 12 else "")
    print("TESTS:", ", ".join(tests[:5]) or "none")
    srcs = [f for f in files if not SKIP.search(f) and f not in tests][:3]
    budget = 36
    for f in srcs:
        _, p = git(d, *(args + ["--unified=1", "--", f]))
        lines = [l for l in p.splitlines() if (l.startswith("+") or l.startswith("-")) and not l.startswith(("+++", "---"))]
        take = lines[: max(10, budget // max(1, len(srcs)))]
        print(f"--- {f} ({len(lines)} changed lines)")
        for l in take:
            print("   ", l[:160])
