"""Full-diff evidence for rechecking fix_type.

For each row: whether the labeling digest was cut off, and the added lines across all source files
that carry fix_type signals (reject/abort vs escape/harden), plus removal counts.

Usage: python3 -I fullfix.py <sample.csv> <work-dir> <out.jsonl> <n> [<n> ...]
"""
import csv, json, os, re, subprocess, sys, datetime

sample, work, out = sys.argv[1], sys.argv[2], sys.argv[3]
want = [int(x) for x in sys.argv[4:]]
rows = {int(r["n"]): r for r in csv.DictReader(open(sample, encoding="utf-8"))}


def git(d, *a, timeout=300):
    try:
        p = subprocess.run(["git", "-C", d, *a], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 1, ""


def has(d, obj):
    return git(d, "cat-file", "-e", obj + "^{commit}")[0] == 0


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
        if not (has(d, ref) and has(d, ref + "^")):
            if git(d, "fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", ref)[0]:
                return d, None
            if not has(d, ref + "^"):
                git(d, "fetch", "-q", "--deepen", "1", "--filter=blob:none", "origin", ref)
        return d, (f"{ref}^", ref) if has(d, ref + "^") else (None, ref)
    pr = f"refs/remotes/pr/{ref}"
    if git(d, "rev-parse", "--verify", "-q", pr)[0]:
        if git(d, "fetch", "-q", "--depth", "300", "--filter=blob:none", "origin", f"refs/pull/{ref}/head:{pr}")[0]:
            return d, None
    _, refs = git(d, "for-each-ref", "--format=%(refname)", "refs/remotes/base/")
    base_refs = refs.split()
    if not base_refs:
        _, date = git(d, "log", "-1", "--format=%cI", pr)
        _, sym = git(d, "ls-remote", "--symref", "origin", "HEAD", timeout=60)
        m = re.search(r"ref: refs/heads/(\S+)\s+HEAD", sym)
        br = m.group(1) if m else "main"
        try:
            day = datetime.date.fromisoformat(date.strip()[:10])
        except ValueError:
            day = datetime.date.today()
        git(d, "fetch", "-q", f"--shallow-since={(day - datetime.timedelta(days=400)).isoformat()}", "--filter=blob:none", "origin", f"{br}:refs/remotes/base/{br}", timeout=420)
        base_refs = [f"refs/remotes/base/{br}"]
    bref = base_refs[0]
    rc, base = git(d, "merge-base", bref, pr)
    if rc or not base.strip():
        return d, None
    head = git(d, "rev-parse", pr)[1].strip()
    if base.strip() != head:
        return d, (base.strip(), head)
    chain = set(git(d, "rev-list", "--first-parent", bref)[1].split())
    if head in chain:
        return d, (f"{head}^", head)
    for c in git(d, "rev-list", "--topo-order", head)[1].split():
        if c in chain:
            return d, (c, head)
    return d, None


SKIP = re.compile(r"(?i)(\.(md|rst|txt|lock|min\.js|map|snap|svg|png|json)$|(^|/)(dist|vendor|node_modules|docs?)/|package-lock|yarn\.lock|go\.sum)")
TEST = re.compile(r"(?i)(^|/)(tests?|spec|__tests__|testdata)(/|$)|_test\.(go|py)$|\.(test|spec)\.[jt]sx?$|Test\.java$|(^|/)test_[^/]*$|(^|/)tests?\.[cm]?[jt]s$")
REJECT = re.compile(r"throw |raise |panic\(|errors?\.New|Errorf|return [^;]*err\b|new \w*(Error|Exception)\(|reject|deny|denied|forbid|abort|\b40[03]\b|not allowed|refus|return false|BadRequest|http\.Error|IllegalArgument|SecurityException|ValueError|TypeError")
HARDEN = re.compile(r"(?i)escape|encode|quote|sanitiz|\bclean|safe|secure_processing|FEATURE_SECURE|disallow-doctype|external-(general|parameter)|xxe|execFile|spawn\(|recover\(|Object\.create\(null\)|constant.?time|compare_digest|ConstantTimeCompare")

with open(out, "a") as fo:
    for n in want:
        r = rows[n]
        rec = {"n": n}
        m = re.match(r"https://github\.com/([^/]+/[^/]+)/(commit|pull)/([0-9a-fA-F]+|\d+)", r["fix_url"])
        rg = None
        if m:
            d, rg = rng(m.group(1), m.group(2), m.group(3))
        if not rg:
            rec["status"] = "no diff"
            fo.write(json.dumps(rec) + "\n"); fo.flush(); continue
        a_, b_ = rg
        args = ["show", "--format=", b_] if a_ is None else ["diff", a_, b_]
        _, names = git(d, *(args[:1] + ["--name-only"] + args[1:]))
        files = [f for f in names.splitlines() if f.strip()]
        srcs = [f for f in files if not SKIP.search(f) and not TEST.search(f)]
        per = max(10, 36 // max(1, min(3, len(srcs))))
        cut = len(srcs) > 3
        added = removed = 0
        sig = []
        for f in srcs[:40]:
            _, p = git(d, *(args + ["--unified=0", "--", f]))
            ls = [l for l in p.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
            if len(ls) > per:
                cut = True
            for l in ls:
                if l.startswith("+"):
                    added += 1
                    t = l[1:].strip()
                    kind = ("R" if REJECT.search(t) else "") + ("H" if HARDEN.search(t) else "")
                    if kind and len(sig) < 30:
                        sig.append(f"{kind} {os.path.basename(f)}: {t[:150]}")
                else:
                    removed += 1
        rec.update(status="ok", cut=cut, src_files=len(srcs), added=added, removed=removed, signals=sig)
        fo.write(json.dumps(rec) + "\n"); fo.flush()
        print(n, "cut" if cut else "full", len(srcs), added, removed, len(sig), flush=True)
