"""Pre-fill mechanical facts from each fix diff, for rows marked pilot (or all rows with --all).

Usage: python3 -I scripts/prefill_diffs.py <sample.csv> <work-dir> <out.csv> [--all]
For a commit link: the diff of that commit against its parent.
For a pull request link: the diff from the merge base with the default branch to the PR head.
The output is facts only (files, tests, docs, patterns in added lines), never a label.
"""
import csv, os, re, subprocess, sys

src, work, out = sys.argv[1], sys.argv[2], sys.argv[3]
do_all = "--all" in sys.argv
os.makedirs(work, exist_ok=True)


def git(d, *args, timeout=300):
    try:
        p = subprocess.run(["git", "-C", d, *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 1, ""


def repo_dir(owner_repo):
    d = os.path.join(work, owner_repo.replace("/", "__"))
    if not os.path.isdir(os.path.join(d, ".git")):
        os.makedirs(d, exist_ok=True)
        git(d, "init", "-q")
        git(d, "remote", "add", "origin", f"https://github.com/{owner_repo}")
    return d


def commit_range(owner_repo, kind, ref):
    d = repo_dir(owner_repo)
    if kind == "commit":
        rc, _ = git(d, "fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", ref)
        if rc:
            return d, None, "commit not fetchable"
        rc, _ = git(d, "rev-parse", f"{ref}^")
        return (d, (f"{ref}^", ref), None) if rc == 0 else (d, (None, ref), None)
    rc, _ = git(d, "fetch", "-q", "--depth", "300", "--filter=blob:none", "origin", f"refs/pull/{ref}/head:refs/remotes/pr/{ref}")
    if rc:
        return d, None, "PR not fetchable"
    _, date = git(d, "log", "-1", "--format=%cI", f"refs/remotes/pr/{ref}")
    _, sym = git(d, "ls-remote", "--symref", "origin", "HEAD", timeout=60)
    m = re.search(r"ref: refs/heads/(\S+)\s+HEAD", sym)
    branch = m.group(1) if m else "main"
    import datetime
    try:
        head_day = datetime.date.fromisoformat(date.strip()[:10])
    except ValueError:
        head_day = datetime.date.today()
    rc, base = 1, ""
    for days in (120, 400):
        since = (head_day - datetime.timedelta(days=days)).isoformat()
        git(d, "fetch", "-q", f"--shallow-since={since}", "--filter=blob:none", "origin", f"{branch}:refs/remotes/base/{branch}", timeout=420)
        rc, base = git(d, "merge-base", f"refs/remotes/base/{branch}", f"refs/remotes/pr/{ref}")
        if rc == 0 and base.strip():
            break
    if rc or not base.strip():
        return d, None, "PR merge base not found"
    return d, (base.strip(), f"refs/remotes/pr/{ref}"), None


CONFIG_RE = re.compile(r"(?i)(^|/)(\.github/|package(-lock)?\.json$|yarn\.lock$|pnpm-lock\.yaml$|go\.(mod|sum)$|pom\.xml$|setup\.(py|cfg)$|pyproject\.toml$|requirements[^/]*\.txt$|\.gitignore$|\.nvmrc$)")
TEST_RE = re.compile(r"(?i)(^|/)(tests?|spec|__tests__|testdata|test_[^/]*|[^/]*_test\.(go|py)|[^/]*_tests?/|[^/]*\.(test|spec)\.[jt]sx?|[^/]*Test\.java)($|/)")
DOC_RE = re.compile(r"(?i)(\.(md|rst|txt|adoc)$|(^|/)docs?/|(^|/)(changelog|changes|history|news)[^/]*$|(^|/)changelogs?/|(^|/)(NOTICE|LICENSE|COPYING)[^/]*$)")
PATTERNS = [
    ("prototype key check", r"__proto__|['\"]constructor['\"]|['\"]prototype['\"]"),
    ("null-prototype object", r"Object\.create\(\s*null\s*\)"),
    ("own-property check", r"hasOwnProperty|Object\.hasOwn"),
    ("path or prefix checks", r"(normalize|resolve|realpath|Clean|abspath|toRealPath)\b.*|startsWith|HasPrefix|is_relative_to|\.\.[/\\]"),
    ("size or length limit", r"(?i)\b(max[_A-Z]?\w*|limit\w*|length\s*[<>]=?|len\([^)]*\)\s*[<>]|MAX_\w+)"),
    ("escaping or sanitizing", r"(?i)\b(escape\w*|sanitiz\w*|encodeURI\w*|html\.escape|quote\w*)\b"),
    ("allowlist or denylist", r"(?i)\b(allow_?list|white_?list|deny_?list|black_?list|allowed\w*|forbidden\w*)\b"),
    ("safer process call", r"execFile|spawn\([^)]*shell\s*:\s*false|shell\s*=\s*False|exec\.Command\("),
    ("auth or permission check", r"(?i)\b(permission\w*|authoriz\w*|isAdmin|has_perm\w*|checkAccess\w*|forbidden)\b"),
    ("regex change", r"new RegExp|re\.compile|regexp\.MustCompile|Pattern\.compile|/\^?\[.*\]\+?/"),
    ("new error or rejection", r"throw new \w*Error|raise \w+(Error|Exception)|return (nil, )?(fmt\.Errorf|errors\.New)|throw new \w*Exception"),
]


def facts(d, rng):
    a, b = rng
    if a is None:
        rc, names = git(d, "show", "--format=", "--name-status", b)
        rc2, patch = git(d, "show", "--format=", "--unified=0", b)
    else:
        rc, names = git(d, "diff", "--name-status", a, b)
        rc2, patch = git(d, "diff", "--unified=0", a, b)
    if rc or rc2:
        return "diff not readable"
    files = [l.split("\t")[-1] for l in names.splitlines() if l.strip()]
    if not files:
        return "empty diff"
    tests = [f for f in files if TEST_RE.search(f)]
    docs = [f for f in files if DOC_RE.search(f)]
    config = [f for f in files if CONFIG_RE.search(f) and f not in tests]
    src = [f for f in files if f not in tests and f not in docs and f not in config]
    added = [l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = sum(1 for l in patch.splitlines() if l.startswith("-") and not l.startswith("---"))
    src_added = []
    cur = None
    for l in patch.splitlines():
        if l.startswith("+++ "):
            cur = l[6:] if l.startswith("+++ b/") else None
        elif l.startswith("+") and cur in src:
            src_added.append(l[1:])
    hits = [name for name, pat in PATTERNS if any(re.search(pat, l) for l in src_added)]
    parts = [f"{len(files)} files (+{len(added)} -{removed} lines)",
             f"source: {', '.join(src[:3])}{' ...' if len(src) > 3 else ''}" if src else "source: none",
             f"tests touched: {'yes, ' + str(len(tests)) if tests else 'no'}",
             f"docs touched: {'yes' if docs else 'no'}",
             f"build or config files: {len(config)}"]
    if not src and docs:
        parts.append("docs-only change")
    elif not src and config:
        parts.append("no source change, only build or config files")
    if hits:
        parts.append("added source lines mention: " + ", ".join(hits))
    return "; ".join(parts)


rows = list(csv.DictReader(open(src, encoding="utf-8")))
res = []
for r in rows:
    if not do_all and r["pilot"] != "yes":
        continue
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/(commit|pull)/([0-9a-fA-F]+|\d+)", r["fix_url"])
    if not m:
        res.append({"n": r["n"], "ghsa_id": r["ghsa_id"], "prefill": "fix link not recognized"})
        continue
    d, rng, err = commit_range(m.group(1), m.group(2), m.group(3))
    note = err or facts(d, rng)
    if r["other_fix_urls"] not in ("", "0"):
        note += f"; advisory lists {r['other_fix_urls']} more fix links, check if this one looks partial"
    res.append({"n": r["n"], "ghsa_id": r["ghsa_id"], "prefill": note})
    print(r["n"], r["ghsa_id"], note[:140], flush=True)

with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["n", "ghsa_id", "prefill"])
    w.writeheader()
    w.writerows(res)
