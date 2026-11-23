"""Collect evidence for tagging packages as library, framework, application or plugin, and suggest a tag.

Usage: python3 -I scripts/tag_evidence.py <top_packages.csv> <work-dir> <out.csv>
Evidence comes from the package's GitHub repo (file tree and README), the npm registry and PyPI metadata.
The suggestion is a starting point for a human to confirm, never a final tag.
"""
import csv, json, os, re, subprocess, sys, urllib.parse, urllib.request

src, work, out = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(work, exist_ok=True)


def run(args, timeout=180):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def fetch_json(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.load(r)
    except Exception:
        return None


def repo_signals(url):
    if not url:
        return None
    d = os.path.join(work, re.sub(r"[^A-Za-z0-9]+", "_", url.split("github.com/")[1]))
    if not os.path.isdir(os.path.join(d, ".git")):
        run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout", url, d])
    files = run(["git", "-C", d, "ls-tree", "-r", "--name-only", "HEAD"]).splitlines()
    if not files:
        return {"error": "repo not readable"}
    readme = next((f for f in files if re.fullmatch(r"(?i)readme(\.(md|rst|txt|markdown|adoc))?", f)), None)
    text = run(["git", "-C", d, "show", f"HEAD:{readme}"])[:40000] if readme else ""
    top2 = [f for f in files if f.count("/") <= 1]
    return {
        "dockerfile": any(re.search(r"(?i)(^|/)dockerfile$", f) for f in top2),
        "compose": any(re.search(r"(?i)(^|/)(docker-)?compose[^/]*\.ya?ml$", f) for f in top2),
        "helm": any(re.search(r"(?i)(^|/)(charts?|helm)/", f) for f in files if f.count("/") <= 2),
        "go_cmd": any(f.startswith("cmd/") for f in files),
        "readme": text,
    }


APP_RE = re.compile(r"(?i)(docker run|docker[- ]compose up|self[- ]host|helm install|download the latest release|deploy (it|your own)|run your own instance)")
FW_RE = re.compile(r"(?i)\b(web framework|framework for building|http framework|application framework)\b")


def dep_install_re(eco, name):
    n = re.escape(name.split(":")[-1] if eco == "Maven" else name)
    return re.compile({
        "npm": rf"(?i)(npm (install|i|add)( --save| -S| -D)? +{n}\b|yarn add +{n}\b|pnpm (add|install) +{n}\b|require\(['\"]{n}|from ['\"]{n})",
        "PyPI": rf"(?i)(pip3? install( -U| --upgrade)? +['\"]?{n}\b|uv add +{n}\b|poetry add +{n}\b|^\s*import {n.replace('-', '_')}\b)",
        "Maven": rf"(?i)(<artifactId>\s*{n}\s*</artifactId>|['\"][\w.\-]+:{n}:)",
        "Go": rf"(go get +{re.escape(name)}|import\s+(\(\s*)?\"{re.escape(name)})",
    }[eco], re.M)


rows = list(csv.DictReader(open(src, encoding="utf-8")))
cache = {}
results = []
for i, r in enumerate(rows, 1):
    eco, name, url = r["ecosystem"], r["package"], r["repo"]
    if url not in cache:
        cache[url] = repo_signals(url)
    rs = cache[url] or {}
    ev, app, lib, fw, plugin = [], 0, 0, 0, 0
    weak_app, weak_lib = 0, 0

    if eco == "npm":
        meta = fetch_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
        latest = (meta or {}).get("dist-tags", {}).get("latest")
        v = (meta or {}).get("versions", {}).get(latest, {}) if latest else {}
        has_bin, has_api = bool(v.get("bin")), bool(v.get("main") or v.get("exports") or v.get("types") or v.get("module"))
        if v:
            ev.append(f"npm: bin={'yes' if has_bin else 'no'}, importable entry={'yes' if has_api else 'no'}")
            if has_api:
                weak_lib += 1
            if has_bin and not has_api:
                weak_app += 1
    elif eco == "PyPI":
        meta = fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        cls = (meta or {}).get("info", {}).get("classifiers", []) or []
        fws = [c.split("::")[1].strip() for c in cls if c.startswith("Framework ::")]
        if any(f.lower() == name.lower() for f in fws):
            fw += 1
            ev.append(f"PyPI classifier Framework :: {name}")
        if any("Topic :: Software Development :: Libraries" in c for c in cls):
            lib += 1
            ev.append("PyPI classifier Topic :: Software Development :: Libraries")
        if any(c.startswith("Environment :: Web Environment") for c in cls) and not fw:
            ev.append("PyPI classifier Environment :: Web Environment")
        if any("Intended Audience :: End Users" in c or "Intended Audience :: System Administrators" in c for c in cls):
            app += 1
            ev.append("PyPI audience: end users or sysadmins")
        elif any("Intended Audience :: Developers" in c for c in cls):
            weak_lib += 1
            ev.append("PyPI audience: developers")
    elif eco == "Maven":
        group = name.split(":")[0]
        if group.startswith("org.jenkins-ci.plugins") or group.startswith("io.jenkins.plugins"):
            plugin += 1
            ev.append(f"Maven groupId {group} (Jenkins plugin group)")
        if re.search(r"(?i)(^|[-.])bom$", name.split(":")[-1]):
            ev.append("Maven artifact is a BOM")

    if rs.get("error"):
        ev.append(rs["error"])
    if rs.get("compose"):
        app += 1
        ev.append("repo has a compose file")
    if rs.get("helm"):
        app += 1
        ev.append("repo has Helm charts")
    if rs.get("dockerfile"):
        weak_app += 1
        ev.append("repo has a Dockerfile")
    if eco == "Go" and rs.get("go_cmd"):
        weak_app += 1
        ev.append("Go repo has cmd/")
    text = rs.get("readme", "")
    m = APP_RE.search(text)
    if m:
        app += 1
        ev.append(f"README: '{m.group(1).lower()}'")
    m = dep_install_re(eco, name).search(text)
    if m:
        lib += 1
        ev.append(f"README: '{m.group(0).strip()[:50]}'")
    m = FW_RE.search(text)
    if m:
        fw += 1
        ev.append(f"README: '{m.group(1).lower()}'")

    # Strong signals decide; weak ones (npm entry point, Dockerfile, Go cmd/, PyPI developer audience) only break ties.
    if plugin:
        tag = "plugin"
    elif fw and not app:
        tag = "framework"
    elif app and not lib:
        tag = "application"
    elif lib and not app:
        tag = "library"
    elif lib and app:
        tag = "unsure (mixed signals)"
    elif weak_app and not weak_lib:
        tag = "application (weak)"
    elif weak_lib and not weak_app:
        tag = "library (weak)"
    elif weak_app or weak_lib:
        tag = "unsure (mixed signals)"
    else:
        tag = "unsure (no signals)"
    results.append({**r, "suggested": tag, "evidence": "; ".join(ev)})
    if i % 20 == 0:
        print(f"{i}/{len(rows)}", flush=True)

cols = list(rows[0].keys()) + ["suggested", "evidence"]
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(results)
from collections import Counter
print(Counter(r["suggested"] for r in results))
