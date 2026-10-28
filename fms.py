# modules/fms/fms.py
"""
FMS - file inventory: what is where, by content. The first part of the File Management System (planned: node registry, inventory manifests, rules as data, stakes-based staging, resumable transfers).
A scan walks a root (a folder on this server) and writes a manifest: each file's path, size, modification time and - in a full scan - its SHA-256. A file with the same size and time as in the root's last finished scan
keeps that scan's hash, so a rescan only reads what changed. A scan cut off by a restart (or stopped) continues where it stopped.
Manifests compare: a scan against the root's previous one (added, removed, changed, moved), or against any other manifest - another root, or one exported from another portal instance and imported here
(by path: what differs where the layout is the same; by content: what is on one side only, wherever it sits). Duplicates: files with the same content (full scans), or the same name and size.
FMS only reads the roots; it never changes, moves or deletes a file there.
Data at data/fms/: roots.txt ("name | folder" per line), scans/<root>/<scan id>.jsonl.gz (one JSON list per file: [path, size, mtime_ns, sha256 or ""]) with <scan id>.json beside it (its summary; a scan that
has not finished keeps the files done so far in <scan id>.part), imported/<name>.jsonl.gz (manifests from elsewhere). Other modules reach it through the "fms" service.
"""
import io, os, re, csv, gzip, html, json, stat, asyncio, hashlib, posixpath
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response

MODULE_META = {"label": "FMS", "icon": "&#x1F5C2;", "description": "File inventory: scan folders, see what changed, compare copies, find duplicates"}
router = APIRouter()
ENV = {}
UI = IM = None
DATA = Path("./data/fms")
SHOW = 300         # rows listed per category on screen (the CSV download has all)
_JOBS = {}         # root -> live counters of its running scan
_TASKS = set()

def init_module(env: dict):
    global UI, IM
    ENV.update(env)
    UI = env["templates"].env.globals.get("UI")
    for d in ("scans", "imported"): (DATA / d).mkdir(parents=True, exist_ok=True)
    for f in (DATA / "scans").glob("*/*.json"):   # scans that were running when the server stopped are continued from their .part
        s = json.loads(f.read_text(encoding="utf-8"))
        if s["state"] == "running": f.write_text(json.dumps({**s, "state": "stopped"}), encoding="utf-8")
    IM = env["InterfaceManager"](nesting_level=1, db_path="fms/im_registry.db")
    IM.scripts.update({f"fms_{k}": [fn] for k, fn in {"view": _h_view, "scan": _h_scan, "stop": _h_stop, "poll": _h_poll, "roots_save": _h_roots_save, "forget": _h_forget}.items()})
    env["register_service"]("fms", {"roots": roots, "scans": scans, "manifest": manifest, "compare": compare, "duplicates": duplicates})

# --- Roots and scans on disk ---

def roots() -> dict:
    """name -> folder, from data/fms/roots.txt."""
    p = DATA / "roots.txt"
    rows = [[x.strip() for x in l.split("|", 1)] for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")] if p.exists() else []
    return {r[0]: Path(r[1]).expanduser() for r in rows if len(r) == 2 and r[0] and r[1]}

def _sdir(root: str) -> Path: return DATA / "scans" / re.sub(r"[^A-Za-z0-9_-]", "_", root)
def _meta_path(root: str, sid: str) -> Path: return _sdir(root) / f"{sid}.json"
def _write_meta(s: dict): _meta_path(s["root"], s["sid"]).write_text(json.dumps(s), encoding="utf-8")

def scans(root: str) -> list:
    """The root's scans, newest first (summaries: state done, running or stopped)."""
    d = _sdir(root)
    return sorted((json.loads(f.read_text(encoding="utf-8")) for f in d.glob("*.json")), key=lambda s: s["started"], reverse=True) if d.exists() else []

def scan_meta(root: str, sid: str) -> dict: return json.loads(_meta_path(root, sid).read_text(encoding="utf-8")) if root != "@imported" else {"root": "@imported", "sid": sid, "state": "done", "full": True, "started": "", "path": "imported"}

def manifest(root: str, sid: str) -> dict:
    """path -> [size, mtime_ns, sha256 or ""] of one finished scan; root "@imported" reads an imported manifest."""
    p = DATA / "imported" / f"{sid}.jsonl.gz" if root == "@imported" else _sdir(root) / f"{sid}.jsonl.gz"
    with gzip.open(p, "rt", encoding="utf-8") as f: return {r[0]: r[1:] for r in map(json.loads, f)}

# --- Scanning (a worker thread per scan; the event loop only starts it and reads its counters) ---

def _hash(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def _scan(s: dict, job: dict):
    """Walks the root and writes its manifest. Hashes come from the root's last finished scan where size and time match; files already done by this scan (its .part, when continued) are not read again.
    Symbolic links are not followed or listed. Stopping (or a restart) leaves the .part for Continue."""
    folder, d = Path(s["path"]), _sdir(s["root"])
    part_p = d / f"""{s["sid"]}.part"""
    last = next((x for x in scans(s["root"]) if x["state"] == "done" and x["sid"] != s["sid"]), None)
    known = manifest(s["root"], last["sid"]) if last else {}
    done = {r[0]: r[1:] for r in map(json.loads, part_p.read_text(encoding="utf-8").splitlines())} if part_p.exists() else {}
    job.update(files=len(done), bytes=sum(v[0] for v in done.values()))
    with part_p.open("a", encoding="utf-8") as part:
        for dirpath, dirs, files in os.walk(folder, onerror=lambda e: job["errors"].append(f"{e.filename}: {e.strerror}")):
            dirs.sort()
            for name in sorted(files):
                if job["stop"]: break
                p = Path(dirpath) / name
                rel = p.relative_to(folder).as_posix()
                try: st = p.lstat()
                except OSError as e:
                    job["errors"].append(f"{rel}: {e}")
                    continue
                if not stat.S_ISREG(st.st_mode) or (rel in done and done[rel][:2] == [st.st_size, st.st_mtime_ns]): continue
                k = known.get(rel)
                h = k[2] if k and k[:2] == [st.st_size, st.st_mtime_ns] else ""
                job["reused"] += bool(h)
                if s["full"] and not h:
                    try: h = _hash(p)
                    except OSError as e:
                        job["errors"].append(f"{rel}: {e}")
                        continue
                    job["hashed"] += 1
                part.write(json.dumps([rel, st.st_size, st.st_mtime_ns, h]) + "\n")
                job["files"] += 1
                job["bytes"] += st.st_size
            if job["stop"]: break
    if job["stop"]: return
    rows = {r[0]: r for r in map(json.loads, part_p.read_text(encoding="utf-8").splitlines())}   # a file written twice (changed while a scan was continued) keeps its last line
    with gzip.open(d / f"""{s["sid"]}.jsonl.gz""", "wt", encoding="utf-8") as out:
        for rel in sorted(rows): out.write(json.dumps(rows[rel]) + "\n")
    part_p.unlink()

async def _run(s: dict, job: dict):
    try:
        await asyncio.to_thread(_scan, s, job)
        s.update(state="stopped" if job["stop"] else "done", finished=datetime.now().isoformat(timespec="seconds"))
    except Exception as e: s.update(state="stopped", error=f"{type(e).__name__}: {e}"[:300])
    s.update(files=job["files"], bytes=job["bytes"], hashed=job["hashed"], reused=job["reused"], errors=job["errors"][:20], error_count=len(job["errors"]))
    _write_meta(s)
    _JOBS.pop(s["root"], None)

def start_scan(root: str, full: bool, sid: str = "") -> dict:
    """Starts a scan of root (or continues the stopped scan sid) in the background; returns its summary."""
    if root in _JOBS: raise RuntimeError(f"{root} is being scanned already")
    folder = roots()[root]
    if not folder.is_dir(): raise RuntimeError(f"{folder} is not a folder on this server")
    s = {**scan_meta(root, sid), "state": "running"} if sid else {"root": root, "sid": datetime.now().strftime("%Y%m%d-%H%M%S"), "path": str(folder), "full": full, "started": datetime.now().isoformat(timespec="seconds"), "state": "running"}
    _sdir(root).mkdir(parents=True, exist_ok=True)
    _write_meta(s)
    _JOBS[root] = {"files": 0, "bytes": 0, "hashed": 0, "reused": 0, "errors": [], "stop": False, "sid": s["sid"]}   # registered before the task starts, so a second press cannot start a second scan
    t = asyncio.create_task(_run(s, _JOBS[root]))
    _TASKS.add(t)
    t.add_done_callback(_TASKS.discard)
    return s

# --- Comparing ---

def exact(*ms) -> bool: return all(m and all(v[2] for v in m.values()) for m in ms)   # every file hashed: content matches are exact

def _keyer(*ms) -> callable:
    """Content key: the SHA-256 when every file of every manifest given has one, else name + size (a weaker match, said so on screen)."""
    return (lambda m, p: m[p][2]) if exact(*ms) else (lambda m, p: f"{m[p][0]}|{posixpath.basename(p)}")

def compare(a: dict, b: dict, by: str = "path") -> dict:
    """What differs from manifest a to manifest b.
    by "path": added (only in b), removed (only in a), changed (same path, other size or content), moved (a removed file whose content - or name and size - reappears at an added path).
    by "content": only_a / only_b - content on one side only, wherever it sits (copies count as present)."""
    key = _keyer(a, b)
    if by == "content":
        ka, kb = {key(a, p) for p in a}, {key(b, p) for p in b}
        return {"by": "content", "only_a": sorted(p for p in a if key(a, p) not in kb), "only_b": sorted(p for p in b if key(b, p) not in ka)}
    removed, added = sorted(set(a) - set(b)), sorted(set(b) - set(a))
    changed = sorted(p for p in set(a) & set(b) if a[p][0] != b[p][0] or (a[p][2] and b[p][2] and a[p][2] != b[p][2]))
    arrivals = {}
    for p in added: arrivals.setdefault(key(b, p), []).append(p)
    moved = [(p, arrivals[key(a, p)].pop(0)) for p in removed if arrivals.get(key(a, p))]
    gone, came = {x for x, _ in moved}, {y for _, y in moved}
    return {"by": "path", "added": [p for p in added if p not in came], "removed": [p for p in removed if p not in gone], "changed": changed, "moved": moved, "same": len(set(a) & set(b)) - len(changed)}

def duplicates(m: dict) -> list:
    """Groups of paths with the same content (or name and size where there are no hashes), most wasted space first."""
    key, g = _keyer(m), {}
    for p in m:
        if m[p][0]: g.setdefault(key(m, p), []).append(p)
    return sorted((v for v in g.values() if len(v) > 1), key=lambda v: -m[v[0]][0] * (len(v) - 1))

# --- HTML ---

def _esc(s) -> str: return html.escape(str(s if s is not None else ""))
def _post(action: str, **extra) -> str: return f"""hx-post="/im/in" hx-target="body" hx-swap="none" hx-vals="{_esc(json.dumps({"type": f"fms_{action}", "lvl": 1, **extra}))}\""""
def _size(n: int) -> str: return next(f"{n / 1024 ** i:.1f} {u}" for i, u in ((4, "TB"), (3, "GB"), (2, "MB"), (1, "KB"), (0, "B")) if n >= 1024 ** i or u == "B")
def _when(t: str) -> str: return (t or "")[:16].replace("T", " ")

def _ref_options(cur: str = "") -> str:
    """Every finished scan of every root and every imported manifest, as <option>s (value root|sid)."""
    opts = [(f"""{r}|{s["sid"]}""", f"""{r} - {_when(s["started"])} ({"full" if s["full"] else "quick"}, {s.get("files", "?")} files)""") for r in roots() for s in scans(r) if s["state"] == "done"]
    opts += [(f"@imported|{f.name[:-9]}", f"imported: {f.name[:-9]}") for f in sorted((DATA / "imported").glob("*.jsonl.gz"))]
    return "".join(f"""<option value="{_esc(v)}"{" selected" if v == cur else ""}>{_esc(t)}</option>""" for v, t in opts)

def _progress_html(root: str) -> str:
    j = _JOBS.get(root)
    if not j: return ""
    return f"""<div class="info-bar row">&#x25CC; scanning: {j["files"]} files, {_size(j["bytes"])}{f', {j["hashed"]} hashed, {j["reused"]} hashes reused' if j["hashed"] or j["reused"] else ""}{f', {len(j["errors"])} unreadable' if j["errors"] else ""}
               <span class="grow"></span><button class="ui-btn" {_post("stop", root=root)}>Stop</button></div><div {_post("poll", root=root)} hx-trigger="load delay:2s"></div>"""

def _root_html(root: str) -> str:
    folder, ss = roots()[root], scans(root)
    stopped = next((s for s in ss if s["state"] == "stopped"), None)
    cont = f"""<button class="ui-btn" {_post("scan", root=root, sid=stopped["sid"])} title="Continue the scan started {_when(stopped["started"])}">Continue</button>""" if stopped and root not in _JOBS else ""
    start = "" if root in _JOBS else f"""<button class="ui-btn" {_post("scan", root=root, full=0)} title="Sizes and times only - quick">Quick scan</button><button class="ui-btn" {_post("scan", root=root, full=1)} title="Also SHA-256 of every new or changed file - needed to compare by content and find exact duplicates">Full scan</button>"""
    rows = "".join(f"""<tr><td>{_when(s["started"])}</td><td>{"full" if s["full"] else "quick"}</td><td>{s.get("files", "")}</td><td>{_size(s.get("bytes", 0))}</td><td>{_esc(s["state"])}{f' ({s["error_count"]} unreadable)' if s.get("error_count") else ""}</td>
                   <td>{f'<button class="cm-qbtn" {_post("view", view="scan", root=root, sid=s["sid"])}>Open</button>' if s["state"] == "done" else ""}</td></tr>""" for s in ss)
    return f"""<div class="row"><span class="form-title">{_esc(root)}</span><span class="status-label mono grow">{_esc(folder)}</span>{start}{cont}</div><div id="fms-progress">{_progress_html(root)}</div>
               <table class="data-table"><thead><tr><th>Started</th><th>Kind</th><th>Files</th><th>Size</th><th>State</th><th></th></tr></thead><tbody>{rows or '<tr><td colspan="6" class="list-empty">No scans yet.</td></tr>'}</tbody></table>"""

def _scan_html(root: str, sid: str) -> str:
    s, ss = scan_meta(root, sid), [x for x in scans(root) if x["state"] == "done"] if root != "@imported" else []
    prev = next((x for x in ss if x["started"] < s["started"]), None)
    since = f"""<button class="ui-btn" {_post("view", view="compare", a=f"{root}|{prev['sid']}", b=f"{root}|{sid}", by="path")}>Changes since {_when(prev["started"])}</button>""" if prev else ""
    errs = "".join(f"""<div class="status-label mono">{_esc(e)}</div>""" for e in s.get("errors", []))
    return f"""<div class="row"><button class="ui-btn" {_post("view", view="root", root=root) if root != "@imported" else _post("view", view="imported")}>&#x2190; Back</button><span class="form-title grow">{_esc(root)} - {_when(s["started"]) or sid}</span></div>
               <div class="info-bar row">{s.get("files", "?")} files &#xB7; {_size(s.get("bytes", 0))} &#xB7; {"full (SHA-256)" if s["full"] else "quick (no hashes)"}{f' &#xB7; {s.get("hashed", 0)} hashed, {s.get("reused", 0)} hashes reused' if s["full"] else ""} &#xB7; {_esc(s.get("path", ""))}</div>
               <div class="row">{since}<button class="ui-btn" {_post("view", view="dups", root=root, sid=sid)}>Duplicates</button><a class="ui-btn" href="/module/fms/export/{_esc(root)}/{_esc(sid)}" download>&#x2B07; Export manifest</a>
               {f'<button class="ui-btn" style="color:#ff5f5f" {_post("forget", root=root, sid=sid)} hx-confirm="Delete this scan record? Only FMS data - the files in the root are not touched.">Delete scan record</button>' if root != "@imported" else ""}</div>
               <form class="row" {_post("view", view="compare", b=f"{root}|{sid}")} hx-include="this"><span class="status-label">Compare with</span><select name="a" class="module-select grow">{_ref_options()}</select>
               <select name="by" class="module-select"><option value="path">by path (same layout)</option><option value="content">by content (anywhere)</option></select><button type="submit" class="ui-btn">Compare</button></form>
               {f'<details class="sec"><summary>Unreadable ({s["error_count"]}, first 20)</summary>{errs}</details>' if errs else ""}"""

def _rows(paths: list, m: dict, fmt=None) -> str:
    out = "".join(f"""<div class="list-row row"><span class="mono grow">{_esc(fmt(p) if fmt else p)}</span><span class="status-label">{_size(m[p if isinstance(p, str) else p[0]][0])}</span></div>""" for p in paths[:SHOW])
    return out + (f"""<div class="status-label">... and {len(paths) - SHOW} more (download the CSV for all)</div>""" if len(paths) > SHOW else "") or """<div class="list-empty">None.</div>"""

def _parse_ref(ref: str) -> tuple: return tuple(ref.split("|", 1))

def _compare_html(a_ref: str, b_ref: str, by: str) -> str:
    (ra, sa), (rb, sb) = _parse_ref(a_ref), _parse_ref(b_ref)
    a, b = manifest(ra, sa), manifest(rb, sb)
    c, label = compare(a, b, by), lambda r, s: f"""{r} {_when(scan_meta(r, s).get("started")) or s}"""
    weak = "" if exact(a, b) else """<div class="status-label">Content is matched by file name and size here (not every file has a hash - a full scan of both sides makes it exact).</div>"""
    csv_link = f"""<a class="ui-btn" href="/module/fms/compare.csv?a={_esc(a_ref)}&amp;b={_esc(b_ref)}&amp;by={by}" download>&#x2B07; CSV</a>"""
    head = f"""<div class="row"><button class="ui-btn" {_post("view", view="scan", root=rb, sid=sb)}>&#x2190; Back</button><span class="form-title grow">{_esc(label(ra, sa))} &#x2192; {_esc(label(rb, sb))} ({by})</span>{csv_link}</div>{weak}"""
    if by == "content":
        return f"""{head}<div class="info-bar">{len(c["only_a"])} only in {_esc(label(ra, sa))} &#xB7; {len(c["only_b"])} only in {_esc(label(rb, sb))}</div>
                   <details class="sec" open><summary>Only in {_esc(label(ra, sa))} ({len(c["only_a"])})</summary>{_rows(c["only_a"], a)}</details><details class="sec"><summary>Only in {_esc(label(rb, sb))} ({len(c["only_b"])})</summary>{_rows(c["only_b"], b)}</details>"""
    return f"""{head}<div class="info-bar">{c["same"]} unchanged &#xB7; {len(c["added"])} added &#xB7; {len(c["removed"])} removed &#xB7; {len(c["changed"])} changed &#xB7; {len(c["moved"])} moved</div>
               <details class="sec" open><summary>Added ({len(c["added"])})</summary>{_rows(c["added"], b)}</details><details class="sec" open><summary>Removed ({len(c["removed"])})</summary>{_rows(c["removed"], a)}</details>
               <details class="sec"><summary>Changed ({len(c["changed"])})</summary>{_rows(c["changed"], b)}</details><details class="sec"><summary>Moved ({len(c["moved"])})</summary>{_rows(c["moved"], a, lambda m: f"{m[0]}  ->  {m[1]}")}</details>"""

def _dups_html(root: str, sid: str) -> str:
    m = manifest(root, sid)
    groups = duplicates(m)
    wasted = sum(m[g[0]][0] * (len(g) - 1) for g in groups)
    rows = "".join(f"""<div class="list-row"><div class="status-label">{len(g)} copies &#xB7; {_size(m[g[0]][0])} each</div>{"".join(f'<div class="mono">{_esc(p)}</div>' for p in g[:12])}</div>""" for g in groups[:150])
    return f"""<div class="row"><button class="ui-btn" {_post("view", view="scan", root=root, sid=sid)}>&#x2190; Back</button><span class="form-title grow">Duplicates - {_esc(root)}</span></div>
               <div class="info-bar">{len(groups)} group(s) &#xB7; {_size(wasted)} in extra copies &#xB7; {"same content (SHA-256)" if exact(m) else "same name and size (a full scan makes it exact)"}</div>{rows or '<div class="list-empty">No duplicates.</div>'}
               <div class="status-label">FMS only reports; deciding which copy goes is yours (or a later staged-delete step).</div>"""

def _imported_html() -> str:
    rows = "".join(f"""<div class="list-row row"><span class="grow mono">{_esc(f.name[:-9])}</span><span class="status-label">{_size(f.stat().st_size)} gz</span><button class="cm-qbtn" {_post("view", view="scan", root="@imported", sid=f.name[:-9])}>Open</button></div>""" for f in sorted((DATA / "imported").glob("*.jsonl.gz")))
    return f"""<div class="row"><span class="form-title">Imported manifests</span></div><div class="status-label">A manifest exported from another portal instance (or another FMS) - compare it with a scan here to see what one side has that the other lacks.</div>
               <form hx-post="/module/fms/import" hx-encoding="multipart/form-data" hx-target="#fms-import-msg" class="row"><input name="name" class="module-select" placeholder="name, e.g. home-manga" required pattern="[A-Za-z0-9_-]+"><input type="file" name="file" accept=".gz" required><button class="ui-btn">Import</button><span id="fms-import-msg" class="status-label"></span></form>
               {rows or '<div class="list-empty">None yet.</div>'}"""

def _settings_html(msg: str = "") -> str:
    p = DATA / "roots.txt"
    return f"""<div class="row"><span class="form-title">Roots</span><span class="status-label">{msg}</span></div>
               <form class="node-form" {_post("roots_save")}><label class="status-label">One per line: name | folder on this server. FMS only reads these folders.</label><textarea name="roots" class="cm-input mono" rows="6" placeholder="manga | /data/manga">{_esc(p.read_text(encoding="utf-8") if p.exists() else "")}</textarea>
               <div class="row"><span class="grow"></span><button type="submit" class="ui-btn">Save</button></div></form>"""

def _root_state(r: str) -> str:
    s = next((s for s in scans(r) if s["state"] == "done"), None)
    return "scanning" if r in _JOBS else f"""{_when(s["started"])} &#xB7; {s.get("files", "?")} files""" if s else "not scanned"

def _side_html(v: dict) -> str:
    rs = "".join(f"""<div class="side-list-item{" active" if v.get("root") == r else ""}" {_post("view", view="root", root=r)}><span class="side-list-item-title">{_esc(r)}</span><span class="status-label">{_root_state(r)}</span></div>""" for r in roots())
    return f"""<div class="list-panel-hd"><span class="list-panel-title">Roots</span></div>{rs or '<div class="list-empty">No roots yet.</div>'}
               <div class="row" style="margin-top:.4rem"><button class="ui-btn" {_post("view", view="imported")}>Imported manifests</button><button class="ui-btn" {_post("view", view="settings")}>Roots...</button></div>"""

def _main_html(request, v: dict) -> str:
    admin, view = request.state.user.role == "admin", v.get("view")
    if view == "settings" and admin: return _settings_html()
    if view == "imported": return _imported_html()
    if view == "root" and v.get("root") in roots(): return _root_html(v["root"])
    if view == "scan": return _scan_html(v["root"], v["sid"])
    if view == "compare": return _compare_html(v["a"], v["b"], v.get("by", "path"))
    if view == "dups": return _dups_html(v["root"], v["sid"])
    return """<div class="list-empty">Pick a root on the left (an admin adds roots under Roots...), or open the imported manifests.</div>"""

async def _view(request) -> dict: return await ENV["get_state"](request, scope="user", namespace="fms", key="view") or {}

async def _show(request, imr, v: dict, main: str = None):
    await ENV["set_state"](request, v, scope="user", namespace="fms", key="view")
    imr.oob(main if main is not None else _main_html(request, v), "fms-main")
    return imr.oob(_side_html(v), "fms-side")

# --- Intent handlers (FMS is an admin tool: roots are folders on the server) ---

def _admin(request):
    if request.state.user.role != "admin": raise HTTPException(403, "FMS is for admins")

async def _h_view(request, payload, imr):
    _admin(request)
    return await _show(request, imr, {k: payload[k] for k in ("view", "root", "sid", "a", "b", "by") if payload.get(k)})

async def _h_scan(request, payload, imr):
    _admin(request)
    try: start_scan(payload["root"], str(payload.get("full")) == "1", payload.get("sid", ""))
    except RuntimeError as e: return imr.oob(f"""<div class="err-box">{_esc(e)}</div>""", "fms-progress")
    return await _show(request, imr, {"view": "root", "root": payload["root"]})

async def _h_stop(request, payload, imr):
    _admin(request)
    if payload.get("root") in _JOBS: _JOBS[payload["root"]]["stop"] = True
    return imr.oob(f"""<div class="status-label">Stopping after the current file...</div><div {_post("poll", root=payload.get("root", ""))} hx-trigger="load delay:2s"></div>""", "fms-progress")

async def _h_poll(request, payload, imr):
    """Progress of a running scan; when it has ended, the root view again."""
    _admin(request)
    if payload.get("root") in _JOBS: return imr.oob(_progress_html(payload["root"]), "fms-progress")
    return await _show(request, imr, {"view": "root", "root": payload.get("root", "")})

async def _h_roots_save(request, payload, imr):
    _admin(request)
    (DATA / "roots.txt").write_text(payload.get("roots", ""), encoding="utf-8")
    return await _show(request, imr, {"view": "settings"}, _settings_html(f"saved - {len(roots())} root(s)"))

async def _h_forget(request, payload, imr):
    """Deletes one scan record (FMS's own data; the root is not touched)."""
    _admin(request)
    for ext in (".json", ".jsonl.gz", ".part"): (_sdir(payload["root"]) / f"""{Path(payload["sid"]).name}{ext}""").unlink(missing_ok=True)
    return await _show(request, imr, {"view": "root", "root": payload["root"]})

# --- Routes ---

@router.get("/")
async def root(request: Request):
    _admin(request)
    v = await _view(request)
    side = UI.toolbar(side="left", content=f"""<div id="fms-side" class="scroll-pane">{_side_html(v)}</div>""", size="15rem", overlay=False, start_open=True, resizable=True, id="fms-left", nesting_level=1)
    return ENV["templates"].TemplateResponse(name="base.html", request=request, context={"request": request, "user": request.state.user, "nesting_level": 1, "shell_id": IM.branch_id, "toolbars": {"left": side}, "content": f"""<div id="fms-main" class="scroll-pane">{_main_html(request, v)}</div>""", "extra_css": ""})

@router.get("/export/{root}/{sid}")
async def export(request: Request, root: str, sid: str):
    _admin(request)
    p = DATA / "imported" / f"{Path(sid).name}.jsonl.gz" if root == "@imported" else _sdir(root) / f"{Path(sid).name}.jsonl.gz"
    if not p.exists(): raise HTTPException(404)
    return FileResponse(p, filename=f"""fms-{re.sub(r"[^A-Za-z0-9_-]", "_", root)}-{Path(sid).name}.jsonl.gz""", media_type="application/gzip")

@router.get("/compare.csv")
async def compare_csv(request: Request, a: str, b: str, by: str = "path"):
    _admin(request)
    (ra, sa), (rb, sb) = _parse_ref(a), _parse_ref(b)
    ma, mb = manifest(ra, sa), manifest(rb, sb)
    c, out = compare(ma, mb, by), io.StringIO()
    w = csv.writer(out)
    w.writerow(["change", "path", "to", "size"])
    for k in ("added", "removed", "changed", "only_a", "only_b"):
        for p in c.get(k, []): w.writerow([k, p, "", (mb if k in ("added", "changed", "only_b") else ma)[p][0]])
    for x, y in c.get("moved", []): w.writerow(["moved", x, y, ma[x][0]])
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"""attachment; filename="fms-compare-{by}.csv\""""})

@router.post("/import")
async def import_manifest(request: Request):
    """A manifest exported from FMS elsewhere (.jsonl.gz); checked line by line before it is kept. A name already used gets -2, -3."""
    _admin(request)
    form = await request.form()
    name, data = re.sub(r"[^A-Za-z0-9_-]", "_", form.get("name", "")) or "imported", await form["file"].read()
    try: rows = [json.loads(l) for l in gzip.decompress(data).decode("utf-8").splitlines() if l.strip()]
    except (OSError, ValueError) as e: return HTMLResponse(f"""<span style="color:#ff5f5f">Not an FMS manifest ({_esc(e)})</span>""")
    if not all(isinstance(r, list) and len(r) == 4 and isinstance(r[0], str) and isinstance(r[1], int) for r in rows): return HTMLResponse("""<span style="color:#ff5f5f">Not an FMS manifest (each line must be [path, size, mtime, sha256])</span>""")
    dest, n = DATA / "imported" / f"{name}.jsonl.gz", 2
    while dest.exists(): dest, n = DATA / "imported" / f"{name}-{n}.jsonl.gz", n + 1
    dest.write_bytes(data)
    return HTMLResponse(f"""&#x2713; {len(rows)} files as {_esc(dest.name[:-9])}<div id="fms-main" hx-swap-oob="innerHTML">{_imported_html()}</div>""")
