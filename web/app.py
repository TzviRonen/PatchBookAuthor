"""CVE Pipeline Web UI — Flask server on port 3011."""
import json
import os
import queue
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import markdown
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
TRACES_DIR = DATA_DIR / "traces"
BLOGS_DIR = DATA_DIR / "blogs"
DIFFS_DIR = DATA_DIR / "diffs"
BINARIES_DIR = DATA_DIR / "binaries"
LOG_FILE = DATA_DIR / "diffs" / "ghidriff.log"
RUN_TRACE = DATA_DIR / "run_trace.json"

app = Flask(__name__, template_folder="templates")

# ── running tasks ──────────────────────────────────────────────────────────────

tasks: dict[str, dict] = {}  # task_id → {status, output_lines, proc, cve_id, started_at}


def _stream_proc(task_id: str, proc: subprocess.Popen) -> None:
    t = tasks[task_id]
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        t["output_lines"].append(line)
        t["queue"].put(line)
    proc.wait()
    t["returncode"] = proc.returncode
    t["status"] = "done" if proc.returncode == 0 else "failed"
    t["ended_at"] = datetime.utcnow().isoformat()
    t["queue"].put(None)  # sentinel


# ── helpers ────────────────────────────────────────────────────────────────────

STAGES = ["msrc", "binaries", "ghidriff", "identify", "blog"]

STAGE_LABELS = {
    "msrc": "MSRC Lookup",
    "binaries": "Binaries",
    "ghidriff": "Ghidriff",
    "identify": "Patch ID",
    "blog": "Blog Post",
}


def _load_trace(cve_id: str) -> dict:
    p = TRACES_DIR / f"{cve_id}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _all_cves() -> list[dict]:
    cves = []
    if TRACES_DIR.exists():
        for f in sorted(TRACES_DIR.glob("CVE-*.json")):
            cve_id = f.stem
            trace = _load_trace(cve_id)
            stages = trace.get("stages", {})
            completed = [s for s in STAGES if stages.get(s, {}).get("status") == "done"]
            last_stage = completed[-1] if completed else None
            cve_meta = stages.get("msrc", {}).get("result", {}).get("cve", {})
            cves.append({
                "id": cve_id,
                "title": cve_meta.get("title", ""),
                "cvss": cve_meta.get("cvss"),
                "completed_stages": completed,
                "stage_count": len(completed),
                "last_stage": last_stage,
                "has_blog": (BLOGS_DIR / f"{cve_id}_*.md").exists() or any(BLOGS_DIR.glob(f"{cve_id}*.md")),
                "has_diff": any(DIFFS_DIR.glob(f"*{cve_id}*.md")) or _find_diff_for_cve(cve_id) is not None,
            })
    return cves


def _find_blog(cve_id: str) -> Path | None:
    for p in BLOGS_DIR.glob(f"{cve_id}*.md"):
        return p
    return None


def _find_diff_for_cve(cve_id: str) -> Path | None:
    trace = _load_trace(cve_id)
    dp = trace.get("stages", {}).get("ghidriff", {}).get("result", {}).get("diff_path")
    if dp:
        p = BASE_DIR / dp
        if p.exists():
            return p
    for p in DIFFS_DIR.glob("*.ghidriff.md"):
        return p
    return None


def _md_to_html(text: str) -> str:
    return markdown.markdown(
        text,
        extensions=["fenced_code", "tables", "toc", "nl2br"],
        extension_configs={"toc": {"permalink": True}},
    )


def _file_size(p: Path) -> str:
    b = p.stat().st_size
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


# ── routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    cves = _all_cves()
    running = [t for t in tasks.values() if t["status"] == "running"]
    return render_template("dashboard.html", cves=cves, stages=STAGES,
                           stage_labels=STAGE_LABELS, running_count=len(running))


@app.route("/cve/<cve_id>")
def cve_detail(cve_id: str):
    trace = _load_trace(cve_id)
    stages = trace.get("stages", {})
    blog_path = _find_blog(cve_id)
    diff_path = _find_diff_for_cve(cve_id)
    return render_template("cve_detail.html", cve_id=cve_id, stages=stages,
                           stage_list=STAGES, stage_labels=STAGE_LABELS,
                           blog_path=blog_path, diff_path=diff_path)


@app.route("/cve/<cve_id>/blog")
def cve_blog(cve_id: str):
    p = _find_blog(cve_id)
    if not p:
        return render_template("error.html", msg=f"No blog post found for {cve_id}"), 404
    raw = p.read_text()
    html = _md_to_html(raw)
    back = request.args.get("from", "cve")
    back_url = "/blogs" if back == "blogs" else f"/cve/{cve_id}"
    back_label = "All Blogs" if back == "blogs" else cve_id
    return render_template("markdown_view.html", title=f"{cve_id} — Blog Post",
                           content_html=html, back_url=back_url,
                           back_label=back_label, raw=raw,
                           feedback_url=f"/cve/{cve_id}/blog/feedback")


@app.route("/cve/<cve_id>/blog/feedback", methods=["POST"])
def cve_blog_feedback(cve_id: str):
    p = _find_blog(cve_id)
    if not p:
        return jsonify({"error": "Blog not found"}), 404
    data = request.get_json(silent=True) or {}
    text = (data.get("feedback") or "").strip()
    if not text:
        return jsonify({"error": "Feedback text required"}), 400

    content = p.read_text(encoding="utf-8")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    entry = f"- **[{date_str}]**: {text}"

    if "## Feedback" in content:
        content = content.rstrip() + f"\n{entry}\n"
    else:
        content = content.rstrip() + f"\n\n## Feedback\n\n{entry}\n"

    p.write_text(content, encoding="utf-8")
    return jsonify({"ok": True})


@app.route("/cve/<cve_id>/diff")
def cve_diff(cve_id: str):
    p = _find_diff_for_cve(cve_id)
    if not p:
        return render_template("error.html", msg=f"No diff found for {cve_id}"), 404
    raw = p.read_text()
    html = _md_to_html(raw)
    return render_template("markdown_view.html", title=f"{cve_id} — Ghidriff",
                           content_html=html, back_url=f"/cve/{cve_id}", raw=raw)


@app.route("/diffs")
def diffs_list():
    items = []
    for p in sorted(DIFFS_DIR.glob("*.ghidriff.md")):
        items.append({"name": p.name, "size": _file_size(p), "path": str(p.relative_to(BASE_DIR))})
    return render_template("diffs.html", items=items)


@app.route("/diffs/<path:name>")
def diff_view(name: str):
    p = DIFFS_DIR / name
    if not p.exists() or not p.suffix == ".md":
        return render_template("error.html", msg="Diff not found"), 404
    raw = p.read_text()
    html = _md_to_html(raw)
    return render_template("markdown_view.html", title=name, content_html=html,
                           back_url="/diffs", raw=raw)


def _blog_meta(p: Path) -> dict:
    import re as _re
    text = p.read_text(encoding="utf-8", errors="replace")
    body = _re.sub(r"^.*?---\s*\n+", "", text, flags=_re.DOTALL, count=1)
    titles = _re.findall(r"^# (.+)", body, _re.MULTILINE)
    title = titles[0].strip() if titles else p.stem
    h2 = _re.search(r"^## (.+)", body, _re.MULTILINE)
    subtitle = h2.group(1).strip() if h2 else ""
    paras = _re.findall(r"^(?!#|\*\*Affected|\*\*CVE|!\[)[^\n]{60,}", body, _re.MULTILINE)
    excerpt = paras[0][:240].rstrip() + "…" if paras else ""
    return {"title": title, "subtitle": subtitle, "excerpt": excerpt}


@app.route("/blogs")
def blogs_list():
    items = []
    for p in sorted(BLOGS_DIR.glob("*.md"), reverse=True):
        cve_id = p.name.split("_")[0]
        meta = _blog_meta(p)
        trace = _load_trace(cve_id)
        cvss = trace.get("stages", {}).get("msrc", {}).get("result", {}).get("cve", {}).get("cvss")
        items.append({
            "name": p.name,
            "cve_id": cve_id,
            "size": _file_size(p),
            "title": meta["title"],
            "subtitle": meta["subtitle"],
            "excerpt": meta["excerpt"],
            "cvss": cvss,
        })
    return render_template("blogs.html", items=items)


@app.route("/binaries")
def binaries_list():
    groups = {}
    if BINARIES_DIR.exists():
        for cve_dir in sorted(BINARIES_DIR.iterdir()):
            if cve_dir.is_dir():
                files = []
                for f in sorted(cve_dir.iterdir()):
                    if f.is_file():
                        files.append({"name": f.name, "size": _file_size(f)})
                if files:
                    groups[cve_dir.name] = files
    return render_template("binaries.html", groups=groups)


@app.route("/logs")
def logs_view():
    log_text = ""
    if LOG_FILE.exists():
        log_text = LOG_FILE.read_text()[-100_000:]  # last 100KB
    run_trace_text = ""
    if RUN_TRACE.exists():
        run_trace_text = RUN_TRACE.read_text()
    ghidriff_run_log = ""
    p = DATA_DIR / "ghidriff_run.log"
    if p.exists():
        ghidriff_run_log = p.read_text()[-100_000:]
    return render_template("logs.html", log_text=log_text,
                           run_trace_text=run_trace_text,
                           ghidriff_run_log=ghidriff_run_log)


@app.route("/tasks")
def tasks_list():
    task_list = sorted(tasks.values(), key=lambda t: t["started_at"], reverse=True)
    return render_template("tasks.html", tasks=task_list)


@app.route("/tasks/new")
def new_task_form():
    return render_template("new_task.html")


@app.route("/tasks/run", methods=["POST"])
def run_task():
    cve_id = request.form.get("cve_id", "").strip().upper()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    update_id = request.form.get("update_id", "").strip() or None
    force = request.form.get("force") == "1"
    skip_blog = request.form.get("skip_blog") == "1"
    from_stage = request.form.get("from_stage", "").strip() or None

    cmd = [sys.executable, str(BASE_DIR / "run_cve.py"), cve_id]
    if update_id:
        cmd += ["--update-id", update_id]
    if force:
        cmd.append("--force")
    if skip_blog:
        cmd.append("--skip-blog")
    if from_stage:
        cmd += ["--from-stage", from_stage]

    task_id = str(uuid.uuid4())[:8]
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONFAULTHANDLER": "1"}
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=str(BASE_DIR),
        env=env,
    )
    tasks[task_id] = {
        "id": task_id,
        "cve_id": cve_id,
        "cmd": " ".join(cmd),
        "status": "running",
        "output_lines": [],
        "queue": queue.Queue(),
        "proc": proc,
        "started_at": datetime.utcnow().isoformat(),
        "ended_at": None,
        "returncode": None,
    }
    threading.Thread(target=_stream_proc, args=(task_id, proc), daemon=True).start()
    return jsonify({"task_id": task_id})


@app.route("/tasks/<task_id>/stream")
def task_stream(task_id: str):
    t = tasks.get(task_id)
    if not t:
        return Response("data: Task not found\n\n", content_type="text/event-stream")

    def generate():
        # Replay buffered lines first
        for line in list(t["output_lines"]):
            yield f"data: {line}\n\n"
        if t["status"] != "running":
            yield f"event: done\ndata: exit={t['returncode']}\n\n"
            return
        q = t["queue"]
        while True:
            try:
                item = q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if item is None:
                yield f"event: done\ndata: exit={t['returncode']}\n\n"
                break
            yield f"data: {item}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return Response(stream_with_context(generate()), headers=headers)


@app.route("/tasks/<task_id>")
def task_detail(task_id: str):
    t = tasks.get(task_id)
    if not t:
        return render_template("error.html", msg=f"Task {task_id!r} not found (tasks are in-memory and lost on server restart)."), 404
    return render_template("task_detail.html", task=t)


@app.route("/tasks/<task_id>/kill", methods=["POST"])
def kill_task(task_id: str):
    t = tasks.get(task_id)
    if not t:
        return jsonify({"error": "not found"}), 404
    if t["status"] == "running" and t["proc"]:
        t["proc"].terminate()
        t["status"] = "killed"
    return jsonify({"ok": True})


@app.route("/api/cves")
def api_cves():
    return jsonify(_all_cves())


@app.route("/api/cve/<cve_id>")
def api_cve(cve_id: str):
    trace = _load_trace(cve_id)
    if not trace:
        return jsonify({"error": "not found"}), 404
    return jsonify(trace)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3011, debug=False, threaded=True)
