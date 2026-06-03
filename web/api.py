"""REST API blueprint for project management."""

import os
import subprocess
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__)

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
import db

VAR_DIR = Path(__file__).parent.parent / "var" / "projects"


@api_bp.route("/projects", methods=["GET"])
def handle_list_projects():
    return jsonify(db.list_projects())


@api_bp.route("/projects", methods=["POST"])
def handle_create_project():
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"error": "name is required"}), 400

    name = data["name"]
    target_dir = data.get("target_dir", "")
    proj_path = db.get_project_path(name)

    if proj_path.exists():
        return jsonify({"error": "project already exists"}), 409

    # Check target_dir is not already used by another project
    for p in db.list_projects():
        if p.get("target_dir") == target_dir:
            return jsonify({"error": f"target directory already used by project '{p['name']}'"}), 409

    proj_path.mkdir(parents=True, exist_ok=True)
    db_path = proj_path / "results.db"
    db.init_db(str(db_path))

    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO projects (name, target_dir, status) VALUES (?, ?, ?)",
        (name, target_dir, "pending"),
    )
    conn.commit()
    conn.close()

    return jsonify({"name": name, "status": "pending"}), 201


@api_bp.route("/projects/<name>", methods=["GET"])
def handle_get_project(name):
    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    # Verify running status against actual PID
    if proj.get("status") == "running":
        pid_file = db.get_project_path(name) / "run.pid"
        alive = False
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                alive = _is_pid_alive(pid)
            except (ValueError, OSError):
                pass
        if not alive:
            import sqlite3
            db_path = str(db.get_project_path(name) / "results.db")
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE projects SET status=? WHERE name=?", ("error", name))
            conn.commit()
            conn.close()
            proj["status"] = "error"

    db_path = str(db.get_project_path(name) / "results.db")
    proj["file_counts"] = {}
    for stage in ("surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"):
        proj["file_counts"][stage] = db.count_files(db_path, stage)
    return jsonify(proj)


@api_bp.route("/projects/<name>", methods=["DELETE"])
def handle_delete_project(name):
    import shutil
    import sqlite3

    proj_path = db.get_project_path(name)
    if not proj_path.exists():
        return jsonify({"error": "not found"}), 404

    # Read target_dir before deleting project DB
    db_path = proj_path / "results.db"
    target_dir = None
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT target_dir FROM projects WHERE name=?", (name,)
        ).fetchone()
        conn.close()
        if row:
            target_dir = row[0]

    # Delete _output under target directory
    if target_dir:
        output_path = Path(target_dir) / "_output"
        if output_path.exists():
            shutil.rmtree(output_path)

    # Delete project directory
    shutil.rmtree(proj_path)
    return jsonify({"status": "deleted"})


def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running (Unix)."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError, PermissionError):
        return False


def _check_running(proj: dict) -> tuple[dict | None, int | None]:
    """Return error response if project already has a running process, else (None, None).

    Returns (error_body, status_code) on conflict, or (None, None) if clear to run.
    """
    pid_file = db.get_project_path(proj["name"]) / "run.pid"
    if not pid_file.exists():
        return None, None
    try:
        pid = int(pid_file.read_text().strip())
        if _is_pid_alive(pid):
            return {"error": f"project already running (PID {pid})"}, 409
        pid_file.unlink(missing_ok=True)
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
    return None, None


@api_bp.route("/projects/<name>/run", methods=["POST"])
def handle_run_project(name):
    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    # Check if already running
    err_body, err_code = _check_running(proj)
    if err_body:
        return jsonify(err_body), err_code

    data = request.get_json() or {}

    db_path = str(db.get_project_path(name) / "results.db")
    import sqlite3
    conn = sqlite3.connect(db_path)

    # Save runtime params and update status
    conn.execute(
        "UPDATE projects SET collect_prompt=?, analyze_prompt=?, vuln_prompt=?, model=?, agent=?, force_surface=?, status=? WHERE name=?",
        (data.get("collect_prompt", ""), data.get("analyze_prompt", ""),
         data.get("vuln_prompt", ""), data.get("model", ""),
         data.get("agent", ""), data.get("force_surface", ""),
         "running", name),
    )
    conn.commit()
    conn.close()

    # Build command using request params
    cmd = [sys.executable, "run.py", proj["target_dir"], "--project", name]
    if data.get("collect_prompt"):
        cmd += ["--collect-prompt", data["collect_prompt"]]
    if data.get("analyze_prompt"):
        cmd += ["--analyze-prompt", data["analyze_prompt"]]
    if data.get("vuln_prompt"):
        cmd += ["--vuln-prompt", data["vuln_prompt"]]
    if data.get("model"):
        cmd += ["--model", data["model"]]
    if data.get("agent"):
        cmd += ["--agent", data["agent"]]
    if data.get("force_surface"):
        cmd += ["--force-surface", data["force_surface"]]

    # Launch asynchronously
    proc = subprocess.Popen(
        cmd,
        cwd=str(Path(__file__).parent.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Save PID to project directory
    db.get_project_path(proj["name"]).joinpath("run.pid").write_text(str(proc.pid))

    return jsonify({"status": "running", "pid": proc.pid}), 202


@api_bp.route("/projects/<name>/files/<stage>", methods=["GET"])
def handle_list_files(name, stage):
    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    db_path = str(db.get_project_path(name) / "results.db")
    if not Path(db_path).exists():
        return jsonify({"error": "project not found"}), 404

    return jsonify({"stage": stage, "files": db.list_files(db_path, stage)})


@api_bp.route("/projects/<name>/stages/<stage>", methods=["DELETE"])
def handle_clear_stage(name, stage):
    import shutil
    import sqlite3

    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    # Clear database records
    db_path = str(db.get_project_path(name) / "results.db")
    db.clear_stage(db_path, stage)

    # Delete _output/<stage> files
    output_dir = Path(proj["target_dir"]) / "_output" / stage
    if output_dir.exists():
        shutil.rmtree(output_dir)

    return jsonify({"status": "cleared", "stage": stage})


@api_bp.route("/projects/<name>/files/<stage>/<int:file_id>", methods=["DELETE"])
def handle_delete_file(name, stage, file_id):
    import shutil

    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    db_path = str(db.get_project_path(name) / "results.db")
    filename = db.delete_file(db_path, stage, file_id)
    if filename is None:
        return jsonify({"error": "file not found"}), 404

    # Delete file from _output/<stage>/
    file_path = Path(proj["target_dir"]) / "_output" / stage / filename
    if file_path.exists():
        file_path.unlink()

    return jsonify({"status": "deleted", "stage": stage, "filename": filename})


_VULN_PREFIXES = ("VULN-", "DISMISSED-", "CLEAN-", "SUSPECTED-")


def _extract_surface_stem(filename: str) -> str:
    """Extract the surface-level stem from any stage filename.

    Examples::
        iface-REST-ping.md          → iface-REST-ping
        iface-REST-ping-1.md        → iface-REST-ping
        VULN-iface-REST-ping-1-1.md → iface-REST-ping
    """
    stem = filename.replace(".md", "")
    # Strip verdict prefixes repeatedly
    while True:
        before = stem
        for p in _VULN_PREFIXES:
            if stem.startswith(p):
                stem = stem[len(p):]
        if stem == before:
            break
    # Strip trailing -\d+ sequences
    import re
    while re.search(r'-\d+$', stem):
        stem = re.sub(r'-\d+$', '', stem)
    return stem


@api_bp.route("/projects/<name>/files/<stage>/<int:file_id>", methods=["GET"])
def handle_get_file(name, stage, file_id):
    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    db_path = str(db.get_project_path(name) / "results.db")
    if not Path(db_path).exists():
        return jsonify({"error": "project not found"}), 404

    file_data = db.get_file(db_path, stage, file_id)
    if file_data is None:
        return jsonify({"error": "file not found"}), 404
    return jsonify(file_data)


def _strip_one_number(s: str) -> str:
    """Strip only the LAST trailing '-\d+' segment."""
    import re
    return re.sub(r'-\d+$', '', s)


def _stem_and_prefix(stage: str, filename: str) -> dict:
    """Compute precise related filenames for a source file.

    Returns a dict with:
      - exact: set of exact expected filenames per stage
      - prefix: set of prefixes for prefix-based matching per stage
    """
    import re
    s = filename.replace('.md', '')
    exact: dict[str, set[str]] = {st: set() for st in ("surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review")}
    prefix: dict[str, set[str]] = {st: set() for st in ("surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review")}

    # Always include itself
    exact[stage].add(filename)

    if stage == "vuln_review":
        # VULN-VULN-{S}-{T}-{V}.md → VULN-{S}-{T}-{V}.md (vuln)
        vuln_name = re.sub(r"^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-", "", filename, count=1)
        exact["vulnerabilities"].add(vuln_name)

        # vuln stem without prefix → {S}-{T}-{V}, strip trailing -\d+ → {S}-{T} (task)
        vuln_stem = re.sub(r"^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-", "", vuln_name.replace(".md", ""), count=1)
        task_stem = _strip_one_number(vuln_stem)
        task_name = task_stem + ".md"
        exact["vuln_tasks"].add(task_name)

        # task stem without trailing -\d+ → {S} (surface)
        surface_stem = _strip_one_number(task_stem)
        surface_name = surface_stem + ".md"
        exact["analysis"].add(surface_name)
        exact["surfaces"].add(surface_name)

    elif stage == "vulnerabilities":
        # VULN-{S}-{T}-{V}.md → VULN-VULN-{S}-{T}-{V}.md (review)
        review_name = "VULN-" + filename
        exact["vuln_review"].add(review_name)

        # strip VULN- → {S}-{T}-{V}, strip trailing -\d+ → {S}-{T} (task)
        vuln_stem = re.sub(r"^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-", "", s, count=1)
        task_stem = _strip_one_number(vuln_stem)
        task_name = task_stem + ".md"
        exact["vuln_tasks"].add(task_name)

        # task stem without trailing -\d+ → {S} (surface)
        surface_stem = _strip_one_number(task_stem)
        surface_name = surface_stem + ".md"
        exact["analysis"].add(surface_name)
        exact["surfaces"].add(surface_name)

    elif stage == "vuln_tasks":
        # {S}-{T}.md → {S}.md (analysis/surface)
        surface_stem = _strip_one_number(s)
        surface_name = surface_stem + ".md"
        exact["analysis"].add(surface_name)
        exact["surfaces"].add(surface_name)

        # Prefix: VULN-{S}-{T}- for vulns, VULN-VULN-{S}-{T}- for reviews
        prefix["vulnerabilities"].add("VULN-" + s)
        prefix["vuln_review"].add("VULN-VULN-" + s)

    elif stage in ("analysis", "surfaces"):
        # Exact: the same file is in both stages
        exact["analysis"].add(filename)
        exact["surfaces"].add(filename)

        # Prefix: {S}- for tasks, VULN-{S}- for vulns, VULN-VULN-{S}- for reviews
        prefix["vuln_tasks"].add(s + "-")
        prefix["vulnerabilities"].add("VULN-" + s)
        prefix["vuln_review"].add("VULN-VULN-" + s)

    return {"exact": exact, "prefix": prefix}


@api_bp.route("/projects/<name>/files/<stage>/<int:file_id>/trace", methods=["GET"])
def handle_trace_file(name, stage, file_id):
    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    db_path = str(db.get_project_path(name) / "results.db")
    if not Path(db_path).exists():
        return jsonify({"error": "project not found"}), 404

    file_data = db.get_file(db_path, stage, file_id)
    if file_data is None:
        return jsonify({"error": "file not found"}), 404

    chain = _stem_and_prefix(stage, file_data["filename"])
    exact = chain["exact"]
    prefix = chain["prefix"]

    stem = _extract_surface_stem(file_data["filename"])
    trace = {"source": {"id": file_id, "stage": stage, "filename": file_data["filename"]}, "stem": stem, "related": {}}
    for s in VALID_STAGES:
        files = db.list_files(db_path, s)
        matching = []
        for f in files:
            fn = f["filename"]
            # Exact match takes priority
            if fn in exact[s]:
                matching.append(f)
            elif prefix[s]:
                for p in prefix[s]:
                    if fn.startswith(p):
                        matching.append(f)
                        break
        if matching:
            trace["related"][s] = matching
    return jsonify(trace)
