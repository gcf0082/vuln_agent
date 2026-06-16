"""REST API blueprint for project management."""

import os
import sqlite3
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

    # Verify running status against actual process
    pid_file = db.get_project_path(name) / "run.pid"
    alive = False
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            alive = _is_pid_alive(pid)
        except (ValueError, OSError):
            pass

    if proj.get("status") == "running" and not alive:
        # Mark as error if process died unexpectedly
        db_path = str(db.get_project_path(name) / "results.db")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE projects SET status=? WHERE name=?", ("error", name))
        conn.commit()
        conn.close()
        proj["status"] = "error"
    elif proj.get("status") != "running":
        # pgrep fallback: process might be running without PID file or correct status
        pgrep_pid = _find_running_process(name)
        if pgrep_pid is not None:
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(str(pgrep_pid))
            db_path = str(db.get_project_path(name) / "results.db")
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE projects SET status=? WHERE name=?", ("running", name))
            conn.commit()
            conn.close()
            proj["status"] = "running"

    db_path = str(db.get_project_path(name) / "results.db")
    proj["file_counts"] = {}
    for stage in ("discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews"):
        proj["file_counts"][stage] = db.count_files(db_path, stage)
    return jsonify(proj)


@api_bp.route("/projects/<name>", methods=["DELETE"])
def handle_delete_project(name):
    import shutil

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

    # Stop running process if alive
    pid_file = proj_path / "run.pid"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            if _is_pid_alive(pid):
                os.kill(pid, 15)  # SIGTERM
        except (ValueError, OSError, ProcessLookupError):
            pass

    # Delete .vuln_agent_output under target directory
    if target_dir:
        output_path = Path(target_dir) / ".vuln_agent_output"
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


def _find_running_process(project_name: str) -> int | None:
    """Cross-platform scan for run.py processes targeting this project name.

    Linux: tries pgrep -f, then falls back to /proc/[pid]/cmdline.
    Windows: uses wmic CommandLine filter.
    macOS: same as Linux (pgrep).

    Returns PID if found, None otherwise.
    """
    import subprocess as _sp
    import platform
    own_pid = os.getpid()
    system = platform.system()

    # --- Linux / macOS: pgrep ---
    if system in ('Linux', 'Darwin'):
        try:
            result = _sp.run(
                ["pgrep", "-f", f"run.py.*--project.*{project_name}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for p in result.stdout.strip().splitlines():
                    p = p.strip()
                    if not p:
                        continue
                    try:
                        pid = int(p)
                    except ValueError:
                        continue
                    if pid != own_pid and _is_pid_alive(pid):
                        return pid
        except FileNotFoundError:
            pass  # pgrep not installed, fall through
        except Exception:
            pass

    # --- Linux fallback: /proc scan (works without pgrep) ---
    if system == 'Linux':
        import glob
        for pid_dir in sorted(glob.glob('/proc/[0-9]*')):
            try:
                pid = int(os.path.basename(pid_dir))
                if pid == own_pid:
                    continue
                cmdline_path = os.path.join(pid_dir, 'cmdline')
                with open(cmdline_path, 'rb') as f:
                    raw = f.read()
                cmdline = raw.decode('utf-8', errors='replace').replace('\0', ' ')
                if 'run.py' in cmdline and '--project' in cmdline and project_name in cmdline:
                    if _is_pid_alive(pid):
                        return pid
            except (OSError, ValueError):
                continue

    # --- Windows: wmic ---
    if system == 'Windows':
        try:
            result = _sp.run(
                ['wmic', 'process', 'where',
                 f'CommandLine like \'%run.py%\' and CommandLine like \'%{project_name}%\'',
                 'get', 'ProcessId', '/FORMAT:CSV'],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith('ProcessId') or line.startswith('Node'):
                        continue
                    try:
                        pid = int(line)
                    except ValueError:
                        continue
                    if pid != own_pid and _is_pid_alive(pid):
                        return pid
        except Exception:
            pass

    # --- Windows fallback: tasklist ---
    if system == 'Windows':
        try:
            result = _sp.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = line.strip().split('","')
                    if len(parts) < 2:
                        continue
                    try:
                        pid = int(parts[1].strip('"'))
                    except (ValueError, IndexError):
                        continue
                    if pid == own_pid:
                        continue
                    # Verify this is our python process via wmic CommandLine
                    wmi_result = _sp.run(
                        ['wmic', 'process', 'where',
                         f'ProcessId={pid}',
                         'get', 'CommandLine', '/FORMAT:CSV'],
                        capture_output=True, text=True, timeout=5,
                    )
                    if wmi_result.returncode == 0:
                        cmdline = wmi_result.stdout
                        if 'run.py' in cmdline and project_name in cmdline:
                            if _is_pid_alive(pid):
                                return pid
        except Exception:
            pass

    return None


def _check_running(proj: dict) -> tuple[dict | None, int | None]:
    """Return error response if project already has a running process, else (None, None).

    Checks two sources:
      1. PID file (normal case)
      2. _find_running_process scan (resilient against missing PID file)

    Returns (error_body, status_code) on conflict, or (None, None) if clear to run.
    """
    name = proj["name"]

    # 1. PID file check
    pid_file = db.get_project_path(name) / "run.pid"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            if _is_pid_alive(pid):
                return {"error": f"project already running (PID {pid})"}, 409
            pid_file.unlink(missing_ok=True)
        except (ValueError, OSError):
            pid_file.unlink(missing_ok=True)

    # 2. Cross-platform process scan fallback (in case PID file was lost but process still alive)
    found_pid = _find_running_process(name)
    if found_pid is not None:
        # Rescue the PID file so future checks find it too
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        pid_file.write_text(str(found_pid))
        return {"error": f"project already running (PID {found_pid})"}, 409

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
    conn = sqlite3.connect(db_path)

    # Save runtime params and update status
    conn.execute(
        "UPDATE projects SET recon_prompt=?, flow_prompt=?, vuln_prompt=?, verify_prompt=?, model=?, agent=?, force_surface=?, status=? WHERE name=?",
        (data.get("recon_prompt", ""), data.get("flow_prompt", ""),
         data.get("vuln_prompt", ""), data.get("verify_prompt", ""),
         data.get("model", ""), data.get("agent", ""),
         data.get("force_surface", ""), "running", name),
    )
    conn.commit()
    conn.close()

    # Build command using request params
    cmd = [sys.executable, "run.py", proj["target_dir"], "--project", name]
    if data.get("recon_prompt"):
        cmd += ["--recon-prompt", data["recon_prompt"]]
    if data.get("flow_prompt"):
        cmd += ["--flow-prompt", data["flow_prompt"]]
    if data.get("vuln_prompt"):
        cmd += ["--vuln-prompt", data["vuln_prompt"]]
    if data.get("verify_prompt"):
        cmd += ["--verify-prompt", data["verify_prompt"]]
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
    VALID_STAGES = {"discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    db_path = str(db.get_project_path(name) / "results.db")
    if not Path(db_path).exists():
        return jsonify({"error": "project not found"}), 404

    return jsonify({"stage": stage, "files": db.list_files(db_path, stage)})


@api_bp.route("/projects/<name>/stages/<stage>", methods=["DELETE"])
def handle_clear_stage(name, stage):
    import shutil

    VALID_STAGES = {"discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    # Clear database records
    db_path = str(db.get_project_path(name) / "results.db")
    db.clear_stage(db_path, stage)

    # Delete .vuln_agent_output/<stage> files
    output_dir = Path(proj["target_dir"]) / ".vuln_agent_output" / stage
    if output_dir.exists():
        shutil.rmtree(output_dir)

    return jsonify({"status": "cleared", "stage": stage})


@api_bp.route("/projects/<name>/files/<stage>/<int:file_id>", methods=["DELETE"])
def handle_delete_file(name, stage, file_id):
    import shutil

    VALID_STAGES = {"discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    db_path = str(db.get_project_path(name) / "results.db")
    filename = db.delete_file(db_path, stage, file_id)
    if filename is None:
        return jsonify({"error": "file not found"}), 404

    # Delete file from .vuln_agent_output/<stage>/
    file_path = Path(proj["target_dir"]) / ".vuln_agent_output" / stage / filename
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
    VALID_STAGES = {"discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews"}
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
    exact: dict[str, set[str]] = {st: set() for st in ("discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews")}
    prefix: dict[str, set[str]] = {st: set() for st in ("discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews")}

    # Always include itself
    exact[stage].add(filename)

    if stage == "vuln_reviews":
        # VULN-VULN-{S}-{T}-{V}.md → VULN-{S}-{T}-{V}.md (vuln)
        vuln_name = re.sub(r"^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-", "", filename, count=1)
        exact["vuln_findings"].add(vuln_name)

        # vuln stem without prefix → {S}-{T}-{V}, strip trailing -\d+ → {S}-{T} (task)
        vuln_stem = re.sub(r"^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-", "", vuln_name.replace(".md", ""), count=1)
        task_stem = _strip_one_number(vuln_stem)
        # task stem without trailing -\d+ → {S} (surface)
        surface_stem = _strip_one_number(task_stem)
        surface_name = surface_stem + ".md"
        exact["analyzed_surfaces"].add(surface_name)
        exact["discovered_surfaces"].add(surface_name)

    elif stage == "vuln_findings":
        # VULN-{S}-{T}-{V}.md → VULN-/NOVULN-/SUSPECTED-VULN-{S}-{T}-{V}.md (review)
        for rev_prefix in ("VULN-", "NOVULN-", "SUSPECTED-"):
            exact["vuln_reviews"].add(rev_prefix + filename)

        # strip VULN- → {S}-{T}-{V}, strip trailing -\d+ → {S} (surface)
        vuln_stem = re.sub(r"^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-", "", s, count=1)
        surface_stem = _strip_one_number(vuln_stem)
        surface_name = surface_stem + ".md"
        exact["analyzed_surfaces"].add(surface_name)
        exact["discovered_surfaces"].add(surface_name)

    elif stage in ("analyzed_surfaces", "discovered_surfaces"):
        # Exact: the same file is in both stages
        exact["analyzed_surfaces"].add(filename)
        exact["discovered_surfaces"].add(filename)

        # Prefix: VULN-/DISMISSED-/CLEAN-/SUSPECTED-{S} for vulns, VULN-/NOVULN-/SUSPECTED-VULN-{S} for reviews
        for vp in ("VULN-", "DISMISSED-", "CLEAN-", "SUSPECTED-"):
            prefix["vuln_findings"].add(vp + s)
        for rp in ("VULN-VULN-", "NOVULN-VULN-", "SUSPECTED-VULN-"):
            prefix["vuln_reviews"].add(rp + s)

    return {"exact": exact, "prefix": prefix}


@api_bp.route("/projects/<name>/files/<stage>/<int:file_id>/trace", methods=["GET"])
def handle_trace_file(name, stage, file_id):
    VALID_STAGES = {"discovered_surfaces", "analyzed_surfaces", "vuln_findings", "vuln_reviews"}
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
