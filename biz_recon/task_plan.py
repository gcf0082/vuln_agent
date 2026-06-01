"""Stage 2.5: Task planning — one client per analysis file, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_surface_files, log


def run(work_dir: Path, max_workers: int = 3):
    log(f"\n=== Stage 2.5: Task Planning ===")

    analysis_files = find_surface_files(work_dir)
    if not analysis_files:
        log("  No analysis files found.")
        return []

    tasks_dir = work_dir / OUTPUT_PARENT / "tasks"
    existing = sorted(tasks_dir.glob("*.md")) if tasks_dir.exists() else []
    if existing:
        log(f"  SKIP: tasks already exist ({len(existing)} files)")
        return existing

    tasks_dir.mkdir(parents=True, exist_ok=True)
    log(f"  Planning tasks from {len(analysis_files)} analysis files (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

    def plan_one(sf_path):
        log(f"  ▶ {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
        }
        prompt = read_prompt("plan-tasks.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            log(f"  ✗ {sf_path.name}")
            return False
        log(f"  ✓ {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(analysis_files, pool.map(plan_one, analysis_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return sorted(tasks_dir.glob("*.md"))
