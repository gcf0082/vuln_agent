# -*- coding: utf-8 -*-
"""Stage 3: plan_vuln_tasks — plan vulnerability analysis tasks per analyzed surface."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_surface_files, log


def _has_existing(stem: str, tasks_dir: Path) -> bool:
    if not tasks_dir.exists():
        return False
    return any(not f.stem.endswith("-0") for f in tasks_dir.glob(f"*{stem}*"))


def run(work_dir: Path, max_workers: int = 3,
        force_list: list[str] | None = None,
        extra_prompt: str = ""):
    from .workspace import setup_stage_log
    pv_log = setup_stage_log("plan_vuln_tasks")
    pv_log(f"\n=== Stage 3: Plan Vulnerability Tasks ===")

    analysis_files = find_surface_files(work_dir)
    if not analysis_files:
        pv_log("  No analysis files found.")
        return

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        analysis_files = [sf for sf in analysis_files if sf.stem in stems]
        if not analysis_files:
            pv_log("  No analysis files matched force_list.")
            return
        pv_log(f"  Force surfaces: {[sf.name for sf in analysis_files]}")

    tasks_dir = work_dir / OUTPUT_PARENT / "planned_vuln_tasks"

    need_planning = [sf for sf in analysis_files if not _has_existing(sf.stem, tasks_dir)]
    if not need_planning:
        pv_log(f"  All surfaces already have task files ({len(analysis_files)}/{len(analysis_files)})")
        return

    skipped = len(analysis_files) - len(need_planning)
    pv_log(f"  Planning tasks for {len(need_planning)} surfaces ({skipped} already have tasks, workers={max_workers})...")
    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def plan_one(sf_path):
        plan_log = setup_stage_log("plan_vuln_tasks", sf_path.name)
        plan_log(f"  ▶ {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": extras,
        }
        prompt = read_prompt("plan-vuln-tasks.txt", local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("plan_vuln_tasks", sf_path.name)
        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            plan_log(f"  ✗ {sf_path.name}")
            return False
        plan_log(f"  ✓ {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(need_planning, pool.map(plan_one, need_planning)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        pv_log(msg)
        print(msg, flush=True)
