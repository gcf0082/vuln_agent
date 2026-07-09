# -*- coding: utf-8 -*-
"""Stage 2.5: vuln_planner — evaluate each analyzed surface and output analysis plan."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        thinking: bool = False,
        only_stems: list[str] | None = None,
        prefix: str = ""):
    from .workspace import setup_stage_log
    pl_log = setup_stage_log("vuln_planner", prefix=prefix)

    analysis_dir = work_dir / OUTPUT_PARENT / "analyzed_surfaces"
    if not analysis_dir.exists():
        pl_log(f"{prefix} No analyzed surfaces directory found.")
        return

    surface_files = sorted(analysis_dir.glob("*.md"))
    if not surface_files:
        pl_log(f"{prefix} No analyzed surface files found.")
        return

    if only_stems:
        surface_files = [f for f in surface_files if f.stem in only_stems]
        if not surface_files:
            return

    plans_dir = work_dir / OUTPUT_PARENT / "vuln_plans"
    plans_dir.mkdir(parents=True, exist_ok=True)

    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def plan_one(sf_path):
        pl_ao_log = setup_stage_log("vuln_planner", sf_path.name, prefix=prefix)
        plan_dir = plans_dir / sf_path.stem
        if plan_dir.exists():
            pl_ao_log(f"{prefix} ⏭ 规划漏洞分析任务跳过 {sf_path.name}")
            return True

        pl_ao_log(f"{prefix} → 规划漏洞分析任务 {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": extras,
        }
        prompt = read_prompt("vuln-planner.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking, timeout=get_timeout())
        if result.exit_code != 0:
            suffix = "（超时）" if result.timed_out else ""
            pl_ao_log(f"{prefix} ✗ {sf_path.name}{suffix}")
            return False
        pl_ao_log(f"{prefix} ✓ 规划漏洞分析任务完成 {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(surface_files, pool.map(plan_one, surface_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"{prefix} FAILURES ({len(failures)}): {', '.join(failures)}"
        pl_log(msg)
        print(msg, flush=True)
