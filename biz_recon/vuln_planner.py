# -*- coding: utf-8 -*-
"""Stage 2.5: vuln_planner — evaluate each analyzed surface and output analysis plan."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        thinking: bool = False):
    from .workspace import setup_stage_log
    pl_log = setup_stage_log("vuln_planner")
    pl_log("\n=== 阶段3: 漏洞分析规划 ===")

    analysis_dir = work_dir / OUTPUT_PARENT / "analyzed_surfaces"
    if not analysis_dir.exists():
        pl_log("  No analyzed surfaces directory found. Run surface analysis first.")
        return

    surface_files = sorted(analysis_dir.glob("*.md"))
    if not surface_files:
        pl_log("  No analyzed surface files found. Run surface analysis first.")
        return

    plans_dir = work_dir / OUTPUT_PARENT / "vuln_plans"
    plans_dir.mkdir(parents=True, exist_ok=True)

    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def plan_one(sf_path):
        pl_ao_log = setup_stage_log("vuln_planner", sf_path.name)
        plan_dir = plans_dir / sf_path.stem
        if plan_dir.exists():
            pl_ao_log(f"  规划分析跳过 {sf_path.name}")
            return True

        pl_ao_log(f"  规划分析 {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": extras,
        }
        prompt = read_prompt("vuln-planner.txt", local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("vuln_planner", sf_path.name)
        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking)
        if result.exit_code != 0:
            pl_ao_log(f"  ✗ {sf_path.name}")
            return False
        pl_ao_log(f"  规划分析完成 {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(surface_files, pool.map(plan_one, surface_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        pl_log(msg)
        print(msg, flush=True)
