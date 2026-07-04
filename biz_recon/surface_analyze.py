# -*- coding: utf-8 -*-
"""Stage 2: surface_analyze — deep-analyze each discovered surface, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, read_surface_list, log


def run(work_dir: Path, max_workers: int = 3,
        only_surfaces: list[str] | None = None,
        extra_prompt: str = "",
        thinking: bool = False):
    from .workspace import setup_stage_log
    sa_log = setup_stage_log("surface_analyze")
    sa_log("\n=== 阶段2: 业务流分析 ===")

    items = read_surface_list(work_dir)
    if not items:
        sa_log("  No surface items found.")
        return items

    if only_surfaces is not None:
        filtered = [item for item in items if item.filename in only_surfaces]
        if not filtered:
            sa_log("  No surfaces matched the --only filter. Nothing to analyze.")
            return filtered
        items = filtered

    vars = build_vars(work_dir)
    failures: list[str] = []

    def analyze_one(item):
        ao_log = setup_stage_log("surface_analyze", item.filename)
        output_path = work_dir / OUTPUT_PARENT / "analyzed_surfaces" / item.filename
        if output_path.exists():
            ao_log(f"  业务流分析跳过 {item.filename}")
            return True

        ao_log(f"  业务流分析 {item.filename}")
        local_vars = {**vars,
            "surface_file": item.filename,
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("analyze-surface.txt", local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("surface_analyze", item.filename)
        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking)
        if result.exit_code != 0:
            ao_log(f"  ✗ {item.filename}")
            return False
        ao_log(f"  业务流分析完成 {item.filename}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for item, ok in zip(items, pool.map(analyze_one, items)):
            if not ok:
                failures.append(item.filename)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        sa_log(msg)
        print(msg, flush=True)

    return items
