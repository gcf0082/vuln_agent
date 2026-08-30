# -*- coding: utf-8 -*-
"""Stage 2: surface_analyze — deep-analyze each discovered surface, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, read_surface_list, log, get_timeout, record_failure, save_thinking, append_thinking_manifest


def run(work_dir: Path, max_workers: int = 3,
        only_surfaces: list[str] | None = None,
        任务特殊要求: str = "",
        thinking: bool = False,
        prefix: str = ""):
    from .workspace import setup_stage_log
    sa_log = setup_stage_log("surface_analyze", prefix=prefix)

    items = read_surface_list(work_dir)
    if not items:
        sa_log(f"{prefix} No surface items found.")
        return items

    if only_surfaces is not None:
        filtered = [item for item in items if item.filename in only_surfaces]
        if not filtered:
            sa_log(f"{prefix} No surfaces matched the --only filter.")
            return filtered
        items = filtered

    vars = build_vars(work_dir)
    failures: list[str] = []

    def analyze_one(item):
        ao_log = setup_stage_log("surface_analyze", item.filename, prefix=prefix)
        output_path = work_dir / OUTPUT_PARENT / "analyzed_surfaces" / item.filename
        if output_path.exists():
            ao_log(f"{prefix} ⏭ 业务流分析跳过 {item.filename}")
            return True

        ao_log(f"{prefix} → 业务流分析 {item.filename}")
        local_vars = {**vars,
            "surface_file": item.filename,
            "任务特殊要求": f"\n**任务特殊要求：**{任务特殊要求}" if 任务特殊要求 else "",
        }
        prompt = read_prompt("analyze-surface.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking, timeout=get_timeout())

        thinking_id = f"analyze-{item.filename.replace('.md', '')}"
        save_thinking(work_dir, thinking_id, prompt, result.text, "analyze", result.exit_code)

        if result.exit_code != 0:
            suffix = "（超时）" if result.timed_out else ""
            ao_log(f"{prefix} ✗ {item.filename}{suffix}")
            return False
        append_thinking_manifest(work_dir, {
            "thinking_id": thinking_id,
            "stage": "analyze",
            "surface_stem": item.filename.replace('.md', ''),
            "output_files": [f"analyzed_surfaces/{item.filename}"],
        })
        ao_log(f"{prefix} ✓ 业务流分析完成 {item.filename}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for item, ok in zip(items, pool.map(analyze_one, items)):
            if not ok:
                failures.append(item.filename)

    if failures:
        msg = f"{prefix} FAILURES ({len(failures)}): {', '.join(failures)}"
        sa_log(msg)
        print(msg, flush=True)
        for fname in failures:
            record_failure(f"业务流分析 [{prefix}] {fname}")

    return items
