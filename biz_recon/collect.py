# -*- coding: utf-8 -*-
"""Stage 1: Surface collection."""

from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, ensure_dirs, build_vars, log


DONE_MARKER = ".collect_done"


def run(work_dir: Path, extra_prompt: str = ""):
    from .workspace import setup_stage_log
    collect_log = setup_stage_log("collect")
    collect_log("\n=== Stage 1: Surface Collection ===")

    marker = work_dir / OUTPUT_PARENT / DONE_MARKER
    if marker.exists():
        collect_log("  SKIP: already completed (delete .collect_done to redo)")
        return

    ensure_dirs(work_dir)
    vars = build_vars(work_dir)
    vars["extra_prompt"] = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    prompt = read_prompt("identify-surfaces.txt", vars)

    from .workspace import set_prompt_log_path
    set_prompt_log_path("collect")
    client = OpenCodeClient()
    result = client.run(prompt)
    collect_log(f"  exit={result.exit_code}")
    if result.exit_code != 0:
        raise RuntimeError(f"Surface collection failed (exit={result.exit_code})")

    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()

    surfaces_dir = work_dir / OUTPUT_PARENT / "surfaces"
    surface_files = sorted(surfaces_dir.glob("*.md"))
    collect_log(f"  Generated {len(surface_files)} surface entries:")
    for sf in surface_files:
        collect_log(f"    - {sf.name}")

    return result
