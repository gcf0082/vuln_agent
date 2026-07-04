# -*- coding: utf-8 -*-
"""Stage 1: surface_discover — discover attack surfaces from target code."""

from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, ensure_dirs, build_vars, log


DONE_MARKER = ".surface_discover_done"


def run(work_dir: Path, extra_prompt: str = "", force: bool = False,
        thinking: bool = False):
    from .workspace import setup_stage_log
    sd_log = setup_stage_log("surface_discover")
    sd_log("\n=== Surface Discovery ===")

    marker = work_dir / OUTPUT_PARENT / DONE_MARKER
    if not force and marker.exists():
        sd_log("  暴露面识别跳过 (already completed)")
        return

    ensure_dirs(work_dir)
    vars = build_vars(work_dir)

    extras = ""
    if extra_prompt:
        extras += f"\n**用户特殊要求：**{extra_prompt}"
    ext_file = Path(__file__).parent.parent / "prompts-ext" / "surface_discover.md"
    if ext_file.exists():
        content = ext_file.read_text(encoding="utf-8").strip()
        if content:
            extras += f"\n\n{content}"
    vars["extra_prompt"] = extras
    prompt = read_prompt("identify-surfaces.txt", vars)

    from .workspace import set_prompt_log_path
    set_prompt_log_path("surface_discover")
    sd_log("  暴露面识别")
    client = OpenCodeClient()
    result = client.run(prompt, verbose=thinking)
    if result.exit_code != 0:
        raise RuntimeError(f"Surface discovery failed (exit={result.exit_code})")
    sd_log("  暴露面识别完成")

    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()

    surfaces_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
    surface_files = sorted(surfaces_dir.glob("*.md"))
    sd_log(f"  Generated {len(surface_files)} surface entries:")
    for sf in surface_files:
        sd_log(f"    - {sf.name}")

    return result
