# -*- coding: utf-8 -*-
"""Stage 1: surface_discover — discover attack surfaces from target code."""

from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, ensure_dirs, build_vars, log, get_timeout, save_thinking, append_thinking_manifest


DONE_MARKER = ".surface_discover_done"


def run(work_dir: Path, extra_prompt: str = "", force: bool = False,
        thinking: bool = False, prefix: str = ""):
    from .workspace import setup_stage_log
    sd_log = setup_stage_log("surface_discover", prefix=prefix)
    sd_log(f"{prefix} → 暴露面识别")

    marker = work_dir / OUTPUT_PARENT / DONE_MARKER
    if not force and marker.exists():
        sd_log(f"{prefix} ⏭ 暴露面识别跳过")
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

    client = OpenCodeClient()
    result = client.run(prompt, verbose=thinking, timeout=get_timeout("surface_discover"))

    thinking_id = "discover"
    save_thinking(work_dir, thinking_id, prompt, result.text, "discover", result.exit_code)

    if result.exit_code != 0:
        suffix = "（超时）" if result.timed_out else ""
        sd_log(f"{prefix} ⚠ 暴露面识别失败 (exit={result.exit_code}){suffix}")
        return

    surfaces_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
    surface_files = sorted(surfaces_dir.glob("*.md"))
    if surface_files:
        append_thinking_manifest(work_dir, {
            "thinking_id": thinking_id,
            "stage": "discover",
            "surface_stem": None,
            "output_files": [f"discovered_surfaces/{f.name}" for f in surface_files],
        })
    if not surface_files:
        sd_log(f"{prefix} ⚠ 暴露面识别完成，但未生成任何暴露面文件")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
        return

    sd_log(f"{prefix} ✓ 暴露面识别完成")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    sd_log(f"{prefix} Generated {len(surface_files)} surface entries:")

    return result
