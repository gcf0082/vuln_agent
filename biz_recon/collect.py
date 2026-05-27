"""Stage 1: Surface collection."""

from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .workspace import ensure_dirs, build_vars, read_prompt, log


def run(work_dir: Path, extra_prompt: str = ""):
    log("\n=== Stage 1: Surface Collection ===")
    ensure_dirs(work_dir)
    vars = build_vars(work_dir)
    prompt = read_prompt("identify-surfaces.txt", vars)
    if extra_prompt:
        prompt += "\n\n" + extra_prompt

    client = OpenCodeClient()
    result = client.run(prompt)
    log(f"  exit={result.exit_code}")
    return result
