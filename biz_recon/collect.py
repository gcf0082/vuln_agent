"""Stage 1: Surface collection."""

from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .workspace import OUTPUT_PARENT, ensure_dirs, build_vars, read_prompt, log


DONE_MARKER = ".collect_done"


def run(work_dir: Path, extra_prompt: str = ""):
    log("\n=== Stage 1: Surface Collection ===")

    marker = work_dir / OUTPUT_PARENT / DONE_MARKER
    if marker.exists():
        log("  SKIP: already completed (delete .collect_done to redo)")
        return

    ensure_dirs(work_dir)
    vars = build_vars(work_dir)
    prompt = read_prompt("identify-surfaces.txt", vars)
    if extra_prompt:
        prompt += "\n\n" + extra_prompt

    client = OpenCodeClient()
    result = client.run(prompt)
    log(f"  exit={result.exit_code}")
    if result.exit_code != 0:
        raise RuntimeError(f"Surface collection failed (exit={result.exit_code})")

    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    return result
