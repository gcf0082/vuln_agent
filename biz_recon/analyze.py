"""Stage 2: Surface analysis — one client per entry, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .workspace import OUTPUT_PARENT, build_vars, read_prompt, read_surface_list, log


def run(work_dir: Path, max_workers: int = 3,
        only_surfaces: list[str] | None = None,
        extra_prompt: str = ""):
    log(f"\n=== Stage 2: Surface Analysis ===")

    items = read_surface_list(work_dir)
    if not items:
        log("  No surface items found.")
        return items

    if only_surfaces is not None:
        filtered = [item for item in items if item.filename in only_surfaces]
        if not filtered:
            log("  No surfaces matched the --only filter. Nothing to analyze.")
            return filtered
        log(f"  Filtered: {len(items)} → {len(filtered)} items (--only match)")
        items = filtered

    log(f"  {len(items)} items, analyzing in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

    def analyze_one(item):
        output_path = work_dir / OUTPUT_PARENT / "analysis" / item.filename
        if output_path.exists():
            log(f"    SKIP (exists): {item.filename}")
            return True

        local_vars = {**vars,
            "surface_file": str(work_dir / OUTPUT_PARENT / "surfaces" / item.filename),
        }
        prompt = read_prompt("analyze-surface.txt", local_vars)
        if extra_prompt:
            prompt += "\n\n" + extra_prompt

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            msg = f"Analysis failed for {item.filename} (exit={result.exit_code})"
            log(f"    ERROR: {msg}")
            return False
        log(f"    OK: {item.filename}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for item, ok in zip(items, pool.map(analyze_one, items)):
            if not ok:
                failures.append(item.filename)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return items
