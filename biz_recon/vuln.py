"""Stage 4: Vulnerability analysis — one client per surface, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .workspace import build_vars, read_prompt, find_surface_files, find_vuln_files, needs_analysis, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = ""):
    from .workspace import ensure_dirs
    log(f"\n=== Stage 4: Vulnerability Analysis ===")
    ensure_dirs(work_dir)

    surface_files = find_surface_files(work_dir)
    to_analyze = [f for f in surface_files if needs_analysis(work_dir, f.name)]

    if not to_analyze:
        log("  All surfaces already analyzed.")
        return find_vuln_files(work_dir)

    log(f"  Analyzing {len(to_analyze)} surfaces in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)

    def analyze_one(sf_path):
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
        }
        prompt = read_prompt("analyze-vulnerability.txt", local_vars)
        if extra_prompt:
            prompt += "\n\n" + extra_prompt

        client = OpenCodeClient()
        result = client.run(prompt)
        status = "OK" if result.exit_code == 0 else f"FAIL({result.exit_code})"
        log(f"    {status}: {sf_path.name}")
        return sf_path

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        pool.map(analyze_one, to_analyze)

    return find_vuln_files(work_dir)
