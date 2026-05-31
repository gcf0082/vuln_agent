"""Stage 3: Vulnerability analysis — one client per surface, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import build_vars, find_surface_files, find_vuln_files, needs_analysis, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None):
    from .workspace import ensure_dirs
    log(f"\n=== Stage 3: Vulnerability Analysis ===")
    ensure_dirs(work_dir)

    surface_files = find_surface_files(work_dir)
    if force_list:
        to_analyze = [f for f in surface_files if f.name in force_list]
        if not to_analyze:
            log(f"  No matching surfaces for force-list: {force_list}")
            return find_vuln_files(work_dir)
        log(f"  Force re-analyzing {len(to_analyze)} surface(s): {[f.name for f in to_analyze]}")
    else:
        to_analyze = [f for f in surface_files if needs_analysis(work_dir, f.name)]

    if not to_analyze:
        log("  All surfaces already analyzed.")
        return find_vuln_files(work_dir)

    log(f"  Analyzing {len(to_analyze)} surfaces in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

    def analyze_one(sf_path):
        log(f"  ▶ {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("analyze-vulnerability.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            log(f"  ✗ {sf_path.name}")
            return False
        log(f"  ✓ {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(to_analyze, pool.map(analyze_one, to_analyze)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return find_vuln_files(work_dir)
