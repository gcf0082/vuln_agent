# -*- coding: utf-8 -*-
"""Stage 3: vuln_analyze — execute vulnerability analysis per analyzed surface, parallel."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_vuln_files, log


def _surface_has_vuln_output(surface_stem: str, vuln_dir: Path) -> bool:
    """Check if a surface already has corresponding vulnerability analysis results."""
    if not vuln_dir.exists():
        return False
    pattern = re.compile(rf'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-{re.escape(surface_stem)}-\d+\.md$')
    return any(pattern.match(f.name) for f in vuln_dir.iterdir())


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None):
    from .workspace import ensure_dirs, setup_stage_log
    from . import surface_discover
    va_log = setup_stage_log("vuln_analyze")
    va_log(f"\n=== Stage 3: Vulnerability Analysis ===")
    ensure_dirs(work_dir)

    analysis_dir = work_dir / OUTPUT_PARENT / "analyzed_surfaces"
    if not analysis_dir.exists():
        va_log("  No analyzed surfaces directory found. Run surface analysis first.")
        return find_vuln_files(work_dir)

    surface_files = sorted(analysis_dir.glob("*.md"))
    if not surface_files:
        va_log("  No analyzed surface files found. Run surface analysis first.")
        return find_vuln_files(work_dir)

    vuln_dir = work_dir / OUTPUT_PARENT / "vuln_findings"

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        surface_files = [f for f in surface_files if any(s in f.name for s in stems)]
        if not surface_files:
            va_log(f"  No matching surfaces for force-list: {force_list}")
            return find_vuln_files(work_dir)
        va_log(f"  Force re-analyzing {len(surface_files)} surface(s): {[f.name for f in surface_files]}")
    else:
        need_analysis = [f for f in surface_files if not _surface_has_vuln_output(f.stem, vuln_dir)]
        skipped = len(surface_files) - len(need_analysis)
        if not need_analysis:
            va_log(f"  All {len(surface_files)} surfaces already have vulnerability analysis results.")
            return find_vuln_files(work_dir)
        surface_files = need_analysis
        va_log(f"  Analyzing {len(surface_files)} surfaces ({skipped} already have results, workers={max_workers})...")

    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def analyze_one(sf_path):
        ao_log = setup_stage_log("vuln_analyze", sf_path.name)
        ao_log(f"  ▶ {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": extras,
        }
        prompt = read_prompt("analyze-vulnerability.txt", local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("vuln_analyze", sf_path.name)
        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            ao_log(f"  ✗ {sf_path.name}")
            return False
        ao_log(f"  ✓ {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(surface_files, pool.map(analyze_one, surface_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        va_log(msg)
        print(msg, flush=True)

    return find_vuln_files(work_dir)
