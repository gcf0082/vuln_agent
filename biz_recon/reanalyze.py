# -*- coding: utf-8 -*-
"""Stage 4: Vulnerability re-analysis — one client per file, parallel."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None):
    from .workspace import setup_stage_log
    review_log = setup_stage_log("review")
    review_log(f"\n=== Stage 4: Vulnerability Re-Analysis ===")

    review_dir = work_dir / OUTPUT_PARENT / "vuln_review"
    if not force_list and review_dir.exists() and any(review_dir.iterdir()):
        review_log("  SKIP: vuln_review already has output")
        return sorted(review_dir.glob("*"))

    vuln_files = sorted((work_dir / OUTPUT_PARENT / "vulnerabilities").glob("*.md"))
    if force_list:
        # Match vuln files by surface stem (e.g. iface-REST-api-users-list)
        stems = [n.replace(".md", "") for n in force_list]
        vuln_files = [f for f in vuln_files if any(s in f.name for s in stems)]
        if not vuln_files:
            review_log("  No matching vulnerability files found for force-list.")
            return []
        review_log(f"  Force re-analyzing {len(vuln_files)} file(s): {[f.name for f in vuln_files]}")
    if not vuln_files:
        review_log("  No vulnerability files found.")
        return []

    review_log(f"  Re-analyzing {len(vuln_files)} files in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

    def reanalyze_one(vf_path):
        ra_log = setup_stage_log("review", vf_path.name)
        ra_log(f"  ▶ {vf_path.name}")
        # Derive the corresponding analysis filename from the vuln filename
        # e.g. VULN-iface-REST-api-users-list-1.md → iface-REST-api-users-list.md
        analysis_name = re.sub(r'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-', '', vf_path.stem)
        analysis_name = re.sub(r'-\d+$', '', analysis_name) + '.md'
        local_vars = {**vars,
            "vuln_file": vf_path.name,
            "vuln_file_stem": vf_path.stem,
            "analysis_file": analysis_name,
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("review-vulnerability.txt", local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("review", vf_path.name)
        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            ra_log(f"  ✗ {vf_path.name}")
            return False
        ra_log(f"  ✓ {vf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for vf_path, ok in zip(vuln_files, pool.map(reanalyze_one, vuln_files)):
            if not ok:
                failures.append(vf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        review_log(msg)
        print(msg, flush=True)

    return sorted((work_dir / OUTPUT_PARENT / "vuln_review").glob("*"))
