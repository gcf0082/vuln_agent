# -*- coding: utf-8 -*-
"""review_vuln — challenge-review each vuln finding, parallel (per-surface, not a global stage)."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, log


def _vuln_has_review(vuln_stem: str, review_dir: Path) -> bool:
    """Check if a vulnerability file already has a corresponding review result."""
    if not review_dir.exists():
        return False
    pattern = re.compile(rf'^(?:VULN-|NOVULN-|SUSPECTED-){re.escape(vuln_stem)}\.md$')
    return any(pattern.match(f.name) for f in review_dir.glob("*.md"))


def _extract_surface_stem(vuln_stem: str) -> str:
    """Extract surface stem from a vulnerability filename stem.
    
    e.g. VULN-iface-REST-ping-1 → iface-REST-ping
    """
    stem = re.sub(r'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-', '', vuln_stem)
    stem = re.sub(r'-\d+$', '', stem)
    return stem


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None,
        only_stems: list[str] | None = None,
        thinking: bool = False,
        prefix: str = ""):
    from .workspace import setup_stage_log
    rv_log = setup_stage_log("review_vuln", prefix=prefix)
    review_dir = work_dir / OUTPUT_PARENT / "vuln_reviews"
    review_dir.mkdir(parents=True, exist_ok=True)

    vuln_files = sorted((work_dir / OUTPUT_PARENT / "vuln_findings").glob("*.md"))
    if not vuln_files:
        return []

    if only_stems:
        vuln_files = [f for f in vuln_files if _extract_surface_stem(f.stem) in only_stems]
        if not vuln_files:
            return sorted(review_dir.glob("*"))

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        vuln_files = [f for f in vuln_files if any(s in f.name for s in stems)]
        if not vuln_files:
            rv_log(f"{prefix} No matching vulnerability files found for force-list.")
            return []
    else:
        need_review = [f for f in vuln_files if not _vuln_has_review(f.stem, review_dir)]
        if not need_review:
            return sorted(review_dir.glob("*"))
        vuln_files = need_review

    vars = build_vars(work_dir)
    failures: list[str] = []

    def reanalyze_one(vf_path):
        ra_log = setup_stage_log("review_vuln", vf_path.name, prefix=prefix)
        ra_log(f"{prefix} → 漏洞复核 {vf_path.name}")
        analysis_name = re.sub(r'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-', '', vf_path.stem)
        analysis_name = re.sub(r'-\d+$', '', analysis_name) + '.md'
        local_vars = {**vars,
            "vuln_file": vf_path.name,
            "vuln_file_stem": vf_path.stem,
            "analysis_file": analysis_name,
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("review-vulnerability.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking)
        if result.exit_code != 0:
            ra_log(f"{prefix} ✗ {vf_path.name}")
            return False
        ra_log(f"{prefix} ✓ 漏洞复核完成 {vf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for vf_path, ok in zip(vuln_files, pool.map(reanalyze_one, vuln_files)):
            if not ok:
                failures.append(vf_path.name)

    if failures:
        msg = f"{prefix} FAILURES ({len(failures)}): {', '.join(failures)}"
        rv_log(msg)
        print(msg, flush=True)

    return sorted((work_dir / OUTPUT_PARENT / "vuln_reviews").glob("*"))
