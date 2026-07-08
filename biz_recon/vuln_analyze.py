# -*- coding: utf-8 -*-
"""Stage 3: vuln_analyze — execute vulnerability analysis per analyzed surface, parallel."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_vuln_files, log


def _surface_has_vuln_output(surface_stem: str, vuln_dir: Path, plans_dir: Path | None = None) -> bool:
    """Check if a surface already has corresponding vulnerability analysis results."""
    if vuln_dir.exists():
        pattern = re.compile(rf'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-{re.escape(surface_stem)}-\d+\.md$')
        if any(pattern.match(f.name) for f in vuln_dir.iterdir()):
            return True
    if plans_dir is not None:
        plan_dir = plans_dir / surface_stem
        if plan_dir.exists() and list(plan_dir.glob("none-risk-*.md")):
            return True
    return False





def _surface_priority(surface_stem: str, plans_dir: Path) -> int:
    """Return priority level: 0=high, 1=medium, 2=low."""
    plan_dir = plans_dir / surface_stem
    if not plan_dir.exists():
        return 2
    if list(plan_dir.glob("high-risk-*.md")):
        return 0
    if list(plan_dir.glob("medium-risk-*.md")):
        return 1
    return 2


_LEVEL_MAP = {"high": 0, "medium": 1, "low": 2}


def _plan_file_level(pf: Path) -> int:
    stem = pf.stem
    if stem.startswith("high-risk"):
        return 0
    if stem.startswith("medium-risk"):
        return 1
    if stem.startswith("low-risk"):
        return 2
    if stem.startswith("none-risk"):
        return 99
    return 2


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None,
        only_stems: list[str] | None = None,
        thinking: bool = False,
        min_level: str = "low",
        risk_first: bool = False,
        prefix: str = "",
        force: bool = False):
    from .workspace import ensure_dirs, setup_stage_log
    from . import surface_discover
    va_log = setup_stage_log("vuln_analyze", prefix=prefix)
    ensure_dirs(work_dir)

    analysis_dir = work_dir / OUTPUT_PARENT / "analyzed_surfaces"
    if not analysis_dir.exists():
        va_log(f"{prefix} No analyzed surfaces directory found.")
        return find_vuln_files(work_dir)

    surface_files = sorted(analysis_dir.glob("*.md"))
    if not surface_files:
        va_log(f"{prefix} No analyzed surface files found.")
        return find_vuln_files(work_dir)

    vuln_dir = work_dir / OUTPUT_PARENT / "vuln_findings"
    plans_dir = work_dir / OUTPUT_PARENT / "vuln_plans"

    if only_stems:
        surface_files = [f for f in surface_files if f.stem in only_stems]
        if not surface_files:
            return find_vuln_files(work_dir)

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        surface_files = [f for f in surface_files if any(s in f.name for s in stems)]
        if not surface_files:
            va_log(f"{prefix} No matching surfaces for force-list: {force_list}")
            return find_vuln_files(work_dir)
    elif not force:
        need_analysis = [f for f in surface_files if not _surface_has_vuln_output(f.stem, vuln_dir, plans_dir)]
        if not need_analysis:
            return find_vuln_files(work_dir)
        surface_files = need_analysis

    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def _run_one(sf_path, prompt_name, extra_vars, log_suffix=""):
        ao_log = setup_stage_log("vuln_analyze", sf_path.name, prefix=prefix)
        label = f"{sf_path.name}{log_suffix}"
        ao_log(f"{prefix} → 漏洞分析 {label}")

        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": extras,
            **extra_vars,
        }
        prompt = read_prompt(prompt_name, local_vars)

        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking)
        if result.exit_code != 0:
            ao_log(f"{prefix} ✗ {label}")
            return False
        ao_log(f"{prefix} ✓ 漏洞分析完成 {label}")
        return True

    surface_files.sort(key=lambda f: _surface_priority(f.stem, plans_dir))

    min_level_num = _LEVEL_MAP.get(min_level, 3)

    def _level_match(pf: Path) -> bool:
        lvl = _plan_file_level(pf)
        if risk_first:
            return lvl == min_level_num
        return lvl <= min_level_num

    def analyze_one(sf_path):
        plan_dir = plans_dir / sf_path.stem
        if not plan_dir.exists():
            return _run_one(sf_path, "analyze-vulnerability.txt", {
                "analysis_plan": "",
            })

        for pf in sorted(plan_dir.glob("*.md")):
            if not _level_match(pf):
                continue
            plan_content = pf.read_text(encoding="utf-8")
            ok = _run_one(sf_path, "analyze-vulnerability.txt", {
                "analysis_plan": plan_content,
            }, log_suffix=f" [{pf.name}]")
            if not ok:
                return False
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(surface_files, pool.map(analyze_one, surface_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"{prefix} FAILURES ({len(failures)}): {', '.join(failures)}"
        va_log(msg)
        print(msg, flush=True)

    return find_vuln_files(work_dir)
