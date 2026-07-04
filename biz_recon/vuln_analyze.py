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





def _surface_priority(surface_stem: str, plans_dir: Path) -> int:
    """Return priority level: 0=high, 1=medium, 2=low, 3=standard."""
    plan_dir = plans_dir / surface_stem
    if not plan_dir.exists():
        return 3
    if list(plan_dir.glob("high-risk-*.md")):
        return 0
    if list(plan_dir.glob("medium-risk-*.md")):
        return 1
    if list(plan_dir.glob("low-risk-*.md")):
        return 2
    return 3


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None,
        only_stems: list[str] | None = None,
        context: str = "",
        thinking: bool = False):
    from .workspace import ensure_dirs, setup_stage_log
    from . import surface_discover
    va_log = setup_stage_log("vuln_analyze")
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
    plans_dir = work_dir / OUTPUT_PARENT / "vuln_plans"

    # Filter by only_stems (for priority batching)
    if only_stems:
        surface_files = [f for f in surface_files if f.stem in only_stems]
        if not surface_files:
            va_log("  No surfaces match the current priority batch.")
            return find_vuln_files(work_dir)

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        surface_files = [f for f in surface_files if any(s in f.name for s in stems)]
        if not surface_files:
            va_log(f"  No matching surfaces for force-list: {force_list}")
            return find_vuln_files(work_dir)
        va_log(f"  Force re-analyzing {len(surface_files)} surface(s): {[f.name for f in surface_files]}")
    else:
        need_analysis = [f for f in surface_files if not _surface_has_vuln_output(f.stem, vuln_dir)]
        if not need_analysis:
            return find_vuln_files(work_dir)
        surface_files = need_analysis

    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def _run_one(sf_path, prompt_name, extra_vars, log_suffix=""):
        ao_log = setup_stage_log("vuln_analyze", sf_path.name)
        label = f"{sf_path.name}{log_suffix}"
        ao_log(f"  漏洞分析 {label}")

        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
            "extra_prompt": extras,
            **extra_vars,
        }
        prompt = read_prompt(prompt_name, local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("vuln_analyze", label)
        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking)
        if result.exit_code != 0:
            ao_log(f"  ✗ {label}")
            return False
        ao_log(f"  漏洞分析完成 {label}")
        return True

    # Sort by priority: high → medium → low → standard
    surface_files.sort(key=lambda f: _surface_priority(f.stem, plans_dir))

    def analyze_one(sf_path):
        plan_dir = plans_dir / sf_path.stem
        if not plan_dir.exists():
            return _run_one(sf_path, "analyze-vulnerability.txt", {
                "analysis_plan": "", "excluded_plan": "",
            })

        for pf in sorted(plan_dir.glob("*.md")):
            plan_content = pf.read_text(encoding="utf-8")
            is_deep = pf.stem.startswith("high-risk") or pf.stem.startswith("medium-risk")
            prompt_name = "analyze-vulnerability-deep.txt" if is_deep else "analyze-vulnerability.txt"
            ok = _run_one(sf_path, prompt_name, {
                "analysis_plan": plan_content,
                "excluded_plan": "",
            }, log_suffix=f" [{pf.name}]")
            if not ok:
                return False
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
