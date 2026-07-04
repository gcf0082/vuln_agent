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


def _read_deep_risk_plan(plans_dir: Path, surface_stem: str) -> str:
    """Read high-risk and medium-risk plan files for exclusion in standard pass."""
    plan_dir = plans_dir / surface_stem
    files = sorted(
        list(plan_dir.glob("high-risk-*.md")) +
        list(plan_dir.glob("medium-risk-*.md"))
    )
    if not files:
        return ""
    content = "\n\n---\n\n".join(f.read_text(encoding="utf-8") for f in files)
    return (
        "## 已在深度分析中覆盖的项\n\n"
        f"{content}\n\n"
        "**跳过说明**：上列分析点已在深度追踪中覆盖并产出结论文件，请跳过，不要重复分析。\n"
    )


def _read_plan(plans_dir: Path, surface_stem: str, pattern: str) -> str:
    """Read plan files matching a glob pattern and return combined content."""
    plan_dir = plans_dir / surface_stem
    files = sorted(plan_dir.glob(pattern))
    if not files:
        return ""
    return "\n\n---\n\n".join(f.read_text(encoding="utf-8") for f in files)


def _resolve_prompt_name_and_plan(surface_stem: str, plans_dir: Path) -> tuple[str, str]:
    """Determine which prompt template to use based on planner output.

    Returns (prompt_name, plan_content).
    - high-risk-*.md or medium-risk-*.md exist → deep analysis
    - low-risk-*.md or standard.md exist → standard analysis
    - otherwise → default standard analysis
    """
    plan_dir = plans_dir / surface_stem
    if not plan_dir.exists():
        return "analyze-vulnerability.txt", ""

    deep_files = sorted(
        list(plan_dir.glob("high-risk-*.md")) +
        list(plan_dir.glob("medium-risk-*.md"))
    )
    if deep_files:
        plan_content = "\n\n---\n\n".join(
            f.read_text(encoding="utf-8") for f in deep_files
        )
        return "analyze-vulnerability-deep.txt", plan_content

    low_risk_files = sorted(plan_dir.glob("low-risk-*.md"))
    if low_risk_files:
        plan_content = "\n\n---\n\n".join(
            f.read_text(encoding="utf-8") for f in low_risk_files
        )
        return "analyze-vulnerability.txt", plan_content

    standard_file = plan_dir / "standard.md"
    if standard_file.exists():
        return "analyze-vulnerability.txt", standard_file.read_text(encoding="utf-8")

    return "analyze-vulnerability.txt", ""


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
        only_stems: list[str] | None = None):
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
        skipped = len(surface_files) - len(need_analysis)
        if not need_analysis:
            va_log(f"  All {len(surface_files)} surfaces already have vulnerability analysis results.")
            return find_vuln_files(work_dir)
        surface_files = need_analysis
        va_log(f"  Analyzing {len(surface_files)} surfaces ({skipped} already have results, workers={max_workers})...")

    vars = build_vars(work_dir)
    extras = f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else ""
    failures: list[str] = []

    def _run_one(sf_path, prompt_name, extra_vars, log_suffix=""):
        ao_log = setup_stage_log("vuln_analyze", sf_path.name)
        label = f"{sf_path.name}{log_suffix}"
        ao_log(f"  ▶ {label}")

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
        result = client.run(prompt)
        if result.exit_code != 0:
            ao_log(f"  ✗ {label}")
            return False
        ao_log(f"  ✓ {label}")
        return True

    # Sort by priority: high → medium → low → standard
    surface_files.sort(key=lambda f: _surface_priority(f.stem, plans_dir))

    def analyze_one(sf_path):
        prompt_name, plan_content = _resolve_prompt_name_and_plan(sf_path.stem, plans_dir)
        deep = prompt_name == "analyze-vulnerability-deep.txt"

        if not deep:
            # standard analysis only
            ok = _run_one(sf_path, prompt_name, {
                "analysis_plan": plan_content,
                "excluded_plan": "",
            })
        else:
            # pass 1: deep analysis for high-risk and medium-risk items
            ok = _run_one(sf_path, "analyze-vulnerability-deep.txt", {
                "analysis_plan": plan_content,
                "excluded_plan": "",
            }, " [deep]")
            if not ok:
                return False
            # pass 2: standard analysis for remaining items, skipping deep-covered items
            excluded = _read_deep_risk_plan(plans_dir, sf_path.stem)
            ok = _run_one(sf_path, "analyze-vulnerability.txt", {
                "analysis_plan": "",
                "excluded_plan": excluded,
            }, " [standard]")

        return ok

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(surface_files, pool.map(analyze_one, surface_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        va_log(msg)
        print(msg, flush=True)

    return find_vuln_files(work_dir)
