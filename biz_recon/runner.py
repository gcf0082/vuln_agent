#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline runner — executes all stages in sequence."""

import fnmatch
import os
import shutil
import sys
from pathlib import Path

from . import surface_discover, surface_analyze, vuln_planner, vuln_analyze, review_vuln
from .workspace import OUTPUT_PARENT, setup_logging, setup_stage_log, find_surface_files, find_vuln_files


def load_config() -> dict:
    """Load flat key-value config from analysis-config.yaml."""
    config_path = Path(__file__).parent.parent / "config" / "analysis-config.yaml"
    config: dict = {}
    if not config_path.exists():
        return config
    for line in config_path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if val.lower() == "true":
            val = True
        elif val.lower() == "false":
            val = False
        else:
            try:
                val = int(val)
            except ValueError:
                pass
        config[key] = val
    return config


# ── Stage Registry ──

_STAGE_REGISTRY = {
    "recon": {
        "module": surface_discover,
        "name": "暴露面识别",
        "dir": "discovered_surfaces",
        "requires": [],
        "config_key": None,
    },
    "flow": {
        "module": surface_analyze,
        "name": "业务流分析",
        "dir": "analyzed_surfaces",
        "requires": ["discovered_surfaces"],
        "config_key": None,
    },
    "plan": {
        "module": vuln_planner,
        "name": "漏洞分析规划",
        "dir": "vuln_plans",
        "requires": ["analyzed_surfaces"],
        "config_key": "vuln_planning",
    },
    "vuln": {
        "module": vuln_analyze,
        "name": "漏洞分析",
        "dir": "vuln_findings",
        "requires": ["analyzed_surfaces"],
        "config_key": None,
    },
    "verify": {
        "module": review_vuln,
        "name": "二次审查",
        "dir": "vuln_reviews",
        "requires": ["vuln_findings"],
        "config_key": None,
    },
}

_PRIORITY_LABELS = ["high", "medium", "low", "standard"]

_STAGE_NAMES = {k: v["name"] for k, v in _STAGE_REGISTRY.items()}
_STAGE_DIRS = {k: v["dir"] for k, v in _STAGE_REGISTRY.items()}

STAGE_ORDER = _STAGE_NAMES  # insertion-order dict → ordered





def _group_surfaces_by_priority(analysis_dir: Path, plans_dir: Path) -> list[tuple[str, list[str]]]:
    """Group surface stems by their max priority level.
    
    Returns [(label, [stems]), ...] ordered high → medium → low → standard,
    skipping empty groups.
    """
    groups: dict[str, list[str]] = {l: [] for l in _PRIORITY_LABELS}
    for sf in sorted(analysis_dir.glob("*.md")):
        plan_dir = plans_dir / sf.stem
        if plan_dir.exists():
            if list(plan_dir.glob("high-risk-*.md")):
                groups["high"].append(sf.stem)
            elif list(plan_dir.glob("medium-risk-*.md")):
                groups["medium"].append(sf.stem)
            elif list(plan_dir.glob("low-risk-*.md")):
                groups["low"].append(sf.stem)
            else:
                groups["standard"].append(sf.stem)
        else:
            groups["standard"].append(sf.stem)
    return [(l, groups[l]) for l in _PRIORITY_LABELS if groups[l]]


def _resolve_stages(work_path: Path, stage: str, force_list: list[str] | None = None,
                    config: dict | None = None) -> list[str]:
    """Return ordered stage list, auto-adding missing prerequisites.

    Stages with a config_key set to false in config are skipped,
    unless explicitly requested via --stage.
    """
    if config is None:
        config = {}

    all_stages = [s for s in _STAGE_REGISTRY]

    if not stage:
        stages = list(all_stages)
    else:
        stages = []
        for s in all_stages:
            if s == stage:
                stages.append(s)
                break

            entry = _STAGE_REGISTRY[s]
            output_dir = work_path / OUTPUT_PARENT / entry["dir"]

            if s == "recon":
                need = not (output_dir.exists() and bool(list(output_dir.rglob("*.md"))))
            elif force_list:
                if s == "flow":
                    existing = {f.name for f in output_dir.glob("*.md")} if output_dir.exists() else set()
                    need = not all(n in existing for n in force_list)
                elif s == "plan":
                    stems = [n.replace(".md", "") for n in force_list]
                    need = not all((output_dir / stem).exists() for stem in stems)
                else:
                    existing = [f.name for f in output_dir.glob("*.md")] if output_dir.exists() else []
                    stems = [n.replace(".md", "") for n in force_list]
                    need = not all(any(s in name for name in existing) for s in stems)
            else:
                need = not (output_dir.exists() and bool(list(output_dir.rglob("*.md"))))

            if need:
                stages.append(s)

    # Filter disabled stages (config_key=false) unless explicitly requested
    return [s for s in stages
            if s == stage or _stage_enabled(s, config)]


def _force_clean_stage(work_path: Path, stage_key: str, force_list: list[str],
                        runner_log) -> None:
    """Remove existing outputs for force-listed surfaces in a given stage."""
    dirname = _STAGE_REGISTRY[stage_key]["dir"]
    d = work_path / OUTPUT_PARENT / dirname
    for name in force_list:
        stem = name.replace(".md", "")
        if stage_key == "plan":
            subdir = d / stem
            if subdir.exists():
                shutil.rmtree(subdir)
                runner_log(f"  Removed: {d.name}/{stem}/")
        else:
            pattern = f"{stem}*" if stage_key == "flow" else f"*{stem}*"
            for f in d.glob(pattern):
                if f.is_file():
                    f.unlink()
                    runner_log(f"  Removed: {d.name}/{f.name}")


def _stage_enabled(stage_key: str, config: dict) -> bool:
    """Check if a stage is enabled in config."""
    entry = _STAGE_REGISTRY.get(stage_key)
    if not entry:
        return True
    key = entry.get("config_key")
    if key is None:
        return True
    return config.get(key, True)


def _prepare_stage(work_path: Path, stage: str, overwrite: bool, runner_log) -> None:
    """Prepare stage output directory before execution.

    overwrite=True:  delete entire output directory for a fresh start.
    overwrite=False: do nothing (append mode — stage receives force=True to skip internal checks).
    """
    if overwrite:
        d = work_path / OUTPUT_PARENT / _STAGE_DIRS[stage]
        if d.exists():
            for child in d.iterdir():
                if child.is_file():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
            runner_log(f"  Cleared: {OUTPUT_PARENT}/{_STAGE_DIRS[stage]}/")


def _run_stage(stage_func, stage_key, runner_log, **kwargs):
    """Run a single stage."""
    stage_func(**kwargs)


def main(work_dir: str | None = None,
         recon_prompt: str = "",
         flow_prompt: str = "",
         vuln_prompt: str = "",
         verify_prompt: str = "",
         thinking: bool = False,
         force_surface: str = "",
         model: str = "",
         agent: str = "",
         stage: str = "",
         overwrite: bool = False,
         min_level: str = "standard"):
    work_path = Path(work_dir).resolve() if work_dir else \
                (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    config = load_config()
    max_workers = config.get("max_workers", 3)
    setup_logging()
    runner_log = setup_stage_log("runner")
    runner_log(f"Work directory: {work_path}")
    runner_log(f"Max workers:    {max_workers}")
    if recon_prompt:
        runner_log(f"  Recon extra:   {recon_prompt[:120]}")
    if flow_prompt:
        runner_log(f"  Flow extra:    {flow_prompt[:120]}")
    if vuln_prompt:
        runner_log(f"  Vuln extra:    {vuln_prompt[:120]}")
    if verify_prompt:
        runner_log(f"  Verify extra:  {verify_prompt[:120]}")
    if thinking:
        os.environ["OPENCODE_THINKING"] = "true"
        runner_log("  Thinking:      show process")
    if agent:
        os.environ["LLM_AGENT"] = agent
        runner_log(f"  Agent:         {agent}")
    if model:
        os.environ["LLM_MODEL"] = model
        runner_log(f"  Model:         {model}")
    runner_log("=" * 50)

    # Parse force-surface list and expand wildcards
    raw_list = [s.strip() for s in force_surface.split(",") if s.strip()] if force_surface else []
    force_list: list[str] = []
    if raw_list:
        analysis_dir = work_path / OUTPUT_PARENT / "analyzed_surfaces"
        existing = [f.name for f in analysis_dir.glob("*.md")] if analysis_dir.exists() else []
        for pat in raw_list:
            if "*" in pat:
                matched = fnmatch.filter(existing, pat)
                if not matched:
                    runner_log(f"  No surfaces match pattern: {pat}")
                force_list.extend(matched)
            else:
                force_list.append(pat)
        force_list = sorted(set(force_list))
        runner_log(f"  Force surfaces ({len(force_list)}): {force_list}")

        # Clean existing outputs for forced surfaces
        if stage == "recon":
            clean_stages: list[str] = []
            clean_batches = False
        elif stage:
            clean_stages = [stage]
            clean_batches = stage == "flow"
        else:
            clean_stages = ["flow", "plan", "vuln", "verify"]
            clean_batches = True

        for s_key in clean_stages:
            _force_clean_stage(work_path, s_key, force_list, runner_log)

        if clean_batches:
            meta_batches = work_path / OUTPUT_PARENT / "meta" / "batches"
            if meta_batches.exists():
                for name in force_list:
                    stem = name.replace(".md", "")
                    batch_dir = meta_batches / stem
                    if batch_dir.exists():
                        shutil.rmtree(batch_dir)
                        runner_log(f"  Removed: {batch_dir.relative_to(work_path)}")

    # try:
    stages = _resolve_stages(work_path, stage, force_list if raw_list else None,
                              config=config)
    if stage and len(stages) > 1:
        runner_log(f"  Auto-added dep stages: {[s for s in stages if s != stage]}")

    _STAGE_DISPATCH = {
        "recon":  (surface_discover.run,
                   {"work_dir": work_path, "extra_prompt": recon_prompt,
                    "force": stage == "recon", "thinking": thinking}),
        "flow":   (surface_analyze.run,
                   {"work_dir": work_path, "max_workers": max_workers,
                    "extra_prompt": flow_prompt,
                    "only_surfaces": force_list or None,
                    "thinking": thinking}),
        "plan":   (vuln_planner.run,
                   {"work_dir": work_path, "max_workers": max_workers,
                    "extra_prompt": vuln_prompt,
                    "thinking": thinking}),
        "vuln":   (vuln_analyze.run,
                   {"work_dir": work_path, "max_workers": max_workers,
                    "extra_prompt": vuln_prompt,
                    "force_list": force_list,
                    "thinking": thinking,
                    "min_level": min_level}),
        "verify": (review_vuln.run,
                   {"work_dir": work_path, "max_workers": max_workers,
                    "extra_prompt": verify_prompt,
                    "force_list": force_list,
                    "thinking": thinking}),
    }

    failed_stages: list[str] = []

    # Determine whether to use priority batching for vuln+verify
    plans_dir = work_path / OUTPUT_PARENT / "vuln_plans"
    analysis_dir = work_path / OUTPUT_PARENT / "analyzed_surfaces"
    plan_in_stages = "plan" in stages
    use_priority_batch = (
        not force_list
        and "vuln" in stages
        and "verify" in stages
        and (plans_dir.exists() or plan_in_stages)
    )

    # Stage loop (recon, flow, plan; skip vuln+verify if using priority batching)
    for s in stages:
        if use_priority_batch and s in ("vuln", "verify"):
            continue
        try:
            if (overwrite or stage) and not force_list:
                _prepare_stage(work_path, s, overwrite, runner_log)
            if s == "vuln" and not use_priority_batch:
                runner_log("\n=== 阶段4: 漏洞分析 ===")
            func, kwargs = _STAGE_DISPATCH.get(s)
            _run_stage(func, s, runner_log, **kwargs)
        except Exception as e:
            failed_stages.append(s)
            runner_log(f"  ✗ {_STAGE_NAMES.get(s, s)} 失败: {e}")

    # Priority-batched vuln+verify: per-surface analysis → immediate review
    if use_priority_batch and plans_dir.exists():
        runner_log("\n=== 阶段4: 漏洞分析 ===")
        import concurrent.futures as cf
        priority_groups = _group_surfaces_by_priority(analysis_dir, plans_dir)
        for label, stems in priority_groups:
            runner_log(f"\n  === [{label.upper()}] {len(stems)} surfaces ===")

            def process_one(stem):
                ctx = f"{label.upper()} — {stem}"
                vuln_analyze.run(
                    work_dir=work_path, max_workers=1,
                    extra_prompt=vuln_prompt, only_stems=[stem],
                    context=ctx, thinking=thinking,
                    min_level=min_level,
                )
                review_vuln.run(
                    work_dir=work_path, max_workers=1,
                    extra_prompt=verify_prompt, only_stems=[stem],
                    context=ctx, thinking=thinking,
                )

            with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
                for _ in pool.map(process_one, stems):
                    pass
    elif use_priority_batch and not plans_dir.exists():
        runner_log("\n=== 阶段4: 漏洞分析 ===")
        for s in ("vuln", "verify"):
            if s in stages:
                try:
                    func, kwargs = _STAGE_DISPATCH.get(s)
                    _run_stage(func, s, runner_log, **kwargs)
                except Exception as e:
                    failed_stages.append(s)
                    runner_log(f"  ✗ {_STAGE_NAMES.get(s, s)} 失败: {e}")
    runner_log()
    runner_log("=" * 50)
    runner_log("Pipeline complete.")
    surfaces = find_surface_files(work_path)
    vulns = find_vuln_files(work_path)
    runner_log(f"  Surface products: {len(surfaces)}")
    runner_log(f"  Vuln products:    {len(vulns)}")

    return {
        "stages": stages,
        "failed_stages": failed_stages,
        "surfaces": len(surfaces),
        "vulns": len(vulns),
    }


if __name__ == "__main__":
    main()
