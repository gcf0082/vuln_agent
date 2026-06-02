#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline runner — executes all stages in sequence."""

import fnmatch
import os
import shutil
import sys
from pathlib import Path

from . import collect, analyze, vuln_task_plan, vuln, reanalyze
from .workspace import OUTPUT_PARENT, setup_logging, log, find_surface_files, find_vuln_files


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


def main(work_dir: str | None = None,
         collect_prompt: str = "",
         vuln_prompt: str = "",
         thinking: bool = False,
         force_surface: str = "",
         model: str = "",
         agent: str = ""):
    work_path = Path(work_dir).resolve() if work_dir else \
                (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    config = load_config()
    max_workers = config.get("max_workers", 3)
    setup_logging(Path.cwd())
    log(f"Work directory: {work_path}")
    log(f"Max workers:    {max_workers}")
    if collect_prompt:
        log(f"  Collect extra: {collect_prompt[:120]}")
    if vuln_prompt:
        log(f"  Vuln extra:    {vuln_prompt[:120]}")
    if thinking:
        os.environ["OPENCODE_THINKING"] = "true"
        log("  Thinking:      show process")
    if agent:
        os.environ["LLM_AGENT"] = agent
        log(f"  Agent:         {agent}")
    if model:
        os.environ["LLM_MODEL"] = model
        log(f"  Model:         {model}")
    log("=" * 50)

    # Parse force-surface list and expand wildcards
    raw_list = [s.strip() for s in force_surface.split(",") if s.strip()] if force_surface else []
    force_list: list[str] = []
    if raw_list:
        analysis_dir = work_path / OUTPUT_PARENT / "analysis"
        existing = [f.name for f in analysis_dir.glob("*.md")] if analysis_dir.exists() else []
        for pat in raw_list:
            if "*" in pat:
                matched = fnmatch.filter(existing, pat)
                if not matched:
                    log(f"  No surfaces match pattern: {pat}")
                force_list.extend(matched)
            else:
                force_list.append(pat)
        force_list = sorted(set(force_list))
        log(f"  Force surfaces ({len(force_list)}): {force_list}")

        # Delete existing products for these surfaces
        vuln_dir = work_path / OUTPUT_PARENT / "vulnerabilities"
        review_dir = work_path / OUTPUT_PARENT / "vuln_review"
        for name in force_list:
            stem = name.replace(".md", "")
            for d in (vuln_dir, review_dir):
                for f in d.glob(f"*{stem}*"):
                    if f.is_file():
                        f.unlink()
                        log(f"  Removed: {f.relative_to(work_path)}")

    try:
        collect.run(work_path, extra_prompt=collect_prompt)
        analyze.run(work_path, max_workers)
        vuln_task_plan.run(work_path, max_workers)
        vuln.run(work_path, max_workers, extra_prompt=vuln_prompt, force_list=force_list)
        reanalyze.run(work_path, max_workers, extra_prompt=vuln_prompt, force_list=force_list)
    except RuntimeError as e:
        log(f"Pipeline aborted: {e}")
        sys.exit(1)

    log()
    log("=" * 50)
    log("Pipeline complete.")
    surfaces = find_surface_files(work_path)
    vulns = find_vuln_files(work_path)
    log(f"  Surface products: {len(surfaces)}")
    log(f"  Vuln products:    {len(vulns)}")


if __name__ == "__main__":
    main()
