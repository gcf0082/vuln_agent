#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline runner — executes all stages in sequence."""

import fnmatch
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from . import collect, analyze, vuln_task_plan, vuln, reanalyze
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


def main(work_dir: str | None = None,
         project: str = "",
         collect_prompt: str = "",
         analyze_prompt: str = "",
         vuln_prompt: str = "",
         thinking: bool = False,
         force_surface: str = "",
         model: str = "",
         agent: str = ""):
    work_path = Path(work_dir).resolve() if work_dir else \
                (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    config = load_config()
    max_workers = config.get("max_workers", 3)
    # Project mode setup
    if project:
        from db import get_project_path, import_stage
        proj_path = get_project_path(project)
        os.environ["OPENCODE_WORK_DIR"] = str(proj_path)
        db_path = str(proj_path / "results.db")
        setup_logging(Path.cwd(), log_base=proj_path)
    else:
        db_path = None
        setup_logging(Path.cwd())
    runner_log = setup_stage_log("runner")
    runner_log(f"Work directory: {work_path}")
    runner_log(f"Max workers:    {max_workers}")
    if collect_prompt:
        runner_log(f"  Collect extra: {collect_prompt[:120]}")
    if analyze_prompt:
        runner_log(f"  Analyze extra: {analyze_prompt[:120]}")
    if vuln_prompt:
        runner_log(f"  Vuln extra:    {vuln_prompt[:120]}")
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
        analysis_dir = work_path / OUTPUT_PARENT / "analysis"
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

        # Delete existing products for these surfaces
        for dirname in ("vuln_tasks", "vulnerabilities", "vuln_review"):
            d = work_path / OUTPUT_PARENT / dirname
            for name in force_list:
                stem = name.replace(".md", "")
                for f in d.glob(f"*{stem}*"):
                    if f.is_file():
                        f.unlink()
                        runner_log(f"  Removed: {d.name}/{f.name}")

        # Also clean up batch intermediates
        meta_batches = work_path / OUTPUT_PARENT / "meta" / "batches"
        if meta_batches.exists():
            for name in force_list:
                stem = name.replace(".md", "")
                batch_dir = meta_batches / stem
                if batch_dir.exists():
                    shutil.rmtree(batch_dir)
                    runner_log(f"  Removed: {batch_dir.relative_to(work_path)}")

    try:
        collect.run(work_path, extra_prompt=collect_prompt)
        if db_path:
            import_stage(db_path, "surfaces", str(work_path / OUTPUT_PARENT / "surfaces"))

        analyze.run(work_path, max_workers, extra_prompt=analyze_prompt, only_surfaces=force_list or None)
        if db_path:
            import_stage(db_path, "analysis", str(work_path / OUTPUT_PARENT / "analysis"))

        vuln_task_plan.run(work_path, max_workers, force_list=force_list or None)
        if db_path:
            import_stage(db_path, "vuln_tasks", str(work_path / OUTPUT_PARENT / "vuln_tasks"))

        vuln.run(work_path, max_workers, extra_prompt=vuln_prompt, force_list=force_list)
        if db_path:
            import_stage(db_path, "vulnerabilities", str(work_path / OUTPUT_PARENT / "vulnerabilities"))

        reanalyze.run(work_path, max_workers, extra_prompt=vuln_prompt, force_list=force_list)
        if db_path:
            import_stage(db_path, "vuln_review", str(work_path / OUTPUT_PARENT / "vuln_review"))
    except RuntimeError as e:
        if project and db_path:
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE projects SET status=? WHERE name=?", ("error", project))
            conn.commit()
            conn.close()
        runner_log(f"Pipeline aborted: {e}")
        sys.exit(1)

    # After success
    if project and db_path:
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE projects SET status=? WHERE name=?", ("done", project))
        conn.commit()
        conn.close()

    runner_log()
    runner_log("=" * 50)
    runner_log("Pipeline complete.")
    surfaces = find_surface_files(work_path)
    vulns = find_vuln_files(work_path)
    runner_log(f"  Surface products: {len(surfaces)}")
    runner_log(f"  Vuln products:    {len(vulns)}")


if __name__ == "__main__":
    main()
