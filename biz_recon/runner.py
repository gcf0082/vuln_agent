#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline runner — executes all stages in sequence."""

import fnmatch
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from . import surface_discover, surface_analyze, vuln_analyze, review_vuln
from .workspace import OUTPUT_PARENT, setup_logging, setup_stage_log, find_surface_files, find_vuln_files
from db import import_stage


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


_STAGE_NAMES = {
    "recon":  "暴露面识别",
    "flow":   "业务流分析",
    "vuln":   "漏洞分析",
    "verify": "二次审查",
}

_STAGE_DIRS = {
    "recon":  "discovered_surfaces",
    "flow":   "analyzed_surfaces",
    "vuln":   "vuln_findings",
    "verify": "vuln_reviews",
}

_STAGE_MARKERS = {
    "recon": ".surface_discover_done",
}

_STAGE_REQUIRES = {
    "flow":   "discovered_surfaces",
    "vuln":   "analyzed_surfaces",
    "verify": "vuln_findings",
}


STAGE_ORDER = ["recon", "flow", "vuln", "verify"]


def _resolve_stages(work_path: Path, stage: str, force_list: list[str] | None = None) -> list[str]:
    """Return ordered stage list, auto-adding missing prerequisites."""
    if not stage:
        return list(STAGE_ORDER)

    result = []
    for s in STAGE_ORDER:
        if s == stage:
            result.append(s)
            break

        output_dir = work_path / OUTPUT_PARENT / _STAGE_DIRS[s]

        if s == "recon":
            need = not (output_dir.exists() and bool(list(output_dir.glob("*.md"))))

        elif force_list:
            if s == "flow":
                existing = {f.name for f in output_dir.glob("*.md")} if output_dir.exists() else set()
                need = not all(n in existing for n in force_list)
            else:
                existing = [f.name for f in output_dir.glob("*.md")] if output_dir.exists() else []
                stems = [n.replace(".md", "") for n in force_list]
                need = not all(any(s in name for name in existing) for s in stems)
        else:
            need = not (output_dir.exists() and bool(list(output_dir.glob("*.md"))))

        if need:
            result.append(s)

    return result


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


def _run_stage(stage_func, db_path: str | None, stage_key: str,
               runner_log, work_path: Path, stage_result_key: str, **kwargs):
    """Run a single stage, import to DB if in project mode."""
    stage_func(**kwargs)
    if db_path:
        import_stage(db_path, stage_key, str(work_path / OUTPUT_PARENT / stage_result_key))
    runner_log(f"  ✓ {_STAGE_NAMES.get(stage_key, stage_key)}")


def main(work_dir: str | None = None,
         project: str = "",
         recon_prompt: str = "",
         flow_prompt: str = "",
         vuln_prompt: str = "",
         verify_prompt: str = "",
         thinking: bool = False,
         force_surface: str = "",
         model: str = "",
         agent: str = "",
         stage: str = "",
         overwrite: bool = False):
    work_path = Path(work_dir).resolve() if work_dir else \
                (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    config = load_config()
    max_workers = config.get("max_workers", 3)
    # Project mode setup
    if project:
        from db import get_project_path
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

        # Determine which dirs to clean based on --stage (only delete what's needed)
        if stage == "recon":
            force_dirs: tuple[str, ...] = ()
            clean_batches = False
        elif stage:
            force_dirs = {"flow": ("analyzed_surfaces",),
                          "vuln": ("vuln_findings",),
                          "verify": ("vuln_reviews",)}[stage]
            clean_batches = stage == "flow"
        else:
            force_dirs = ("analyzed_surfaces", "vuln_findings", "vuln_reviews")
            clean_batches = True

        for dirname in force_dirs:
            d = work_path / OUTPUT_PARENT / dirname
            for name in force_list:
                stem = name.replace(".md", "")
                pattern = f"{stem}*" if dirname == "analyzed_surfaces" else f"*{stem}*"
                for f in d.glob(pattern):
                    if f.is_file():
                        f.unlink()
                        runner_log(f"  Removed: {d.name}/{f.name}")

        if clean_batches:
            meta_batches = work_path / OUTPUT_PARENT / "meta" / "batches"
            if meta_batches.exists():
                for name in force_list:
                    stem = name.replace(".md", "")
                    batch_dir = meta_batches / stem
                    if batch_dir.exists():
                        shutil.rmtree(batch_dir)
                        runner_log(f"  Removed: {batch_dir.relative_to(work_path)}")

    try:
        stages = _resolve_stages(work_path, stage, force_list if raw_list else None)
        if stage and len(stages) > 1:
            runner_log(f"  Auto-added dep stages: {[s for s in stages if s != stage]}")

        for s in stages:
            if (overwrite or stage) and not force_list:
                _prepare_stage(work_path, s, overwrite, runner_log)
            if s == "recon":
                _run_stage(surface_discover.run, db_path, "discovered_surfaces",
                           runner_log, work_path, "discovered_surfaces",
                           work_dir=work_path, extra_prompt=recon_prompt,
                                            force=(stage == "recon"))
            elif s == "flow":
                _run_stage(surface_analyze.run, db_path, "analyzed_surfaces",
                           runner_log, work_path, "analyzed_surfaces",
                           work_dir=work_path, max_workers=max_workers,
                           extra_prompt=flow_prompt,
                           only_surfaces=force_list or None)
            elif s == "vuln":
                _run_stage(vuln_analyze.run, db_path, "vuln_findings",
                           runner_log, work_path, "vuln_findings",
                           work_dir=work_path, max_workers=max_workers,
                           extra_prompt=vuln_prompt, force_list=force_list)
            elif s == "verify":
                _run_stage(review_vuln.run, db_path, "vuln_reviews",
                           runner_log, work_path, "vuln_reviews",
                           work_dir=work_path, max_workers=max_workers,
                           extra_prompt=verify_prompt, force_list=force_list)
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
