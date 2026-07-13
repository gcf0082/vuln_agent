#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline runner — unified entry point for single and multi-directory modes."""

import os
import sys
from pathlib import Path

from . import pipeline
from .pipeline import was_interrupted
from . import surface_discover, surface_analyze, vuln_analyze
from .workspace import OUTPUT_PARENT, setup_logging, setup_stage_log

SKIP_DIRS = frozenset({
    "node_modules", "__pycache__", "venv",
    "dist", "build", "target",
})


def list_subdirs(parent: Path) -> list[Path]:
    result: list[Path] = []
    for child in sorted(parent.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            continue
        if child.name in SKIP_DIRS:
            continue
        result.append(child)
    return result


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
         recon_prompt: str = "",
         flow_prompt: str = "",
         vuln_prompt: str = "",
         thinking: bool = False,
         force_surface: str = "",
         model: str = "",
         agent: str = "",
         stage: str = "",
         overwrite: bool = False,
         min_level: str = "low",
         multi: bool = False):
    work_path = Path(work_dir).resolve() if work_dir else \
                (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    config = load_config()
    max_workers = config.get("max_workers", 5)
    vuln_workers = config.get("vuln_workers", 5)
    os.environ["TIMEOUT_SURFACE_DISCOVER"] = str(config.get("timeout_surface_discover", 120))
    os.environ["TIMEOUT_DEFAULT"] = str(config.get("timeout_default", 60))

    setup_logging()
    runner_log = setup_stage_log("runner")
    runner_log(f"Work directory: {work_path}")
    runner_log(f"Max workers:    {max_workers}")
    runner_log(f"Vuln workers:   {vuln_workers}")
    if recon_prompt:
        runner_log(f"  Recon extra:   {recon_prompt[:120]}")
    if flow_prompt:
        runner_log(f"  Flow extra:    {flow_prompt[:120]}")
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
    if min_level != "low":
        runner_log(f"  Min level:     {min_level}")
    runner_log("=" * 50)

    if multi:
        work_dirs = list_subdirs(work_path)
        if not work_dirs:
            runner_log("No subdirectories found.")
            return {"surfaces": 0, "vulns": 0}
        runner_log(f"Multi-target: {len(work_dirs)} subdirectories")
    else:
        work_dirs = [work_path]

    if stage:
        runner_log(f"Single stage: {stage}")
        for d in work_dirs:
            if stage == "recon":
                if force_surface:
                    runner_log("  --force-surface ignored for recon stage (discovery is global)")
                surface_discover.run(d, extra_prompt=recon_prompt, force=overwrite, thinking=thinking)
            elif stage == "flow":
                matched_files = pipeline._parse_force_surface(force_surface, d) if force_surface else None
                if matched_files == []:
                    runner_log(f"  No surfaces matched: {force_surface}")
                    continue
                if overwrite and matched_files:
                    for sname in matched_files:
                        pipeline._delete_surface_outputs(d, sname, from_stage="flow")
                surface_analyze.run(d, max_workers=max_workers,
                                    only_surfaces=matched_files,
                                    extra_prompt=flow_prompt, thinking=thinking)
                from . import vuln_planner
                matched_stems = [f.replace(".md", "") for f in matched_files] if matched_files else None
                vuln_planner.run(d, max_workers=max_workers,
                                 extra_prompt=vuln_prompt, thinking=thinking,
                                 only_stems=matched_stems)
            elif stage == "postprocess":
                from . import vuln_postprocess
                vuln_postprocess.run(d, thinking=thinking, prefix=f"[{d.name}]")
            elif stage == "vuln":
                matched_stems = None
                if force_surface:
                    matched_files = pipeline._parse_force_surface(force_surface, d)
                    if not matched_files:
                        runner_log(f"  No surfaces matched: {force_surface}")
                        continue
                    matched_stems = [f.replace(".md", "") for f in matched_files]
                if overwrite and matched_stems:
                    for sname in matched_files:
                        pipeline._delete_surface_outputs(d, sname, from_stage="vuln")
                from . import vuln_planner
                vuln_planner.run(d, max_workers=max_workers,
                                 extra_prompt=vuln_prompt, thinking=thinking,
                                 only_stems=matched_stems)
                vuln_analyze.run(d, max_workers=max_workers,
                                 extra_prompt=vuln_prompt, thinking=thinking,
                                 min_level=min_level,
                                 only_stems=matched_stems)
                from . import review_vuln
                review_vuln.run(d, max_workers=max_workers,
                                extra_prompt=vuln_prompt, thinking=thinking,
                                only_stems=matched_stems)
    else:
        pipeline.run(
            work_dirs=work_dirs,
            max_workers=max_workers,
            vuln_workers=vuln_workers,
            recon_prompt=recon_prompt,
            flow_prompt=flow_prompt,
            vuln_prompt=vuln_prompt,
            thinking=thinking,
            model=model,
            agent=agent,
            min_level=min_level,
            overwrite=overwrite,
            force_surface=force_surface,
        )

        if not was_interrupted():
            for d in work_dirs:
                try:
                    from report import generate_report
                    ok, msg = generate_report(d)
                    if ok:
                        runner_log(f"Report: {msg}")
                    else:
                        runner_log(f"Report skipped for {d.name}: {msg}")
                except Exception as e:
                    runner_log(f"Report failed for {d.name}: {e}")

            try:
                from collect import collect_target, update_targets_js
                collected = []
                for d in work_dirs:
                    try:
                        entry = collect_target(d)
                        collected.append(entry)
                    except Exception as e:
                        runner_log(f"Collect skipped for {d.name}: {e}")
                if collected:
                    update_targets_js(collected)
                    runner_log(f"Dashboard collected: {len(collected)} target(s)")
            except Exception as e:
                runner_log(f"Auto-collect failed: {e}")

    return {"surfaces": 0, "vulns": 0}


if __name__ == "__main__":
    main()
