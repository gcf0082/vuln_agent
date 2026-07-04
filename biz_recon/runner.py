#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline runner — unified entry point for single and multi-directory modes."""

import os
import sys
from pathlib import Path

from . import pipeline
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
         verify_prompt: str = "",
         thinking: bool = False,
         force_surface: str = "",
         model: str = "",
         agent: str = "",
         stage: str = "",
         overwrite: bool = False,
         min_level: str = "standard",
         multi: bool = False):
    work_path = Path(work_dir).resolve() if work_dir else \
                (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    config = load_config()
    max_workers = config.get("max_workers", 5)

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
    if min_level != "standard":
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

    pipeline.run(
        work_dirs=work_dirs,
        max_workers=max_workers,
        recon_prompt=recon_prompt,
        flow_prompt=flow_prompt,
        vuln_prompt=vuln_prompt,
        verify_prompt=verify_prompt,
        thinking=thinking,
        model=model,
        agent=agent,
        min_level=min_level,
        overwrite=overwrite,
    )

    return {"surfaces": 0, "vulns": 0}


if __name__ == "__main__":
    main()
