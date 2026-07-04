#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-target runner — iterate subdirectories, run pipeline, archive outputs."""

import shutil
from pathlib import Path

from . import runner
from .workspace import OUTPUT_PARENT

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


def _move(src: Path, dst: Path):
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.move(str(src), str(dst))


def run(parent_dir: str,
        recon_prompt: str = "",
        flow_prompt: str = "",
        vuln_prompt: str = "",
        verify_prompt: str = "",
        thinking: bool = False,
        model: str = "",
        agent: str = "",
        stage: str = "",
        overwrite: bool = False,
        min_level: str = "standard"):
    parent = Path(parent_dir).resolve()
    if not parent.is_dir():
        print(f"Error: not a directory: {parent}")
        return

    subdirs = list_subdirs(parent)
    if not subdirs:
        print("No subdirectories found to analyze.")
        return

    print(f"\n{'=' * 50}")
    print(f"Multi-target analysis: {parent} ({len(subdirs)} subdirectories)")
    if stage:
        print(f"  Stage: {stage}")
    print(f"{'=' * 50}")

    for i, subdir in enumerate(subdirs):
        name = subdir.name
        print(f"\n--- [{i + 1}/{len(subdirs)}] {name} ---")

        parent_arch = parent / OUTPUT_PARENT / name
        subdir_out = subdir / OUTPUT_PARENT

        # Restore previous output from parent archive for resume
        _move(parent_arch, subdir_out)

        try:
            stats = runner.main(
                work_dir=str(subdir),
                recon_prompt=recon_prompt,
                flow_prompt=flow_prompt,
                vuln_prompt=vuln_prompt,
                verify_prompt=verify_prompt,
                thinking=thinking,
                model=model,
                agent=agent,
                stage=stage,
                overwrite=overwrite,
                min_level=min_level,
            )
            if stats.get("failed_stages"):
                print(f"  ✗ Failed stages: {', '.join(stats['failed_stages'])}")
        except Exception as e:
            print(f"  ✗ Error: {e}")

        # Archive to parent directory
        _move(subdir_out, parent_arch)
        print(f"  ✓ Output archived to .vuln_agent_output/{name}/")

    print(f"\n{'=' * 50}")
    print("Multi-target analysis complete.")
    print(f"{'=' * 50}")
