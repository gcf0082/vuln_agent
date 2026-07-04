# -*- coding: utf-8 -*-
"""Pipeline orchestrator — thread pool with per-surface scheduling.

Flow:
  Phase 1: Discovery (per directory, concurrent)
  Phase 2: Per-surface: analyze → plan → high-risk vuln+review (concurrent)
  Phase 3: Per-surface: medium → low → standard vuln+review (concurrent)
"""

import concurrent.futures as cf
import os
from pathlib import Path

from . import surface_discover, surface_analyze, vuln_planner, vuln_analyze, review_vuln
from .workspace import OUTPUT_PARENT, setup_logging, setup_stage_log, read_surface_list, find_surface_files, find_vuln_files

_LEVEL_MAP = {"high": 0, "medium": 1, "low": 2, "standard": 3}


def _levels_for_min(min_level: str) -> list[str]:
    """Return levels to analyze in Phase 3 based on --min-level."""
    all_levels = ["medium", "low", "standard"]
    min_num = _LEVEL_MAP.get(min_level, 3)
    return [l for l in all_levels if _LEVEL_MAP[l] >= min_num]


def run(work_dirs: list[Path],
        max_workers: int = 5,
        recon_prompt: str = "",
        flow_prompt: str = "",
        vuln_prompt: str = "",
        verify_prompt: str = "",
        thinking: bool = False,
        model: str = "",
        agent: str = "",
        min_level: str = "standard",
        overwrite: bool = False):
    setup_logging()
    log = setup_stage_log("pipeline")

    if model:
        os.environ["LLM_MODEL"] = model
    if agent:
        os.environ["LLM_AGENT"] = agent
    if thinking:
        os.environ["OPENCODE_THINKING"] = "true"

    log(f"Targets: {len(work_dirs)} directory(s), workers={max_workers}, min_level={min_level}")

    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        # ── Phase 1: Discovery ──
        log("Phase 1: Surface discovery")
        all_surfaces: list[tuple[Path, str]] = []
        discovery_futures = {}

        for d in work_dirs:
            prefix = f"[{d.name}]"
            f = pool.submit(_discover_one, d, recon_prompt, overwrite, thinking, prefix)
            discovery_futures[f] = d

        for f in cf.as_completed(discovery_futures):
            d = discovery_futures[f]
            surfaces = f.result()
            for sname in surfaces:
                all_surfaces.append((d, sname))

        if not all_surfaces:
            log("No surfaces discovered. Done.")
            return

        log(f"Phase 1 complete: {len(all_surfaces)} surfaces across {len(work_dirs)} directory(s)")

        # ── Phase 2: Analyze → Plan → High-risk vuln+review ──
        log("Phase 2: Analysis → Planning → High-risk vuln+review")
        phase2_futures = []

        for d, sname in all_surfaces:
            f = pool.submit(_phase2_one, d, sname,
                            flow_prompt, vuln_prompt, verify_prompt,
                            thinking, prefix=f"[{d.name}/{sname}]")
            phase2_futures.append(f)

        for f in cf.as_completed(phase2_futures):
            f.result()  # Raise if failed

        log("Phase 2 complete: all surfaces analyzed, planned, high-risk done")

        # ── Phase 3: Medium → Low → Standard vuln+review ──
        phase3_levels = _levels_for_min(min_level)
        if phase3_levels:
            log(f"Phase 3: {', '.join(l.upper() for l in phase3_levels)} vuln+review")
            phase3_futures = []

            for d, sname in all_surfaces:
                f = pool.submit(_phase3_one, d, sname, phase3_levels,
                                vuln_prompt, verify_prompt, thinking,
                                prefix=f"[{d.name}/{sname}]")
                phase3_futures.append(f)

            for f in cf.as_completed(phase3_futures):
                f.result()

            log("Phase 3 complete")

    # Summary
    total_surfaces = sum(len(find_surface_files(d)) for d in work_dirs)
    total_vulns = sum(len(find_vuln_files(d)) for d in work_dirs)
    log(f"Pipeline complete: {total_surfaces} surfaces, {total_vulns} vuln files")


def _discover_one(work_dir: Path, recon_prompt: str, overwrite: bool,
                  thinking: bool, prefix: str) -> list[str]:
    """Run discovery for one directory, return list of surface filenames."""
    surface_discover.run(work_dir, extra_prompt=recon_prompt,
                         force=overwrite, thinking=thinking, prefix=prefix)
    items = read_surface_list(work_dir)
    return [item.filename for item in items]


def _phase2_one(work_dir: Path, surface_file: str,
                flow_prompt: str, vuln_prompt: str, verify_prompt: str,
                thinking: bool, prefix: str):
    """Analyze → plan → high-risk vuln+review for one surface."""
    # Surface analysis
    surface_analyze.run(work_dir, max_workers=1,
                        only_surfaces=[surface_file],
                        extra_prompt=flow_prompt,
                        thinking=thinking, prefix=prefix)

    # Vuln planning
    vuln_planner.run(work_dir, max_workers=1,
                     extra_prompt=vuln_prompt,
                     thinking=thinking,
                     only_stems=[surface_file.replace(".md", "")],
                     prefix=prefix)

    # High-risk vuln analysis + review (coupled)
    vuln_analyze.run(work_dir, max_workers=1,
                     extra_prompt=vuln_prompt,
                     only_stems=[surface_file.replace(".md", "")],
                     thinking=thinking,
                     min_level="high", risk_first=True,
                     prefix=prefix, force=False)
    review_vuln.run(work_dir, max_workers=1,
                    extra_prompt=verify_prompt,
                    only_stems=[surface_file.replace(".md", "")],
                    thinking=thinking, prefix=prefix)


def _phase3_one(work_dir: Path, surface_file: str,
                levels: list[str],
                vuln_prompt: str, verify_prompt: str,
                thinking: bool, prefix: str):
    """Medium → low → standard vuln+review for one surface."""
    stem = surface_file.replace(".md", "")
    for level in levels:
        vuln_analyze.run(work_dir, max_workers=1,
                         extra_prompt=vuln_prompt,
                         only_stems=[stem],
                         thinking=thinking,
                         min_level=level, risk_first=True,
                         prefix=prefix, force=True)
        review_vuln.run(work_dir, max_workers=1,
                        extra_prompt=verify_prompt,
                        only_stems=[stem],
                        thinking=thinking, prefix=prefix)
