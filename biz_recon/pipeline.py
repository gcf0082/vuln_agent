# -*- coding: utf-8 -*-
"""Pipeline orchestrator — thread pool with per-surface scheduling.

Flow:
  Phase 1: Discovery (per directory, concurrent)
  Phase 2: Per-surface: analyze → plan → high-risk vuln+review (concurrent)
  Phase 3: Per-surface: medium → low vuln+review (concurrent)
"""

import concurrent.futures as cf
import fnmatch
import os
import shutil
import signal
from pathlib import Path

from . import surface_discover, surface_analyze, surface_split, surface_rank, vuln_planner, vuln_analyze, review_vuln, vuln_postprocess
from .workspace import OUTPUT_PARENT, setup_logging, setup_stage_log, read_surface_list, find_surface_files, find_vuln_files, record_failure, get_all_failures, reset_failures

_LEVEL_MAP = {"high": 0, "medium": 1, "low": 2}
_INTERRUPTED = False


def _init_signal_handler():
    global _INTERRUPTED
    _INTERRUPTED = False
    signal.signal(signal.SIGINT, _signal_handler)


def _signal_handler(sig, frame):
    global _INTERRUPTED
    if _INTERRUPTED:
        print("\nSecond interrupt — force exit.", flush=True)
        os._exit(1)
    _INTERRUPTED = True
    print("\nInterrupt received — finishing running tasks (press Ctrl+C again to force exit)...", flush=True)


def was_interrupted() -> bool:
    """Check whether SIGINT was received. Safe to import from other modules."""
    return _INTERRUPTED


def _parse_force_surface(pattern: str, work_dir: Path) -> list[str]:
    """解析逗号分隔的模式（支持 * 通配），返回匹配的 surface 文件名列表。"""
    surfaces_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
    if not surfaces_dir.exists():
        return []
    patterns = [p.strip() for p in pattern.split(",") if p.strip()]
    matched = []
    for f in sorted(surfaces_dir.glob("*.md")):
        if any(fnmatch.fnmatch(f.name, p) or fnmatch.fnmatch(f.stem, p) for p in patterns):
            matched.append(f.name)
    return matched


def _delete_surface_outputs(work_dir: Path, filename: str,
                            from_stage: str = "flow"):
    """删除指定 surface 从 from_stage 开始的全部产物。

    from_stage: "flow" = 业务流 onwards, "vuln" = 仅漏洞阶段。
    """
    stem = filename.replace(".md", "")
    base = work_dir / OUTPUT_PARENT

    if from_stage == "flow":
        (base / "analyzed_surfaces" / filename).unlink(missing_ok=True)
        plan_dir = base / "vuln_plans" / stem
        if plan_dir.exists():
            shutil.rmtree(plan_dir)

    for dir_name in ["vuln_findings", "vuln_reviews"]:
        d = base / dir_name
        if d.exists():
            for f in d.glob(f"*{stem}*.md"):
                f.unlink()

    (base / ".phase3_done").unlink(missing_ok=True)


def _levels_for_min(min_level: str) -> list[str]:
    """Return levels to analyze in Phase 3 based on --min-level.
    
    Phase 2 always does high. Phase 3 does levels <= min_level (excluding high).
    --min-level high → Phase 3: none
    --min-level medium → Phase 3: medium
    --min-level low → Phase 3: medium, low
    """
    all_levels = ["medium", "low"]
    min_num = _LEVEL_MAP.get(min_level, 2)
    return [l for l in all_levels if _LEVEL_MAP[l] <= min_num]


def run(work_dirs: list[Path],
        max_workers: int = 5,
        vuln_workers: int = 5,
        recon_prompt: str = "",
        flow_prompt: str = "",
        vuln_prompt: str = "",
        verify_prompt: str = "",
        thinking: bool = False,
        model: str = "",
        agent: str = "",
        min_level: str = "low",
        overwrite: bool = False,
        force_surface: str = "",
        skip_novuln_review: bool = False):
    setup_logging()
    log = setup_stage_log("pipeline")
    reset_failures()
    _init_signal_handler()

    if model:
        os.environ["LLM_MODEL"] = model
    if agent:
        os.environ["LLM_AGENT"] = agent
    if thinking:
        os.environ["OPENCODE_THINKING"] = "true"

    log(f"Targets: {len(work_dirs)} directory(s), workers={max_workers}, vuln_workers={vuln_workers}, min_level={min_level}")

    pool = cf.ThreadPoolExecutor(max_workers=max_workers)
    vpool = None
    try:
        # ── Phase 1: Discovery (skip if force_surface) ──
        all_surfaces: list[tuple[Path, str]] = []

        if force_surface:
            log(f"Force-surface mode: {force_surface}")
            for d in work_dirs:
                matched = _parse_force_surface(force_surface, d)
                if overwrite:
                    for sname in matched:
                        _delete_surface_outputs(d, sname, from_stage="flow")
                for sname in matched:
                    all_surfaces.append((d, sname))
        else:
            log("Phase 1: Surface discovery")
            discovery_futures = {}

            for d in work_dirs:
                prefix = f"[{d.name}]"
                f = pool.submit(_discover_one, d, recon_prompt, overwrite, thinking, prefix)
                discovery_futures[f] = d

            for f in cf.as_completed(discovery_futures):
                if _INTERRUPTED:
                    for remaining in discovery_futures:
                        remaining.cancel()
                    break
                d = discovery_futures[f]
                try:
                    surfaces = f.result()
                    for sname in surfaces:
                        all_surfaces.append((d, sname))
                except Exception as e:
                    log(f"[{d.name}] Discovery failed: {e}")
                    record_failure(f"Phase 1 Discovery [{d.name}]: {e}")

        if not all_surfaces or _INTERRUPTED:
            log("Interrupted after Phase 1" if _INTERRUPTED else "No surfaces discovered. Done.")
            return

        log(f"Phase 1 complete: {len(all_surfaces)} surfaces across {len(work_dirs)} directory(s)")

        # ── Phase 1.5: Surface split verification ──
        # 每个 discovered_surfaces 文件应只含一个攻击面；含多个则拆成多个单文件。
        # 对 CLI 不可见、无独立标记：已有 analyzed_surfaces/<同名> 的视为已流过拆解，跳过。
        if not force_surface and not _INTERRUPTED:
            log("Phase 1.5: Surface split verification")
            for d in work_dirs:
                try:
                    surface_split.run(d, max_workers=max_workers, thinking=thinking, prefix=f"[{d.name}]")
                except Exception as e:
                    log(f"[{d.name}] Surface split failed: {e}")
                    record_failure(f"Phase 1.5 Split [{d.name}]: {e}")
            # 拆解可能增删 discovered_surfaces 文件，刷新 all_surfaces
            all_surfaces = [(d, it.filename) for d in work_dirs for it in read_surface_list(d)]
            log(f"Phase 1.5 complete: {len(all_surfaces)} surfaces after split")

        # ── Phase 1.6: Surface priority ranking ──
        # 对 discovered_surfaces 全局优先级排序 -> meta/surface-priority.jsonl
        # 下游 load_ranking 分发：JSONL 序优先 + 不在 JSONL 的末尾分发。JSONL 已存在即复用。
        if not force_surface and not _INTERRUPTED:
            log("Phase 1.6: Surface priority ranking")
            for d in work_dirs:
                try:
                    surface_rank.run(d, thinking=thinking, prefix=f"[{d.name}]")
                except Exception as e:
                    log(f"[{d.name}] Surface ranking failed: {e}")
                    record_failure(f"Phase 1.6 Rank [{d.name}]: {e}")
            # 按优先级重排 all_surfaces：JSONL 序 + 漏排末尾
            all_surfaces = [(d, fname) for d in work_dirs for fname in surface_rank.load_ranking(d)]
            log(f"Phase 1.6 complete: {len(all_surfaces)} surfaces ranked for analysis")

        # ── Phase 2: Analyze → Plan → High-risk vuln+review ──
        log("Phase 2: Analysis → Planning → High-risk vuln+review")

        vpool = cf.ThreadPoolExecutor(max_workers=vuln_workers)
        phase2a_futures: dict[cf.Future, tuple[Path, str]] = {}
        for d, sname in all_surfaces:
            f = pool.submit(_phase2_analyze_plan, d, sname,
                            flow_prompt, vuln_prompt, thinking,
                            prefix=f"[{d.name}/{sname}]")
            phase2a_futures[f] = (d, sname)

        # As each analyze+plan completes, submit high-risk vuln+review immediately
        vuln_futures: dict[cf.Future, tuple[Path, str]] = {}
        for f in cf.as_completed(phase2a_futures):
            if _INTERRUPTED:
                break
            d, sname = phase2a_futures[f]
            try:
                f.result()
            except Exception as e:
                log(f"[{d.name}/{sname}] Analyze+Plan failed: {e}")
                record_failure(f"Phase 2 Analyze+Plan [{d.name}/{sname}]: {e}")
                continue

            stem = sname.replace(".md", "")
            plan_dir = d / OUTPUT_PARENT / "vuln_plans" / stem
            if plan_dir.exists() and list(plan_dir.glob("high-risk-*.md")):
                vf = vpool.submit(_phase2_vuln_review, d, sname,
                                  vuln_prompt, verify_prompt, thinking,
                                  skip_novuln_review,
                                  prefix=f"[{d.name}/{sname}]")
                vuln_futures[vf] = (d, sname)

        log("Phase 2a complete: all surfaces analyzed and planned")

        for vf in cf.as_completed(vuln_futures):
            if _INTERRUPTED:
                for remaining in vuln_futures:
                    remaining.cancel()
                break
            d, sname = vuln_futures[vf]
            try:
                vf.result()
            except Exception as e:
                log(f"[{d.name}/{sname}] Vuln+Review failed: {e}")
                record_failure(f"Phase 2 Vuln+Review [{d.name}/{sname}]: {e}")

        log("Phase 2b complete: high-risk vuln+review done")

        if not _INTERRUPTED:
            # ── Phase 3: Medium → Low vuln+review ──
            phase3_levels = _levels_for_min(min_level)
            phase3_marker = work_dirs[0] / OUTPUT_PARENT / ".phase3_done"
            if phase3_levels and not phase3_marker.exists():
                log(f"Phase 3: {', '.join(l.upper() for l in phase3_levels)} vuln+review")
                phase3_futures: dict[cf.Future, tuple[Path, str]] = {}

                for d, sname in all_surfaces:
                    if _INTERRUPTED:
                        break
                    f = vpool.submit(_phase3_one, d, sname, phase3_levels,
                                     vuln_prompt, verify_prompt, thinking,
                                     skip_novuln_review,
                                     prefix=f"[{d.name}/{sname}]")
                    phase3_futures[f] = (d, sname)

                for f in cf.as_completed(phase3_futures):
                    if _INTERRUPTED:
                        for remaining in phase3_futures:
                            remaining.cancel()
                        break
                    d, sname = phase3_futures[f]
                    try:
                        f.result()
                    except Exception as e:
                        log(f"[{d.name}/{sname}] Phase 3 failed: {e}")
                        record_failure(f"Phase 3 Vuln+Review [{d.name}/{sname}]: {e}")

                if not _INTERRUPTED:
                    phase3_marker.parent.mkdir(parents=True, exist_ok=True)
                    phase3_marker.touch()
                    log("Phase 3 complete")
            elif phase3_marker.exists():
                log("Phase 3 already completed (delete .phase3_done to redo)")

        # ── Phase 4: Post-processing (user-defined, only if ext file exists) ──
        if not _INTERRUPTED:
            ext_file = Path(__file__).parent.parent / "prompts-ext" / "postprocess-prompt.md"
            if ext_file.exists():
                log("Phase 4: Post-processing (user-defined)")
                for d in work_dirs:
                    try:
                        vuln_postprocess.run(d, thinking=thinking, prefix=f"[{d.name}]")
                    except Exception as e:
                        log(f"[{d.name}] Postprocess failed: {e}")
                        record_failure(f"Phase 4 Postprocess [{d.name}]: {e}")
            else:
                log("Phase 4: Post-processing skipped (no prompts-ext/postprocess-prompt.md)")

    finally:
        if vpool:
            vpool.shutdown(wait=not _INTERRUPTED)
        pool.shutdown(wait=not _INTERRUPTED)

    # Summary
    if not _INTERRUPTED:
        total_surfaces = sum(len(find_surface_files(d)) for d in work_dirs)
        total_vulns = sum(len(find_vuln_files(d)) for d in work_dirs)
        all_failures = get_all_failures()
        if all_failures:
            log(f"=== 失败汇总 ({len(all_failures)}) ===")
            for msg in all_failures:
                log(f"  {msg}")
        log(f"Pipeline complete: {total_surfaces} surfaces, {total_vulns} vuln files, {len(all_failures)} failures")


def _discover_one(work_dir: Path, recon_prompt: str, overwrite: bool,
                  thinking: bool, prefix: str) -> list[str]:
    """Run discovery for one directory, return list of surface filenames."""
    surface_discover.run(work_dir, extra_prompt=recon_prompt,
                         force=overwrite, thinking=thinking, prefix=prefix)
    items = read_surface_list(work_dir)
    return [item.filename for item in items]


def _phase2_analyze_plan(work_dir: Path, surface_file: str,
                         flow_prompt: str, vuln_prompt: str,
                         thinking: bool, prefix: str):
    """Analyze → plan for one surface (runs in main pool)."""
    stem = surface_file.replace(".md", "")
    surface_analyze.run(work_dir, max_workers=1,
                        only_surfaces=[surface_file],
                        extra_prompt=flow_prompt,
                        thinking=thinking, prefix=prefix)

    vuln_planner.run(work_dir, max_workers=1,
                     extra_prompt=vuln_prompt,
                     thinking=thinking,
                     only_stems=[stem],
                     prefix=prefix)


def _phase2_vuln_review(work_dir: Path, surface_file: str,
                        vuln_prompt: str, verify_prompt: str,
                        thinking: bool,
                        skip_novuln_review: bool = False,
                        prefix: str = ""):
    """High-risk vuln+review for one surface (runs in vuln pool)."""
    stem = surface_file.replace(".md", "")
    vuln_analyze.run(work_dir, max_workers=1,
                     extra_prompt=vuln_prompt,
                     only_stems=[stem],
                     thinking=thinking,
                     min_level="high", risk_first=True,
                     prefix=prefix, force=False)
    review_vuln.run(work_dir, max_workers=1,
                    extra_prompt=verify_prompt,
                    only_stems=[stem],
                    thinking=thinking, prefix=prefix,
                    skip_novuln=skip_novuln_review)


def _phase3_one(work_dir: Path, surface_file: str,
                levels: list[str],
                vuln_prompt: str, verify_prompt: str,
                thinking: bool,
                skip_novuln_review: bool = False,
                prefix: str = ""):
    """Medium → low vuln+review for one surface."""
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
                        thinking=thinking, prefix=prefix,
                        skip_novuln=skip_novuln_review)
