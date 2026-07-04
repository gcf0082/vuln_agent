#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-target runner — analyze each subdirectory independently."""

import logging
import shutil
from datetime import datetime
from pathlib import Path

from . import runner
from .workspace import OUTPUT_PARENT

# Skip patterns for subdirectories
SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".idea", ".vscode",
    ".gradle", ".mvn", ".cache", ".tox", ".pytest_cache",
    "env", ".env", ".gitkeep",
})

_logger: logging.Logger | None = None


def _log(msg: str = ""):
    if msg:
        print(f"  {msg}")
    else:
        print()


def list_subdirs(parent: Path) -> list[Path]:
    """List immediate subdirectories, filtering out skip list and hidden dirs."""
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


def restore_from_parent(parent_output: Path, subdir_output: Path) -> None:
    """If parent has stored output for this subdir, move it back for resume."""
    if not parent_output.exists():
        return
    if subdir_output.exists():
        shutil.rmtree(parent_output)
        return
    shutil.move(str(parent_output), str(subdir_output))
    _log(f"  Restored progress from parent")


def move_to_parent(subdir_output: Path, parent_output: Path) -> None:
    """After completion, move subdir's output to parent."""
    if not subdir_output.exists():
        return
    parent_output.parent.mkdir(parents=True, exist_ok=True)
    if parent_output.exists():
        shutil.rmtree(parent_output)
    shutil.move(str(subdir_output), str(parent_output))
    _log(f"  Moved output to parent")


def count_prefix_files(root: Path, subdir_name: str, stage_dir: str, prefixes: list[str]) -> dict[str, int]:
    """Count files by prefix under parent/.vuln_agent_output/<subdir>/<stage_dir>/."""
    d = root / OUTPUT_PARENT / subdir_name / stage_dir
    counts = {p: 0 for p in prefixes}
    if not d.exists():
        return counts
    for f in d.iterdir():
        if not f.is_file() or f.suffix != ".md":
            continue
        for p in prefixes:
            if f.name.startswith(p):
                counts[p] += 1
    return counts


def extract_vuln_summary(filepath: Path) -> dict:
    """Extract title, type, location, CVSS from a VULN finding file."""
    info = {"title": "", "type": "", "location": "", "cvss": "", "severity": ""}
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return info
    for line in text.splitlines():
        if line.startswith("# ") and not info["title"]:
            info["title"] = line[2:].strip()
        # Type
        if "**类型**：" in line:
            info["type"] = line.split("**类型**：", 1)[-1].split("**")[0].strip()
        elif "**类型**: " in line:
            info["type"] = line.split("**类型**: ", 1)[-1].split("**")[0].strip()
        elif "**Type**：" in line or "**Type**: " in line:
            sep = "：" if "：" in line else ": "
            info["type"] = line.split(f"**Type**{sep}", 1)[-1].split("**")[0].strip()
        # Location
        if "**位置**：" in line:
            info["location"] = line.split("**位置**：", 1)[-1].split("**")[0].strip()
        elif "**位置**: " in line:
            info["location"] = line.split("**位置**: ", 1)[-1].split("**")[0].strip()
        elif "**Location**：" in line or "**Location**: " in line:
            sep = "：" if "：" in line else ": "
            info["location"] = line.split(f"**Location**{sep}", 1)[-1].split("**")[0].strip()
        # CVSS
        if "**CVSS 评分**：" in line:
            info["cvss"] = line.split("**CVSS 评分**：", 1)[-1].split("**")[0].strip()
        elif "**CVSS 评分**: " in line:
            info["cvss"] = line.split("**CVSS 评分**: ", 1)[-1].split("**")[0].strip()
        elif "**CVSS**：" in line or "**CVSS**: " in line:
            sep = "：" if "：" in line else ": "
            info["cvss"] = line.split(f"**CVSS**{sep}", 1)[-1].split("**")[0].strip()
        # Severity
        if "**严重性**：" in line:
            info["severity"] = line.split("**严重性**：", 1)[-1].split("**")[0].strip()
        elif "**严重性**: " in line:
            info["severity"] = line.split("**严重性**: ", 1)[-1].split("**")[0].strip()
        elif "**Severity**：" in line or "**Severity**: " in line:
            sep = "：" if "：" in line else ": "
            info["severity"] = line.split(f"**Severity**{sep}", 1)[-1].split("**")[0].strip()
    return info


def check_review_verdict(root: Path, subdir_name: str, vuln_stem: str) -> str:
    """Check if a reviewed verdict exists for a vuln finding."""
    review_dir = root / OUTPUT_PARENT / subdir_name / "vuln_reviews"
    if not review_dir.exists():
        return ""
    for prefix in ("VULN-", "NOVULN-", "SUSPECTED-"):
        candidate = review_dir / f"{prefix}{vuln_stem}.md"
        if candidate.exists():
            try:
                first_line = candidate.read_text(encoding="utf-8").splitlines()[0]
                return first_line.lstrip("# ").strip()
            except Exception:
                return prefix.rstrip("-")
        # Also try with VULN- prefix (review files use VULN-VULN- naming)
        if prefix == "VULN-":
            candidate2 = review_dir / f"{prefix}{prefix}{vuln_stem}.md"
            if candidate2.exists():
                try:
                    first_line = candidate2.read_text(encoding="utf-8").splitlines()[0]
                    return first_line.lstrip("# ").strip()
                except Exception:
                    return "VULN"
    return ""


def generate_summary(parent: Path, results: list[dict]) -> None:
    """Generate aggregated summary report at parent/.vuln_agent_output/summary.md."""
    summary_dir = parent / OUTPUT_PARENT
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_path = summary_dir / "summary.md"

    completed = sum(1 for r in results if r["status"] == "完成")
    failed = sum(1 for r in results if r["status"].startswith("失败"))
    skipped = sum(1 for r in results if r["status"] == "跳过")

    lines = [
        "# 多目标分析汇总报告",
        "",
        f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"分析根目录：{parent}",
        f"子目录数：{len(results)} | 完成：{completed} | 失败：{failed} | 跳过：{skipped}",
        "",
        "## 各子目录结果",
        "",
        "| 子目录 | 状态 | 暴露面 | VULN | SUSPECTED | CLEAN | DISMISSED | 审查 VULN |",
        "|--------|------|--------|------|-----------|-------|-----------|-----------|",
    ]

    for r in results:
        name = r["name"]
        status = r["status"]
        if status == "完成":
            vc = count_prefix_files(parent, name, "vuln_findings",
                                     ["VULN", "SUSPECTED", "CLEAN", "DISMISSED"])
            sc = count_prefix_files(parent, name, "analyzed_surfaces", ["iface", "noniface"])
            rc = count_prefix_files(parent, name, "vuln_reviews", ["VULN", "NOVULN", "SUSPECTED"])
            surf_count = sc.get("iface", 0) + sc.get("noniface", 0)
            review_vuln = rc.get("VULN", 0)
            lines.append(
                f"| {name} | {status} | {surf_count} "
                f"| {vc.get('VULN', 0)} | {vc.get('SUSPECTED', 0)} "
                f"| {vc.get('CLEAN', 0)} | {vc.get('DISMISSED', 0)} "
                f"| {review_vuln} |"
            )
        else:
            lines.append(f"| {name} | {status} | - | - | - | - | - | - |")

    lines.append("")
    lines.append("## VULN 漏洞清单")
    lines.append("")

    for r in results:
        if r["status"] != "完成":
            continue
        name = r["name"]
        vuln_dir = parent / OUTPUT_PARENT / name / "vuln_findings"
        if not vuln_dir.exists():
            continue
        for vf in sorted(vuln_dir.glob("VULN-*.md")):
            info = extract_vuln_summary(vf)
            title = info["title"] or vf.stem
            lines.append(f"### [{name}] {title}")
            if info["type"]:
                lines.append(f"- **类型**：{info['type']}")
            if info["location"]:
                lines.append(f"- **位置**：{info['location']}")
            if info["cvss"]:
                cvss_line = info["cvss"]
                if info["severity"]:
                    cvss_line += f" {info['severity']}"
                lines.append(f"- **CVSS**：{cvss_line}")
            verdict = check_review_verdict(parent, name, vf.stem)
            if verdict:
                lines.append(f"- **审查结论**：{verdict}")
            rel_path = f"{name}/vuln_findings/{vf.name}"
            lines.append(f"- **文件**：{rel_path}")
            lines.append("")

    summary_path.write_text("\n".join(lines), encoding="utf-8")
    _log(f"Summary: {summary_path.relative_to(parent)}")


def run(parent_dir: str,
        recon_prompt: str = "",
        flow_prompt: str = "",
        vuln_prompt: str = "",
        verify_prompt: str = "",
        thinking: bool = False,
        model: str = "",
        agent: str = "",
        stage: str = "",
        overwrite: bool = False):
    """Run pipeline for each subdirectory under parent_dir."""
    parent = Path(parent_dir).resolve()
    if not parent.is_dir():
        print(f"Error: not a directory: {parent}")
        return

    subdirs = list_subdirs(parent)
    if not subdirs:
        print("No subdirectories found to analyze.")
        return

    print(f"\n{'=' * 50}")
    print(f"Multi-target analysis: {parent}")
    print(f"  Subdirectories ({len(subdirs)}): {', '.join(d.name for d in subdirs)}")
    if stage:
        print(f"  Stage: {stage}")
    print(f"{'=' * 50}")

    results: list[dict] = []
    for i, subdir in enumerate(subdirs):
        name = subdir.name
        print(f"\n--- [{i+1}/{len(subdirs)}] {name} ---")

        parent_output = parent / OUTPUT_PARENT / name
        subdir_output = subdir / OUTPUT_PARENT

        # Restore progress from parent if needed
        restore_from_parent(parent_output, subdir_output)

        # Check if this subdir is already fully done (all resolved stages complete)
        try:
            if _is_already_done(subdir, stage, thinking, model, agent, overwrite):
                results.append({"name": name, "status": "跳过"})
                _log("Already completed, skipped")
                continue
        except Exception:
            pass

        # Run pipeline
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
            )
            if stats.get("failed_stages"):
                status = f"失败 ({', '.join(stats['failed_stages'])})"
            else:
                status = "完成"
            _log(f"  Status: {status}")
            results.append({"name": name, "status": status, "stats": stats})
        except Exception as e:
            status = f"失败: {e}"
            _log(f"  Status: {status}")
            results.append({"name": name, "status": status, "stats": {}})

        # Move output to parent (regardless of partial or full completion)
        move_to_parent(subdir_output, parent_output)

    # Generate summary
    generate_summary(parent, results)

    # Print final summary
    print(f"\n{'=' * 50}")
    print("Multi-target analysis complete.")
    completed = sum(1 for r in results if r["status"] == "完成")
    failed = sum(1 for r in results if r["status"].startswith("失败"))
    skipped = sum(1 for r in results if r["status"] == "跳过")
    print(f"  Total: {len(results)}, Done: {completed}, Failed: {failed}, Skipped: {skipped}")


def _is_already_done(work_path: Path, stage: str,
                     thinking: bool, model: str, agent: str,
                     overwrite: bool) -> bool:
    """Check if all resolved stages are already complete for this subdir.
    
    Returns True if every stage that would run has existing output,
    meaning the subdirectory can be skipped entirely.
    """
    from .runner import _resolve_stages, load_config, _STAGE_REGISTRY

    config = load_config()
    # Check without force_list
    stages = _resolve_stages(work_path, stage, force_list=None, config=config)

    for s in stages:
        entry = _STAGE_REGISTRY.get(s)
        if not entry:
            continue
        output_dir = work_path / OUTPUT_PARENT / entry["dir"]
        if s == "recon":
            marker = work_path / OUTPUT_PARENT / ".surface_discover_done"
            if not marker.exists():
                return False
        if not output_dir.exists() or not bool(list(output_dir.rglob("*.md"))):
            return False

    return True
