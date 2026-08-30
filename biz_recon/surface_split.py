# -*- coding: utf-8 -*-
"""Stage 1.5: surface_split - 检查并拆分含多个攻击面的 discovered_surfaces 文件。

每个 discovered_surfaces/*.md 应只含一个攻击面。本阶段用 LLM 逐个校验：
含多个攻击面则拆成多个单文件（必要时读源码判断，如"独立工具"实际提供 web 服务），
含单个则不动。agent 只写新文件 + 输出 manifest，由 Python 校验落盘后删除原文件。

对 CLI 不可见，无独立标记文件：幂等沿用管道 skip-if-output-exists--
已有 analyzed_surfaces/<同名>.md 的攻击面视为已流过拆解，跳过。
"""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import (OUTPUT_PARENT, build_vars, read_surface_list, get_timeout,
                        record_failure, save_thinking, append_thinking_manifest)


_RESULT_RE = re.compile(r"##\s*SPLIT_RESULT(.*?)(?:\n##|\Z)", re.S)
_ACTION_RE = re.compile(r"-\s*\*?\*?action\*?\*?\s*[:：]\s*(\w+)", re.I)
_FILES_RE = re.compile(r"-\s*\*?\*?new_files\*?\*?\s*[:：]\s*(.+)", re.I)
DONE_MARKER = ".surface_split_done"


def _parse_manifest(text: str) -> tuple[str, list[str]]:
    """解析 agent 末尾的 SPLIT_RESULT manifest，返回 (action, new_files)。"""
    m = _RESULT_RE.search(text)
    if not m:
        return "single", []
    block = m.group(1)
    action = "single"
    am = _ACTION_RE.search(block)
    if am:
        action = am.group(1).strip().lower()
    files: list[str] = []
    if action == "split":
        fm = _FILES_RE.search(block)
        if fm:
            files = [f.strip() for f in fm.group(1).replace("，", ",").split(",") if f.strip()]
    return action, files


def _safe_rename(child: Path) -> Path:
    """若 stem 以 -\\d+ 结尾，重命名为 {stem}-part{n}。

    review_vuln._extract_surface_stem 会剥离尾随 -\\d+，纯数字后缀会导致
    不同 surface 的 stem 碰撞。此处兜底纠正。
    """
    if not re.search(r"-\d+$", child.stem):
        return child
    i = 1
    while True:
        cand = child.parent / f"{child.stem}-part{i}.md"
        if not cand.exists():
            child.rename(cand)
            return cand
        i += 1


def run(work_dir: Path, max_workers: int = 3, thinking: bool = False,
        prefix: str = "", extra_prompt: str = "", force: bool = False):
    from .workspace import setup_stage_log
    ss_log = setup_stage_log("surface_split", prefix=prefix)

    marker = work_dir / OUTPUT_PARENT / DONE_MARKER
    if not force and marker.exists():
        ss_log(f"{prefix} ⏭ 拆解跳过（已完成）", quiet=True)
        return

    items = read_surface_list(work_dir)
    if not items:
        ss_log(f"{prefix} No surface items found.", quiet=True)
        return

    vars = build_vars(work_dir)
    failures: list[str] = []

    def split_one(item):
        so_log = setup_stage_log("surface_split", item.filename, prefix=prefix)
        surfaces_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
        # 幂等（无独立标记）：已有 analyzed_surfaces/<同名> 视为已处理，跳过
        analyzed_path = work_dir / OUTPUT_PARENT / "analyzed_surfaces" / item.filename
        if analyzed_path.exists():
            so_log(f"{prefix} ⏭ 已分析，跳过拆解 {item.filename}", quiet=True)
            return True

        # 小文件快速跳过：<20 行不可能内含多个攻击面，无需 LLM 校验
        surface_path = surfaces_dir / item.filename
        if surface_path.exists():
            n_lines = len(surface_path.read_text(encoding="utf-8").splitlines())
            if n_lines < 20:
                so_log(f"{prefix} · 仅 {n_lines} 行，跳过拆解 {item.filename}", quiet=True)
                return True

        local_vars = {**vars,
            "surface_file": item.filename,
            "surface_stem": item.filename.replace(".md", ""),
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("split-surface.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking, timeout=get_timeout())

        thinking_id = f"split-{item.filename.replace('.md', '')}"
        save_thinking(work_dir, thinking_id, prompt, result.text, "split", result.exit_code)

        if result.exit_code != 0:
            suffix = "（超时）" if result.timed_out else ""
            so_log(f"{prefix} ✗ 拆解失败 {item.filename}{suffix}", quiet=True)
            return False

        action, new_files = _parse_manifest(result.text)
        kept: list[str] = []
        if action == "split":
            for fname in new_files:
                fname = Path(fname).name  # 仅取文件名，防 agent 给出路径
                p = surfaces_dir / fname
                if p.exists() and p.name != item.filename:
                    p = _safe_rename(p)
                    kept.append(p.name)
            if kept:
                (surfaces_dir / item.filename).unlink(missing_ok=True)
                so_log(f"{prefix} ✓ 拆分 {item.filename} -> {', '.join(kept)}")
            else:
                so_log(f"{prefix} ⚠ manifest 报告 split 但无落盘文件，保留原文件 {item.filename}", quiet=True)
                record_failure(f"攻击面拆解 [{prefix}] {item.filename}: 无落盘文件")
                return False
        else:
            so_log(f"{prefix} · 单一攻击面 {item.filename}", quiet=True)

        append_thinking_manifest(work_dir, {
            "thinking_id": thinking_id,
            "stage": "split",
            "surface_stem": item.filename.replace('.md', ''),
            "output_files": kept or [f"discovered_surfaces/{item.filename}"],
        })
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for item, ok in zip(items, pool.map(split_one, items)):
            if not ok:
                failures.append(item.filename)

    if failures:
        msg = f"{prefix} FAILURES ({len(failures)}): {', '.join(failures)}"
        ss_log(msg, quiet=True)
        for fname in failures:
            record_failure(f"攻击面拆解 [{prefix}] {fname}")

    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    ss_log(f"{prefix} ✓ 攻击面拆解完成", quiet=True)
