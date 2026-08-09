# -*- coding: utf-8 -*-
"""Stage 1.6: surface_rank - 对 discovered_surfaces 全局优先级排序。

排序产出 meta/surface-priority.jsonl（每行一个攻击面，行序=分发顺序）。
下游 load_ranking 据此分发业务流分析：JSONL 序优先 + 不在 JSONL 的攻击面末尾分发。

对 CLI 不可见、无独立标记：JSONL 已存在即复用（不重排），删除即重排。
不读源码、不改攻击面文件。
"""
import json
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import (OUTPUT_PARENT, build_vars, get_timeout, get_target_id,
                         record_failure, save_thinking, append_thinking_manifest)

PRIORITY_JSONL_NAME = "surface-priority.jsonl"

# 攻击面数量不超过此阈值时跳过排序（直接按文件名序分发，不产出 JSONL）
RANK_THRESHOLD = 30

_RESULT_RE = re.compile(r"##\s*PRIORITY_RESULT(.*?)(?:\n##|\Z)", re.S)
# 兼容 ASCII `|` 与全角 `｜` 作为分隔符
_LINE_RE = re.compile(r"^-\s*(.+?\.md)\s*[|｜]\s*(high|medium|low)\s*[|｜]\s*(.+)$", re.I | re.M)


def _parse_priority_manifest(text: str) -> list[tuple[str, str, str]]:
    """解析 ## PRIORITY_RESULT 清单，返回 [(filename, tier, rationale), ...]。"""
    m = _RESULT_RE.search(text)
    if not m:
        return []
    return [(f.strip(), t.strip().lower(), r.strip()) for f, t, r in _LINE_RE.findall(m.group(1))]


def _build_surfaces_block(work_dir: Path) -> tuple[str, list[str]]:
    """读取 discovered_surfaces/*.md 全文，返回 (拼接块, 排序后的文件名列表)。"""
    surfaces_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
    files = sorted(surfaces_dir.glob("*.md"))
    parts: list[str] = []
    names: list[str] = []
    for f in files:
        names.append(f.name)
        content = f.read_text(encoding="utf-8").strip()
        parts.append(f"### {f.name}\n\n{content}")
    return ("\n\n---\n\n".join(parts), names)


def _priority_file(work_dir: Path) -> Path:
    return work_dir / OUTPUT_PARENT / "meta" / PRIORITY_JSONL_NAME


def run(work_dir: Path, thinking: bool = False, prefix: str = ""):
    """对所有 discovered_surfaces 做一次全局优先级排序，写出 meta/surface-priority.jsonl。

    幂等：JSONL 已存在即复用、跳过；删除即重排。manifest 覆盖部分时仍写入（漏排的下游末尾补）。
    """
    from .workspace import setup_stage_log
    sr_log = setup_stage_log("surface_rank", prefix=prefix)

    out_file = _priority_file(work_dir)
    if out_file.exists():
        sr_log(f"{prefix} ⏭ 优先级排序已存在，跳过 {out_file.name}", quiet=True)
        return

    block, names = _build_surfaces_block(work_dir)
    if not names:
        sr_log(f"{prefix} No surface files to rank.", quiet=True)
        return

    if len(names) <= RANK_THRESHOLD:
        sr_log(f"{prefix} · {len(names)} 个攻击面 ≤ {RANK_THRESHOLD}，无需排序（按文件名序分发）", quiet=True)
        return

    local_vars = {**build_vars(work_dir), "surfaces_block": block}
    prompt = read_prompt("rank-surfaces.txt", local_vars)

    client = OpenCodeClient()
    result = client.run(prompt, verbose=thinking, timeout=get_timeout())

    thinking_id = f"rank-{get_target_id(work_dir)}"
    save_thinking(work_dir, thinking_id, prompt, result.text, "rank", result.exit_code)

    if result.exit_code != 0:
        suffix = "（超时）" if result.timed_out else ""
        sr_log(f"{prefix} ✗ 优先级排序失败{suffix}")
        record_failure(f"攻击面优先级排序 [{prefix}]:{'超时' if result.timed_out else '失败'}")
        return

    ranked = _parse_priority_manifest(result.text)
    if not ranked:
        sr_log(f"{prefix} ✗ 未解析到 PRIORITY_RESULT 清单")
        record_failure(f"攻击面优先级排序 [{prefix}]: 无 PRIORITY_RESULT 清单")
        return

    # 仅保留真实存在的文件名，去重，按 manifest 顺序写入
    name_set = set(names)
    seen: set[str] = set()
    rows: list[dict] = []
    for fname, tier, rationale in ranked:
        fname = Path(fname).name
        if fname in seen or fname not in name_set:
            continue
        seen.add(fname)
        rows.append({"surface_file": fname, "priority": tier, "rationale": rationale})

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    missing = [n for n in names if n not in seen]
    if missing:
        sr_log(f"{prefix} ⚠ 排序 {len(rows)}/{len(names)}，未排序 {len(missing)} 个将末尾分发：{', '.join(missing)}")
    else:
        sr_log(f"{prefix} ✓ 优先级排序完成 {len(rows)}/{len(names)}")

    append_thinking_manifest(work_dir, {
        "thinking_id": thinking_id,
        "stage": "rank",
        "surface_stem": "global",
        "output_files": [f"meta/{PRIORITY_JSONL_NAME}"],
    })


def load_ranking(work_dir: Path) -> list[str]:
    """返回攻击面文件名的分发顺序：

    1. JSONL 行序中**当前仍存在**于 discovered_surfaces 的文件（过滤失效旧条目）；
    2. 当前 discovered_surfaces 中**不在 JSONL** 的文件，按文件名序追加到末尾。

    无 JSONL -> 全部按文件名序返回（即原行为）。
    """
    surfaces_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
    try:
        current = sorted(f.name for f in surfaces_dir.glob("*.md")) if surfaces_dir.exists() else []
    except OSError:
        current = []
    if not current:
        return []

    current_set = set(current)
    ordered: list[str] = []
    in_jsonl: set[str] = set()

    out_file = _priority_file(work_dir)
    try:
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                        fname = Path(row.get("surface_file", "")).name
                    except Exception:
                        continue
                    if fname and fname in current_set and fname not in in_jsonl:
                        ordered.append(fname)
                        in_jsonl.add(fname)
    except OSError:
        # JSONL 不可读/损坏 -> 当作无 JSONL，按文件名序分发
        ordered = []
        in_jsonl = set()

    # 不在 JSONL 的当前攻击面，末尾按文件名序补齐
    for fname in current:
        if fname not in in_jsonl:
            ordered.append(fname)
    return ordered
