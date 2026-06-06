# -*- coding: utf-8 -*-
"""Output directory and file helpers."""

import logging
import os
import re
from datetime import datetime
from pathlib import Path
from .models import SurfaceItem

OUTPUT_PARENT = ".vuln_agent_output"
TOOL_DIR = Path(__file__).parent

_logger: logging.Logger | None = None
_prompt_logger: logging.Logger | None = None


def setup_logging(work_dir: Path, log_base: Path | None = None):
    global _logger, _prompt_logger
    base = log_base or work_dir
    log_dir = base / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    _logger = logging.getLogger("pipeline")
    _logger.setLevel(logging.DEBUG)
    _logger.handlers.clear()

    _prompt_logger = logging.getLogger("prompts")
    _prompt_logger.setLevel(logging.DEBUG)
    _prompt_logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    # Pipeline logger: file (DEBUG) + console (INFO)
    fh = logging.FileHandler(log_dir / "pipeline.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    _logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    _logger.addHandler(ch)

    # Prompt logger: file only (not printed to terminal)
    pfh = logging.FileHandler(log_dir / "prompts.log", encoding="utf-8")
    pfh.setLevel(logging.DEBUG)
    pfh.setFormatter(logging.Formatter("%(asctime)s\n%(message)s", datefmt="%H:%M:%S"))
    _prompt_logger.addHandler(pfh)


def set_prompt_log_path(stage: str, target: str = ""):
    """Set LLM_PROMPT_LOG_PATH env var for llm-run.sh to consume.

    The log filename includes stage, target file, and a readable timestamp.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    name = f"{ts}_{stage}"
    if target:
        name += f"_{target}"
    name += "_prompt.txt"
    base = Path(os.environ.get("OPENCODE_WORK_DIR", Path.cwd()))
    path = base / "logs" / "prompts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    os.environ["LLM_PROMPT_LOG_PATH"] = str(path)


def setup_stage_log(stage: str, target: str = ""):
    """Create a per-target file logger for stage processing.

    Returns a ``log()``-compatible callable that writes to:
      - ``logs/{timestamp}_{stage}_{target}.log``
      - console and ``pipeline.log`` (via the global pipeline logger)

    In parallel stages, each thread creates its own logger via this function
    to avoid file-handler cross-talk.
    """
    log_dir = Path(os.environ.get("OPENCODE_WORK_DIR", Path.cwd())) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{ts}_{stage}"
    if target:
        name += f"_{target}"

    fh = logging.FileHandler(log_dir / f"{name}.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))

    stage_logger = logging.getLogger(f"_stage_{name}")
    stage_logger.setLevel(logging.DEBUG)
    stage_logger.handlers.clear()
    stage_logger.propagate = False
    stage_logger.addHandler(fh)

    def stage_log(msg: str = ""):
        if msg:
            stage_logger.info(msg)
            if _logger:
                _logger.info(msg)
        else:
            print()

    return stage_log


def log(msg: str = ""):
    if not _logger:
        return
    if msg:
        _logger.info(msg)
    else:
        print()


def ensure_dirs(work_dir: Path):
    for d in ["discovered_surfaces", "analyzed_surfaces", "planned_vuln_tasks", "vuln_findings", "vuln_reviews", "meta/error"]:
        (work_dir / OUTPUT_PARENT / d).mkdir(parents=True, exist_ok=True)


def build_vars(target_dir: Path) -> dict[str, str]:
    """Build path variables for prompt substitution."""
    return {
        "tool_dir": str(TOOL_DIR),
        "target_work_dir": str(target_dir),
    }


def _parse_field(line: str, label: str) -> str | None:
    """Extract value from a markdown list item like ``- **类型**：iface``."""
    m = re.search(rf"^\s*-\s*\*+{re.escape(label)}\*+\s*[:：]\s*(.+)", line)
    return m.group(1).strip() if m else None


def read_surface_list(work_dir: Path) -> list[SurfaceItem]:
    """Read surface entries from ``discovered_surfaces/`` directory (one file per entry)."""
    items: list[SurfaceItem] = []
    collect_dir = work_dir / OUTPUT_PARENT / "discovered_surfaces"
    if not collect_dir.exists():
        return items

    for f in sorted(collect_dir.glob("*.md")):
        text = f.read_text()
        lines = text.splitlines()

        entry = {
            "type": None, "分类": None, "优先级": None,
            "来源": None, "描述": None, "输出文件": None,
        }
        for line in lines:
            for key in entry:
                if entry[key] is None:
                    val = _parse_field(line, key)
                    if val:
                        entry[key] = val

        fi = entry["输出文件"] or f.name
        stype = entry["type"] or ("iface" if "iface" in f.name else "noniface")
        slug = re.sub(r'\.md$', '', fi)

        items.append(SurfaceItem(
            category=entry["分类"] or "",
            priority=entry["优先级"] or "medium",
            filename=fi,
            source=entry["来源"] or "",
            description=entry["描述"] or "",
            surface_type=stype,
            slug=slug,
        ))

    return items


def find_surface_files(work_dir: Path) -> list[Path]:
    return sorted((work_dir / OUTPUT_PARENT / "analyzed_surfaces").glob("*.md"))


def find_vuln_files(work_dir: Path) -> list[Path]:
    results = []
    for prefix in ("VULN", "DISMISSED", "CLEAN", "SUSPECTED"):
        results.extend(sorted((work_dir / OUTPUT_PARENT / "vuln_findings").glob(f"{prefix}-*.md")))
    return results


def needs_analysis(work_dir: Path, surface_filename: str) -> bool:
    """Check if a surface file already has vuln analysis."""
    for f in find_vuln_files(work_dir):
        if surface_filename.replace(".md", "") in f.name:
            return False
    return True
