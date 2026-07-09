# -*- coding: utf-8 -*-
"""Output directory and file helpers."""

import logging
import os
import re
import signal
import threading
from pathlib import Path
from .models import SurfaceItem

OUTPUT_PARENT = ".vuln_agent_output"
TOOL_DIR = Path(__file__).parent
LOG_DIR = TOOL_DIR.parent / "var" / "logs"


def get_timeout(stage: str = "default") -> int:
    """Get timeout in seconds from env vars (set by runner from analysis-config.yaml).

    Config values are in minutes, converted to seconds here.
    """
    if stage == "surface_discover":
        return int(os.environ.get("TIMEOUT_SURFACE_DISCOVER", 120)) * 60
    return int(os.environ.get("TIMEOUT_DEFAULT", 60)) * 60


_sigint_event = threading.Event()


def install_sigint_handler():
    """Install SIGINT handler that sets interrupt event then re-raises KeyboardInterrupt."""
    def _handler(signum, frame):
        _sigint_event.set()
        raise KeyboardInterrupt
    try:
        signal.signal(signal.SIGINT, _handler)
    except ValueError:
        pass


def is_interrupted() -> bool:
    return _sigint_event.is_set()


_logger: logging.Logger | None = None


def setup_logging():
    global _logger
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    _logger = logging.getLogger("pipeline")
    _logger.setLevel(logging.DEBUG)
    _logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    fh = logging.FileHandler(LOG_DIR / "pipeline.log", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    _logger.addHandler(fh)

    fh_debug = logging.FileHandler(LOG_DIR / "pipeline_thinking.log", encoding="utf-8")
    fh_debug.setLevel(logging.DEBUG)
    fh_debug.setFormatter(fmt)
    _logger.addHandler(fh_debug)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    _logger.addHandler(ch)


def setup_stage_log(stage: str, target: str = "", prefix: str = ""):
    """Create a per-target stage logger that forwards to pipeline.log."""
    stage_logger = logging.getLogger(f"_stage_{stage}_{target}")
    stage_logger.setLevel(logging.DEBUG)
    stage_logger.handlers.clear()
    stage_logger.propagate = False

    def stage_log(msg: str = ""):
        if msg:
            full = f"{prefix} {msg}" if prefix else msg
            stage_logger.info(full)
            if _logger:
                _logger.info(full)
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
    for d in ["discovered_surfaces", "analyzed_surfaces", "vuln_plans", "vuln_findings", "vuln_reviews", "vuln_postprocess", "meta/error"]:
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
        text = f.read_text(encoding="utf-8")
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
    for prefix in ("VULN", "NOVULN", "SUSPECTED"):
        results.extend(sorted((work_dir / OUTPUT_PARENT / "vuln_findings").glob(f"{prefix}-*.md")))
    return results


def needs_analysis(work_dir: Path, surface_filename: str) -> bool:
    """Check if a surface file already has vuln analysis."""
    for f in find_vuln_files(work_dir):
        if surface_filename.replace(".md", "") in f.name:
            return False
    return True
