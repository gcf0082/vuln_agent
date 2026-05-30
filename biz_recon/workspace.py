"""Output directory and file helpers."""

import logging
import re
from pathlib import Path
from .models import SurfaceItem

OUTPUT_PARENT = "_output"
TOOL_DIR = Path(__file__).parent

_logger: logging.Logger | None = None
_prompt_logger: logging.Logger | None = None


def setup_logging(work_dir: Path):
    global _logger, _prompt_logger
    log_dir = work_dir / "logs"
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


def log(msg: str = ""):
    if not _logger:
        return
    if msg:
        _logger.info(msg)
    else:
        print()


def ensure_dirs(work_dir: Path):
    for d in ["surfaces", "analysis", "vulnerabilities", "vuln_review", "meta/error"]:
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
    """Read surface entries from ``_surfaces/`` directory (one file per entry)."""
    items: list[SurfaceItem] = []
    collect_dir = work_dir / OUTPUT_PARENT / "surfaces"
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
    return sorted((work_dir / OUTPUT_PARENT / "analysis").glob("*.md"))


def find_vuln_files(work_dir: Path) -> list[Path]:
    results = []
    for prefix in ("VULN", "DISMISSED", "CLEAN", "SUSPECTED"):
        results.extend(sorted((work_dir / OUTPUT_PARENT / "vulnerabilities").glob(f"{prefix}-*.md")))
    return results


def needs_analysis(work_dir: Path, surface_filename: str) -> bool:
    """Check if a surface file already has vuln analysis."""
    for f in find_vuln_files(work_dir):
        if surface_filename.replace(".md", "") in f.name:
            return False
    return True
