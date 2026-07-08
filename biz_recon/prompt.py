# -*- coding: utf-8 -*-
"""Prompt template composition: include resolution, variable substitution, logging.

This is the prompt-processing layer — it understands ``{include:xxx}``
markers in template files and resolves them against the ``references/``
directory.  :mod:`workspace` delegates this concern to us and only handles
file paths, output directories, and generic I/O helpers.
"""

import logging
import re
from pathlib import Path

TOOL_DIR = Path(__file__).parent


# ── variable substitution ──


def _subst(text: str, vars: dict[str, str]) -> str:
    """Safe substitution: only replace known ``{key}`` placeholders.

    Unlike ``str.format()``, this won't crash on unknown ``{placeholders}``
    such as ``{METHOD}`` or ``{var}`` in example templates.
    """
    for k, v in vars.items():
        text = text.replace(f"{{{k}}}", v)
    return text


# ── include resolution ──


def _resolve_includes(text: str) -> str:
    """Resolve ``{include:file.md}`` markers by loading ``references/<file>``.

    Include markers can be nested.  Duplicate includes (by filename) are
    silently dropped on subsequent occurrences to prevent infinite loops::

        {include:constraints.md}

    Returns the expanded text with all include markers replaced.
    """
    seen: set[str] = set()
    while True:
        m = re.search(r"\{include:([^}]+)\}", text)
        if not m:
            break
        ref_name = m.group(1)
        if ref_name in seen:
            text = text.replace(m.group(0), "", 1)
            continue
        seen.add(ref_name)
        ref_path = TOOL_DIR / "references" / ref_name
        if ref_path.exists():
            content = ref_path.read_text(encoding="utf-8")
            text = text.replace(m.group(0), content, 1)
        else:
            text = text.replace(m.group(0), f"<!-- missing ref: {ref_name} -->", 1)
    return text


# ── logging ──


def log_prompt(name: str, text: str):
    """Write the full prompt text to the pipeline logger (DEBUG level).

    This goes to pipeline_thinking.log only (not pipeline.log which is INFO only).
    """
    pipeline_logger = logging.getLogger("pipeline")
    pipeline_logger.debug("╭─ PROMPT: %s (%d chars)", name, len(text))
    pipeline_logger.debug(text)


# ── public API ──


def read_prompt(name: str, vars: dict[str, str]) -> str:
    """Read a prompt template, resolve ``{include:file.md}`` markers,
    then substitute path variables.

    Templates and references are read directly from ``biz_recon/prompts/``
    and ``biz_recon/references/``.  Static variable substitution
    (``{tool_dir}``, ``{target_work_dir}``) happens at read time.

    Include markers can be nested.  Example::

        {include:constraints.md}
    """
    text = (TOOL_DIR / "prompts" / name).read_text(encoding="utf-8")
    text = _resolve_includes(text)
    resolved = _subst(text, vars)
    log_prompt(name, resolved)
    return resolved
