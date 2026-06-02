#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM runner — invoked by llm-run.bat on Windows, mirrors llm-run.sh logic.

Reads prompt from stdin, saves to log, then pipes to the LLM agent.
Supports both OPENCODE_CONFIG mode (via opencode_wrapper.py) and standalone.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


def main():
    script_dir = Path(__file__).parent

    # ── Parse --agent from CLI args ──
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", default="")
    parser.add_argument("args", nargs="*")
    parsed, _ = parser.parse_known_args()

    # ── Determine LLM agent ──
    agent = parsed.agent or os.environ.get("LLM_AGENT", "")
    if not agent:
        if sys.platform == "win32":
            agent = "nga" if (shutil.which("nga") or shutil.which("nga.py") or shutil.which("nga.cmd")) else "opencode"
        else:
            agent = "nga" if shutil.which("nga") else "opencode"

    # ── Read prompt (CLI args or stdin) ──
    if parsed.args:
        prompt = " ".join(parsed.args)
    else:
        prompt = sys.stdin.read()

    # ── Save prompt to log file ──
    work_dir = os.environ.get("OPENCODE_WORK_DIR", str(Path.cwd()))
    log_dir = Path(work_dir) / "logs" / "prompts"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:18]
    log_file = log_dir / f"{ts}_prompt.txt"
    log_file.write_text(prompt, encoding="utf-8", errors="replace")

    # ── Build flags ──
    thinking_flag = "--thinking" if os.environ.get("OPENCODE_THINKING") == "true" else ""
    model_flag = f"--model {os.environ['LLM_MODEL']}" if os.environ.get("LLM_MODEL") else ""

    # ── OPENCODE_CONFIG mode (called from opencode_wrapper.py) ──
    if os.environ.get("OPENCODE_CONFIG"):
        os.environ["OPENCODE_PERMISSION"] = '{"read": "allow", "external_directory": {"/*":"allow"}}'
        cmd = [agent, "run", "--dir", work_dir]
        if thinking_flag:
            cmd.append(thinking_flag)
        if model_flag:
            cmd.append(model_flag)
        _pipe(agent if parsed.args else None, cmd, prompt)
        return

    # ── Standalone mode ──
    # Read .env
    env_file = script_dir / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())

    # Isolation env vars
    os.environ.setdefault("OPENCODE_DISABLE_CLAUDE_CODE", "true")
    os.environ.setdefault("OPENCODE_DISABLE_CLAUDE_CODE_SKILLS", "true")
    os.environ.setdefault("OPENCODE_DISABLE_CLAUDE_CODE_PROMPT", "true")
    os.environ.setdefault("OPENCODE_DISABLE_DEFAULT_PLUGINS", "true")
    os.environ.setdefault("OPENCODE_DISABLE_AUTOUPDATE", "true")
    os.environ.setdefault("OPENCODE_DISABLE_MODELS_FETCH", "true")
    os.environ.setdefault("OPENCODE_DISABLE_PRUNE", "true")

    # Create temporary config
    config = {
        "$schema": "https://opencode.ai/config.json",
        "model": "{env:OPENCODE_DEFAULT_MODEL}",
        "autoupdate": False,
        "permission": {"*": "allow"},
        "snapshot": False,
    }
    config_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(config, config_file, indent=2)
    config_file.close()
    os.environ["OPENCODE_CONFIG"] = config_file.name
    os.environ["OPENCODE_PERMISSION"] = '{"read": "allow", "external_directory": {"/*":"allow"}}'

    cmd = [agent, "run", "--dir", work_dir]
    if thinking_flag:
        cmd.append(thinking_flag)
    if model_flag:
        cmd.append(model_flag)
    _pipe(agent, cmd, prompt)


def _pipe(agent, cmd, prompt):
    """Pipe prompt to agent and exit with its return code."""
    try:
        # On Windows, use shell=True to properly execute .cmd/.ps1 files
        # and handle encoding issues
        use_shell = sys.platform.startswith("win")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
            shell=use_shell,
            encoding='utf-8',
            errors='replace',
        )
        proc.communicate(input=prompt)
        sys.exit(proc.returncode)
    except FileNotFoundError:
        print(f"Error: '{agent}' not found in PATH", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

