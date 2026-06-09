#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM runner — invoked by llm-run.bat on Windows, mirrors llm-run.sh logic.

Reads prompt from stdin, saves to log, then pipes to the LLM agent.
Supports both OPENCODE_CONFIG mode (via opencode_wrapper.py) and standalone.
"""

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def main():
    script_dir = Path(__file__).parent
    os.environ.setdefault("OPENCODE_CONFIG_DIR", str(script_dir / "agent_env"))

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
    log_path = os.environ.get("LLM_PROMPT_LOG_PATH")
    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        Path(log_path).write_text(prompt, encoding="utf-8", errors="replace")
    else:
        work_dir = os.environ.get("OPENCODE_WORK_DIR", str(script_dir / "agent_env"))
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
        work_dir = os.environ.get("OPENCODE_WORK_DIR", os.getcwd())
        os.environ["OPENCODE_PERMISSION"] = '{"read": "allow", "external_directory": {"/*":"allow"}}'
        cmd = [agent, "run", "--dir", work_dir]
        if model_flag:
            cmd.extend(model_flag.split())
        if thinking_flag:
            cmd.append(thinking_flag)
        _pipe(agent, cmd, prompt)
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

    # Work directory: external priority, otherwise agent_env
    work_dir = os.environ.get("OPENCODE_WORK_DIR", str(script_dir / "agent_env"))

    # Isolation env vars
    os.environ.setdefault("OPENCODE_DISABLE_CLAUDE_CODE", "true")
    os.environ.setdefault("OPENCODE_DISABLE_CLAUDE_CODE_SKILLS", "true")
    os.environ.setdefault("OPENCODE_DISABLE_CLAUDE_CODE_PROMPT", "true")
    os.environ.setdefault("OPENCODE_DISABLE_DEFAULT_PLUGINS", "true")
    os.environ.setdefault("OPENCODE_DISABLE_AUTOUPDATE", "true")
    os.environ.setdefault("OPENCODE_DISABLE_MODELS_FETCH", "true")
    os.environ.setdefault("OPENCODE_DISABLE_PRUNE", "true")

    # 静态配置
    config_path = script_dir / "agent_env" / "llm-config.json"
    if not config_path.exists():
        print(f"ERROR: missing {config_path}", file=sys.stderr)
        sys.exit(1)
    os.environ["OPENCODE_CONFIG"] = str(config_path)
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
        # On Windows with PowerShell scripts, we need to use subprocess.run with proper encoding

        # For Windows PowerShell scripts, we need to use shell=True
        use_shell = sys.platform.startswith("win")
        if use_shell:
            # Convert list to string for Windows shell
            cmd_str = " ".join(f'"{c}"' if " " in c and not c.startswith('"') else c for c in cmd)
            result = subprocess.run(
                cmd_str,
                input=prompt,
                capture_output=True,
                text=True,
                shell=True,
                timeout=600,
                encoding='utf-8',
                errors='replace'
            )
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            sys.stdout.flush()
            sys.stderr.flush()
            sys.exit(result.returncode)
        else:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=use_shell,
            )
            stdout, stderr = proc.communicate(input=prompt.encode('utf-8'), timeout=600)
            sys.stdout.write(stdout.decode('utf-8', errors='replace'))
            sys.stderr.write(stderr.decode('utf-8', errors='replace'))
            sys.stdout.flush()
            sys.stderr.flush()
            sys.exit(proc.returncode)
    except FileNotFoundError:
        print(f"Error: '{agent}' not found in PATH", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"Error: '{agent}' timeout after 600 seconds", file=sys.stderr)
        proc.kill()
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"Error: '{agent}' timeout after 120 seconds", file=sys.stderr)
        proc.kill()
        sys.exit(1)


if __name__ == "__main__":
    main()

