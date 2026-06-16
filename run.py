#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Entry point for biz-flow-recon pipeline.

Usage:
    python3 run.py [work_dir] [options]
    python3 run.py --test
"""

import argparse
import os
import sys
from pathlib import Path
import io

if sys.platform.startswith('win'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent))
from biz_recon.runner import main
from opencode_wrapper import OpenCodeClient


def _test_llm(model: str = "", agent: str = ""):
    """Verify LLM connectivity by asking what model it is."""
    if agent:
        os.environ["LLM_AGENT"] = agent
    if model:
        os.environ["LLM_MODEL"] = model
    client = OpenCodeClient()
    prompt = (
        "请用一句话回答：你是什么模型？"
        "回答格式：在最后一行单独输出 `OK` 二字。"
    )
    print("Testing LLM connectivity...", flush=True)
    result = client.run(prompt)

    if result.exit_code != 0:
        print(f"\n✗ Connection failed (exit={result.exit_code})")
        sys.exit(1)

    if not result.text.strip():
        print("\n✗ Empty response")
        sys.exit(1)

    print(f"  Response: {result.text.strip()}")
    print("\n✓ LLM connection successful")


def _resolve_project(name: str) -> str:
    """Resolve project name: use given name, or auto-generate project_N."""
    if name:
        return name
    from db import VAR_DIR
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    max_n = 0
    for d in VAR_DIR.iterdir():
        if d.is_dir() and d.name.startswith("project_"):
            try:
                n = int(d.name.split("_")[1])
                max_n = max(max_n, n)
            except (IndexError, ValueError):
                pass
    return f"project_{max_n + 1}"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Biz-flow-recon: automated security analysis pipeline",
    )
    parser.add_argument("work_dir", nargs="?", default=None,
                        help="Target code directory")
    parser.add_argument("--recon-prompt", default="",
                        help="Extra prompt appended to the recon stage (surface discovery)")
    parser.add_argument("--flow-prompt", default="",
                        help="Extra prompt appended to the flow stage (surface analysis)")
    parser.add_argument("--vuln-prompt", default="",
                        help="Extra prompt appended to the vuln stage (vulnerability analysis)")
    parser.add_argument("--verify-prompt", default="",
                        help="Extra prompt appended to the verify stage (vulnerability review)")
    parser.add_argument("--thinking", action="store_true",
                        help="Show LLM thinking process")
    parser.add_argument("--force-surface", default="",
                        help="Force re-analysis of specific surface file(s), comma-separated (e.g. iface-a.md,noniface-b.md)")
    parser.add_argument("--test", action="store_true",
                        help="Test LLM connectivity (ask what model it is)")
    parser.add_argument("--model", default="",
                        help="Model name to use (e.g. gpt-4, claude-sonnet-4)")
    parser.add_argument("--agent", default="",
                        help="LLM agent binary (nga or opencode)")
    parser.add_argument("--project", default="",
                        help="Project name for output tracking (auto-generated if omitted)")
    parser.add_argument("--stage", choices=["recon", "flow", "vuln", "verify"],
                        help="Run a single pipeline stage only: recon / flow / vuln / verify")
    parser.add_argument("--overwrite", action="store_true",
                        help="Delete existing stage output before running (with --stage)")

    # Show help when no arguments given
    if len(sys.argv) == 1 or sys.argv[1:] == ["--"]:
        parser.print_help()
        sys.exit(0)

    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    if args.test:
        _test_llm(model=args.model, agent=args.agent)
    else:
        from db import init_db, get_project_path
        project_name = _resolve_project(args.project)
        proj_path = get_project_path(project_name)
        proj_path.mkdir(parents=True, exist_ok=True)
        # db_path = proj_path / "results.db"
        # init_db(str(db_path))
        ## Write project metadata
        # import sqlite3
        # conn = sqlite3.connect(str(db_path))
        # conn.execute(
        #     "INSERT OR REPLACE INTO projects (name, target_dir, recon_prompt, flow_prompt, vuln_prompt, verify_prompt, model, agent, force_surface) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        #     (project_name, args.work_dir or os.getcwd(),
        #      args.recon_prompt, args.flow_prompt, args.vuln_prompt, args.verify_prompt,
        #      args.model, args.agent, args.force_surface)
        # )
        # conn.commit()
        # conn.close()
        main(work_dir=args.work_dir,
             project=project_name,
             recon_prompt=args.recon_prompt,
             flow_prompt=args.flow_prompt,
             vuln_prompt=args.vuln_prompt,
             verify_prompt=args.verify_prompt,
             thinking=args.thinking,
             force_surface=args.force_surface,
             model=args.model,
             agent=args.agent,
             stage=args.stage,
             overwrite=args.overwrite)
