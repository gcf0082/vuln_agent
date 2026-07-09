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
from biz_recon import runner
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
    result = client.run(prompt, verbose=True)

    if result.exit_code != 0:
        print(f"\n✗ Connection failed (exit={result.exit_code})")
        sys.exit(1)

    if not result.text.strip():
        print("\n✗ Empty response")
        sys.exit(1)

    print(f"  Response: {result.text.strip()}")
    print("\n✓ LLM connection successful")


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
                        help="Extra prompt appended to the vuln stage (vulnerability analysis + review)")
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
    parser.add_argument("--stage", choices=["recon", "flow", "vuln", "postprocess"],
                        help="Run a single pipeline stage only: recon / flow / vuln / postprocess")
    parser.add_argument("--overwrite", action="store_true",
                        help="Delete existing stage output before running (with --stage)")
    parser.add_argument("--multi", action="store_true",
                        help="Treat work_dir as parent containing multiple projects; analyze each subdirectory independently")
    parser.add_argument("--min-level", choices=["high", "medium", "low"],
                        default="low",
                        help="Minimum vulnerability level to analyze (default: low)")

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
        runner.main(work_dir=args.work_dir,
                    recon_prompt=args.recon_prompt,
                    flow_prompt=args.flow_prompt,
                    vuln_prompt=args.vuln_prompt,
                    thinking=args.thinking,
                    force_surface=args.force_surface,
                    model=args.model,
                    agent=args.agent,
                    stage=args.stage,
                    overwrite=args.overwrite,
                    min_level=args.min_level,
                    multi=args.multi)
