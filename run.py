#!/usr/bin/env python3
"""Entry point for biz-flow-recon pipeline.

Usage:
    python3 run.py [work_dir] [options]
    python3 run.py --test
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from biz_recon.runner import main
from opencode_wrapper import OpenCodeClient


def _test_llm(model: str = ""):
    """Verify LLM connectivity by asking what model it is."""
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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Biz-flow-recon: automated security analysis pipeline",
    )
    parser.add_argument("work_dir", nargs="?", default=None,
                        help="Target code directory")
    parser.add_argument("--collect-prompt", default="",
                        help="Extra prompt appended to the surface-collection stage")
    parser.add_argument("--vuln-prompt", default="",
                        help="Extra prompt appended to the vulnerability-analysis stage")
    parser.add_argument("--thinking", action="store_true",
                        help="Enable thinking mode in LLM")
    parser.add_argument("--force-surface", default="",
                        help="Force re-analysis of specific surface file(s), comma-separated (e.g. iface-a.md,noniface-b.md)")
    parser.add_argument("--test", action="store_true",
                        help="Test LLM connectivity (ask what model it is)")
    parser.add_argument("--model", default="",
                        help="Model name to use (e.g. gpt-4, claude-sonnet-4)")

    # Show help when no arguments given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    if args.test:
        _test_llm(model=args.model)
    else:
        main(work_dir=args.work_dir,
             collect_prompt=args.collect_prompt,
             vuln_prompt=args.vuln_prompt,
             thinking=args.thinking,
             force_surface=args.force_surface,
             model=args.model)
