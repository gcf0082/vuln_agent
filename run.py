#!/usr/bin/env python3
"""Entry point for biz-flow-recon pipeline.

Usage:
    python3 run.py [work_dir] [--collect-prompt TEXT] [--vuln-prompt TEXT]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from biz_recon.runner import main


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

    # Show help when no arguments given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    main(work_dir=args.work_dir,
         collect_prompt=args.collect_prompt,
         vuln_prompt=args.vuln_prompt,
         thinking=args.thinking)
