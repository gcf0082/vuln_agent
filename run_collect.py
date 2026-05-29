#!/usr/bin/env python3
"""Stage 1: Attack surface collection (独立入口)."""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from biz_recon import collect
from biz_recon.workspace import setup_logging


def main():
    parser = argparse.ArgumentParser(description="Stage 1: 攻击面收集")
    parser.add_argument("work_dir", nargs="?", default=".",
                        help="目标代码目录 (默认当前目录)")
    parser.add_argument("-e", "--extra-prompt", default="",
                        help="追加到收集阶段提示词末尾的文本")
    args = parser.parse_args()

    work_dir = Path(args.work_dir).resolve()
    setup_logging(Path(__file__).parent.resolve())
    try:
        collect.run(work_dir, extra_prompt=args.extra_prompt)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
