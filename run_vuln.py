#!/usr/bin/env python3
"""Stage 4: Vulnerability analysis (独立入口)."""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from biz_recon import vuln
from biz_recon.runner import load_config
from biz_recon.workspace import setup_logging


def main():
    parser = argparse.ArgumentParser(description="Stage 4: 漏洞分析")
    parser.add_argument("work_dir", nargs="?", default=".",
                        help="目标代码目录 (默认当前目录)")
    parser.add_argument("-e", "--extra-prompt", default="",
                        help="追加到漏洞分析阶段提示词末尾的文本")
    args = parser.parse_args()

    work_dir = Path(args.work_dir).resolve()
    config = load_config()
    max_workers = config.get("max_workers", 3)

    setup_logging(work_dir)
    try:
        vuln.run(work_dir,
                 max_workers=max_workers,
                 extra_prompt=args.extra_prompt)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
