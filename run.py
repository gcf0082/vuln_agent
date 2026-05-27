#!/usr/bin/env python3
"""Entry point for biz-flow-recon pipeline.

Usage:
    python3 run_recon.py [work_dir]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from biz_recon.runner import main

main()
