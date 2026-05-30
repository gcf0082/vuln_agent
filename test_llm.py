#!/usr/bin/env python3
"""Quick LLM connectivity test using opencode_wrapper.

Usage:
    python3 test_llm.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from opencode_wrapper import OpenCodeClient


def main():
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


if __name__ == "__main__":
    main()
