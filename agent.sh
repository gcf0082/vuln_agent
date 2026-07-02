#!/bin/bash
# agent.sh — 打开 LLM 交互式会话，默认 nga，回退 opencode
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LLM_AGENT="nga"
command -v nga &>/dev/null || LLM_AGENT="opencode"

export OPENCODE_CONFIG_DIR="$SCRIPT_DIR/agent_env"

exec $LLM_AGENT --pure "$@"
