#!/bin/bash
# agent.sh — 打开 LLM 交互式会话，默认 nga，回退 opencode，仅使用 agent_env 配置
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 检测 LLM 工具
LLM_AGENT="nga"
command -v nga &>/dev/null || LLM_AGENT="opencode"

# 配置目录指向 agent_env（禁止加载系统级 ~/.claude/ 配置）
export OPENCODE_CONFIG_DIR="$SCRIPT_DIR/agent_env"
export OPENCODE_DISABLE_CLAUDE_CODE=true
export OPENCODE_DISABLE_CLAUDE_CODE_SKILLS=true
export OPENCODE_DISABLE_CLAUDE_CODE_PROMPT=true
export OPENCODE_DISABLE_DEFAULT_PLUGINS=true
export OPENCODE_DISABLE_AUTOUPDATE=true

# 透传命令行参数，打开交互式会话
exec $LLM_AGENT --pure "$@"
