#!/bin/bash
# llm-run.sh — 调用 LLM CLI
# 输入: prompt (stdin 或命令行参数)
# 输出: 响应文本 (stdout)
# 退出码: 0=成功, 非0=失败
#
# 已设 OPENCODE_CONFIG 时由调用方管理，否则使用 agent_env/llm-config.json 静态配置。
#
# 要切换其他 LLM 工具时，修改此文件即可。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── LLM 工具检测 ──
LLM_AGENT="${LLM_AGENT:-}"
# 从命令行参数解析 --agent
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --agent) LLM_AGENT="$2"; shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]}"
# 默认 nga，不存在则回退 opencode
if [ -z "$LLM_AGENT" ]; then
    LLM_AGENT="nga"
    command -v nga &>/dev/null || LLM_AGENT="opencode"
fi

# ── 命令行参数优先，否则从 stdin 读取 ──
if [ $# -ge 1 ]; then
    PROMPT="$*"
else
    PROMPT=$(cat)
fi

# ── 调用方已提供 profile？ ──
if [ -n "${OPENCODE_CONFIG:-}" ]; then
    # 调用方（如 opencode_wrapper.py）已设置好配置目录和隔离环境
    WORK_DIR="${OPENCODE_WORK_DIR:-$(pwd)}"
    THINKING_FLAG=""
    [ "${OPENCODE_THINKING:-}" = "true" ] && THINKING_FLAG="--thinking"
    MODEL_FLAG=""
    [ -n "${LLM_MODEL:-}" ] && MODEL_FLAG="--model $LLM_MODEL"
    export OPENCODE_PERMISSION='{"read": "allow", "external_directory": {"/*":"allow"}}'
    printf '%s' "$PROMPT" | $LLM_AGENT run --dir "$WORK_DIR" $THINKING_FLAG $MODEL_FLAG
    exit $?
fi

# ── 独立运行 ──

# 读取 .env
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# 工作目录：外部指定优先，否则 agent_env
WORK_DIR="${OPENCODE_WORK_DIR:-$SCRIPT_DIR/agent_env}"

# 隔离环境变量
export OPENCODE_DISABLE_CLAUDE_CODE=true
export OPENCODE_DISABLE_CLAUDE_CODE_SKILLS=true
export OPENCODE_DISABLE_CLAUDE_CODE_PROMPT=true
export OPENCODE_DISABLE_DEFAULT_PLUGINS=true
export OPENCODE_DISABLE_AUTOUPDATE=true
export OPENCODE_DISABLE_MODELS_FETCH=true
export OPENCODE_DISABLE_PRUNE=true

# 静态配置
OPENCODE_CONFIG="$SCRIPT_DIR/agent_env/llm-config.json"
if [ ! -f "$OPENCODE_CONFIG" ]; then
    echo "ERROR: missing $OPENCODE_CONFIG" >&2
    exit 1
fi
export OPENCODE_CONFIG
export OPENCODE_CONFIG_DIR="$SCRIPT_DIR/agent_env"

export OPENCODE_PERMISSION='{"read": "allow", "external_directory": {"/*":"allow"}}'

THINKING_FLAG=""
[ "${OPENCODE_THINKING:-}" = "true" ] && THINKING_FLAG="--thinking"
MODEL_FLAG=""
[ -n "${LLM_MODEL:-}" ] && MODEL_FLAG="--model $LLM_MODEL"
printf '%s' "$PROMPT" | $LLM_AGENT run --dir "$WORK_DIR" $THINKING_FLAG $MODEL_FLAG
