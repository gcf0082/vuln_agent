#!/bin/bash
# llm-run.sh — 调用 LLM CLI
# 输入: prompt (stdin 或命令行参数)
# 输出: 响应文本 (stdout)
# 退出码: 0=成功, 非0=失败
#
# 已设 OPENCODE_CONFIG 时跳过 profile 创建（由调用方管理）,
# 否则自动创建隔离 profile。
#
# 要切换其他 LLM 工具时，修改此文件即可。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── 命令行参数优先，否则从 stdin 读取 ──
if [ $# -ge 1 ]; then
    PROMPT="$*"
else
    PROMPT=$(cat)
fi

# ── 保存本轮最终提示词到独立文件 ──
PROMPT_LOG_DIR="${OPENCODE_WORK_DIR:-$SCRIPT_DIR}/logs/prompts"
mkdir -p "$PROMPT_LOG_DIR"
TS=$(date +%Y%m%d_%H%M%S)_$(date +%3N)
echo "$PROMPT" > "$PROMPT_LOG_DIR/${TS}_prompt.txt"

# ── 调用方已提供 profile？ ──
if [ -n "${OPENCODE_CONFIG:-}" ]; then
    # 调用方（如 opencode_wrapper.py）已设置好配置目录和隔离环境
    WORK_DIR="${OPENCODE_WORK_DIR:-$(pwd)}"
    THINKING_FLAG=""
    [ "${OPENCODE_THINKING:-}" = "true" ] && THINKING_FLAG="--thinking"
    export OPENCODE_PERMISSION='{"read": "allow", "external_directory": {"/*":"allow"}}'
    printf '%s' "$PROMPT" | opencode --pure run --dir "$WORK_DIR" $THINKING_FLAG
    exit $?
fi

# ── 独立运行 ──

# 读取 .env
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# 工作目录：外部指定优先，否则当前目录
WORK_DIR="${OPENCODE_WORK_DIR:-$(pwd)}"

# 隔离环境变量
export OPENCODE_DISABLE_CLAUDE_CODE=true
export OPENCODE_DISABLE_CLAUDE_CODE_SKILLS=true
export OPENCODE_DISABLE_CLAUDE_CODE_PROMPT=true
export OPENCODE_DISABLE_DEFAULT_PLUGINS=true
export OPENCODE_DISABLE_AUTOUPDATE=true
export OPENCODE_DISABLE_MODELS_FETCH=true
export OPENCODE_DISABLE_PRUNE=true

# 配置写入临时文件
OPENCODE_CONFIG=$(mktemp -t llm-config-XXXXXX.json)
trap 'rm -f "$OPENCODE_CONFIG"' EXIT
cat > "$OPENCODE_CONFIG" << 'CONFIGJSON'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "{env:OPENCODE_DEFAULT_MODEL}",
  "autoupdate": false,
  "permission": {"*": "allow"},
  "snapshot": false
}
CONFIGJSON

export OPENCODE_CONFIG

export OPENCODE_PERMISSION='{"read": "allow", "external_directory": {"/*":"allow"}}'

THINKING_FLAG=""
[ "${OPENCODE_THINKING:-}" = "true" ] && THINKING_FLAG="--thinking"
printf '%s' "$PROMPT" | opencode --pure run --dir "$WORK_DIR" $THINKING_FLAG
