@echo off
setlocal enabledelayedexpansion

REM llm-run.bat — Windows 版 LLM 调用脚本
REM 由 opencode_wrapper.py 调用，prompt 通过 stdin 传入

set "SCRIPT_DIR=%~dp0"

REM ── LLM 工具检测 ──
set "AGENT=%LLM_AGENT%"
if "%AGENT%"=="" (
    where nga >nul 2>&1
    if not errorlevel 1 (set "AGENT=nga") else (set "AGENT=opencode")
)

REM ── 工作目录 ──
set "WORK_DIR=%OPENCODE_WORK_DIR%"
if "%WORK_DIR%"=="" set "WORK_DIR=%CD%"

REM ── 保存本轮提示词 ──
set "PROMPT_LOG_DIR=%WORK_DIR%\logs\prompts"
if not exist "%PROMPT_LOG_DIR%" mkdir "%PROMPT_LOG_DIR%"

REM 用 PowerShell 读取 stdin、保存到文件、传递到 stdout
set PS_CMD=powershell -NoProfile -Command ^
    "$f=[IO.Path]::Combine('%PROMPT_LOG_DIR:\=\\%', (Get-Date -Format 'yyyyMMdd_HHmmss_fff')+'_prompt.txt'); ^
    $c=[Console]::In.ReadToEnd(); ^
    [IO.File]::WriteAllText($f,$c); ^
    Write-Output $c"

REM ── 标记参数 ──
set "THINKING_FLAG="
if "%OPENCODE_THINKING%"=="true" set "THINKING_FLAG=--thinking"
set "MODEL_FLAG="
if not "%LLM_MODEL%"=="" set "MODEL_FLAG=--model %LLM_MODEL%"

REM ── 调用 LLM ──
%PS_CMD% | %AGENT% run --dir "%WORK_DIR%" %THINKING_FLAG% %MODEL_FLAG%
set "EXIT_CODE=!errorlevel!"

exit /b %EXIT_CODE%
