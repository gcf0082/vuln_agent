# 项目分析约束

## 非分析目标（可参考理解，不作为分析产出）

以下代码可读作参考（理解项目结构、调用关系）：

- 测试代码（`test/`、`*Test.java`、`spec/`、`__tests__/` 等）
- CI/构建流水线脚本（如 `.github/workflows/`、`Jenkinsfile`、`.gitlab-ci.yml`、`Makefile` 等）——需结合项目结构判断，**不能仅靠关键词或文件名**（如 Dockerfile 也可能是项目交付产物本身，不是构建脚本）
- 纯前端 CSS / i18n 资源文件
- 静态资源、图片、字体
- 文档、README

遇到这些非目标文件时跳过即可，排除的路径会记录到 `{target_work_dir}/.vuln_agent_output/meta/excluded-paths.md` 供审计复核。

## 临时脚本

分析过程中如需生成并执行临时脚本（如扫描、提取、转换），统一放在 `{target_work_dir}/.vuln_agent_output/temp/scripts/` 目录下。用完即弃，不影响源码和产物。
