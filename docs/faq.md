# 常见问题（FAQ）

## 安装与运行

**Q：需要联网吗？**
A：mock 模式完全不需要。接入真实 LLM 或在线依赖 CVE 查询时才需要网络。

**Q：需要 API Key 吗？**
A：mock 模式不需要。接入 LLM 时通过环境变量（如 `GLM_API_KEY`）提供。

**Q：Python 版本要求？**
A：>= 3.9，推荐 3.11+。

**Q：`vulnforge serve` 报 uvicorn 缺失？**
A：执行 `pip install -e ".[full]"`。

## 扫描

**Q：为什么没扫出 LLM 结果？**
A：mock 模式下 LLM 用 `MockProvider`，只对特定模式（eval/pickle/subprocess/md5/innerHTML/SQL）返回确定性样例。接入真实模型需配置 provider。

**Q：如何只跑静态扫描？**
A：配置 `scanners.llm/fuzz/dependency` 为 `false`，或 CLI `--no-llm`。

**Q：如何忽略某些目录？**
A：`TargetCollector` 默认跳过 `.git`、`node_modules`、`__pycache__`、`dist`、`build`、`venv` 等。

**Q：扫描结果写到哪里？**
A：默认 `./results/`，可用 `-o` 或 `general.output_dir` 修改。

## 规则与报告

**Q：如何添加自定义规则？**
A：见 [static-rules.md](static-rules.md) 的「编写自定义规则」章节。

**Q：支持哪些报告格式？**
A：`json`、`markdown`、`html`、`sarif`、`cyclonedx`（SBOM）。

**Q：SARIF 怎么接入 GitHub？**
A：见 [reports.md](reports.md) 与 [ci-integration.md](ci-integration.md)。

**Q：严重度与 CVSS 的关系？**
A：`severity_from_cvss` 将分数映射为 `none/low/medium/high/critical`；0 分映射为 `none`（models 层 `Severity.from_score` 映射为 `info`）。

## LLM

**Q：支持哪些模型？**
A：任何 OpenAI 兼容接口（GLM/DeepSeek/Qwen/GPT）、Anthropic、Gemini、本地 Ollama。

**Q：模型返回格式不对怎么办？**
A：`LLMReasoningScanner` 做容错解析（剥离围栏、截取 `[...]`），解析失败该块产出 0 条。

**Q：成本高吗？**
A：按 `chunk_lines` 切块（默认 400 行），可用 DeepSeek 等低成本模型；或完全用 mock。

## Fuzz 与依赖

**Q：Fuzz 如何配置目标？**
A：`config["fuzz"]["targets"]` 里写 `module:function` 或 CLI 命令模板。

**Q：依赖 CVE 怎么查？**
A：`dependency.offline=false` 时查询 OSV.dev；离线时仅产出 SBOM。

**Q：SBOM 怎么导出？**
A：`vulnforge sbom . -o sbom.json`，或 `write(report, "cyclonedx", ...)`。

## 安全与合规

**Q：本工具是否可用于未授权测试？**
A：否。仅限**授权**安全测试与防御性研究。见 `SECURITY.md` 免责声明。

**Q：发现 vulnforge 自身漏洞怎么报告？**
A：见 `SECURITY.md` 的漏洞报告流程。
