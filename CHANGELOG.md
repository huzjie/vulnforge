# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)（语义化版本）。所有重要变更记录于此。

## [1.0.0] - 初始版本

vulnforge 首个正式版本，涵盖完整的自主漏洞挖掘与安全审计能力。

### 新增（Added）

**核心引擎**

- `ScanEngine`：扫描编排引擎，实例化启用的扫描器、聚合、去重、排序、统计。
- `TargetCollector`：目标发现，支持文件/目录/仓库，语言识别，跳过 vendor 目录与二进制/超大文件。
- 配置系统：内置 YAML 解析、深度合并、多来源优先级加载（默认 → 包内示例 → 本地 → 显式路径）。
- 数据模型：`Finding`、`Severity`（枚举）、`Target`、`ScanResult`、`ScanReport`。

**扫描器**

- `StaticScanner`：基于正则的静态规则扫描，15 类 60+ 条规则。
- `LLMReasoningScanner`：LLM 辅助漏洞推理，代码切片 + 容错 JSON 解析 + CVSS 严重度推导。
- `FuzzScanner`：变异模糊测试扫描器，支持 Python 函数与 CLI 命令目标。
- `DependencyScanner`：依赖清单解析、SBOM 生成、OSV CVE 查询。

**静态规则库（CWE 覆盖）**

- SQL 注入（CWE-89）、XSS（CWE-79）、命令注入（CWE-78）、路径穿越（CWE-22）、
- 弱加密（CWE-327/326）、反序列化（CWE-502）、SSRF（CWE-918）、
- 密钥/凭据泄露（CWE-798，15+ 类）、认证/授权、代码质量、C/C++ 内存缺陷、
- Go/Java/Python 语言专属规则。

**LLM Provider**

- `MockProvider`（离线确定性）、`OpenAICompatProvider`（GLM/DeepSeek/Qwen/GPT）、
- `AnthropicProvider`、`GeminiProvider`、`OllamaProvider`。

**模糊测试引擎**

- `FuzzEngine`、`Corpus`、`mutate`（5 种变异策略）、`CrashCollector`、`Sanitizer`。

**CVSS**

- `score_cvss31`：官方 FIRST CVSS 3.1 基评分公式。
- `severity_from_cvss`：分数到定性严重度映射。
- `parse_vector`：向量字符串解析。

**报告**

- JSON、Markdown、HTML、SARIF 2.1.0、CycloneDX 1.5（SBOM）五种格式。
- `render` / `write` / `summarize` 统一接口。

**CLI**

- `scan` / `serve` / `rules` / `providers` / `scanners` / `fuzz` / `sbom` / `report` / `doctor` / `version` 子命令。

**其它**

- Web 控制台（React 前端）+ REST API 工厂 `create_app`。
- Webhook HMAC-SHA256 签名校验与 GitHub 事件解析。
- 内置 CVE 库、OSV 客户端、JSON 缓存。
- 完整测试套件（pytest，离线可跑）。
- 示例（故意漏洞样例 + API 调用示例 + 自定义规则示例）。
- Docker / K8s / Helm 部署资产。

---

## 版本说明

- `1.0.0` 之前无发布版本。
- 后续版本变更将按 Conventional Commits 规范记录。
