# vulnforge 文档

欢迎来到 **vulnforge** 文档中心。vulnforge 是一个 AI 驱动的自主漏洞挖掘与安全审计平台，能够在**完全离线（mock）**模式下运行，也支持接入主流 LLM 进行代码漏洞推理。

## 核心定位

- **对标**：智谱 GLM-5.3 网络安全突破（CyberGym 漏洞推理 84.5%、发现 40 年老漏洞、累计 2404 个漏洞、两周内开源权重）。
- **能力**：静态规则扫描、LLM 漏洞推理、轻量 Fuzz、依赖/SBOM 扫描、密钥检测、CVSS 评分、多格式报告（JSON/Markdown/HTML/SARIF/CycloneDX）、Web 控制台、CLI、SDK、CI 集成。

## 文档导航

### 快速上手

| 文档 | 说明 |
| --- | --- |
| [getting-started.md](getting-started.md) | 从零开始，理解核心概念与最小流程 |
| [installation.md](installation.md) | 安装方式（pip / 源码 / Docker） |
| [quickstart.md](quickstart.md) | 5 分钟上手，纯 mock 离线模式跑通一次扫描 |
| [configuration.md](configuration.md) | `config.yaml` 全字段说明 |

### 深入理解

| 文档 | 说明 |
| --- | --- |
| [architecture.md](architecture.md) | 架构设计与数据流 |
| [scanners.md](scanners.md) | 扫描器总览（static / llm / fuzz / dependency） |
| [static-rules.md](static-rules.md) | 静态规则详解、全部规则 id、自定义规则 |
| [llm-providers.md](llm-providers.md) | LLM provider 接入（GLM-5.3 / DeepSeek / Qwen） |
| [fuzzing.md](fuzzing.md) | 模糊测试引擎使用 |
| [dependency-scan.md](dependency-scan.md) | SBOM 与依赖 CVE 扫描 |
| [cvss.md](cvss.md) | CVSS 3.1 评分说明 |
| [reports.md](reports.md) | 5 种报告格式 + SARIF 接入 GitHub |

### 接口与集成

| 文档 | 说明 |
| --- | --- |
| [cli.md](cli.md) | CLI 全部子命令参考 |
| [api.md](api.md) | REST API 全端点文档 |
| [sdk-python.md](sdk-python.md) | Python SDK 用法 |
| [sdk-typescript.md](sdk-typescript.md) | TypeScript SDK 用法 |
| [webhook.md](webhook.md) | Webhook 配置（GitHub/GitLab） |
| [deployment.md](deployment.md) | Docker / K8s / Helm 部署 |
| [ci-integration.md](ci-integration.md) | GitHub Actions / CodeQL / GitLab CI 集成 |

### 其他

| 文档 | 说明 |
| --- | --- |
| [faq.md](faq.md) | 常见问题 |
| [roadmap.md](roadmap.md) | 路线图 |

## 快速链接

- 项目仓库：https://github.com/huzjie/vulnforge
- 主 README：`../README.md`
- 配置示例：`../config.example.yaml`
- 示例代码：`../examples/`

## 快速开始（最小命令）

```bash
# 安装
pip install -e .

# 5 分钟上手（纯 mock，无需 API Key / 网络）
vulnforge scan examples/vulnerable --format json --format sarif

# 查看版本 / 自检
vulnforge version
vulnforge doctor

# 列出规则与扫描器
vulnforge rules
vulnforge scanners
vulnforge providers
```

> 说明：vulnforge 默认以 **mock 模式**运行，无需任何网络或 API Key。接入真实 LLM（如 GLM-5.3、DeepSeek、Qwen）时，只需在 `config.yaml` 中配置 provider 并设置对应环境变量。
