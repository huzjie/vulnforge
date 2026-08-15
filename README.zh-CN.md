<!-- vulnforge 中文 README -->
<div align="center">

# vulnforge

**AI 驱动的自主漏洞挖掘与安全审计平台**
*AI-powered autonomous vulnerability research & security audit platform*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker)](docker/)
[![CodeQL](https://img.shields.io/badge/CodeQL-integrated-2b3a42.svg?logo=github)](.github/workflows)
[![Stars](https://img.shields.io/github/stars/huzjie/vulnforge?style=social)](https://github.com/huzjie/vulnforge)

</div>

---

## 一句话定位

**vulnforge** 是一个完全可离线运行的 AI 漏洞挖掘平台——把**静态规则、LLM 推理、模糊测试、依赖/SBOM 扫描、密钥检测、CVSS 评分**整合进统一流水线，输出 SARIF/SBOM 等标准格式，可直接接入 CI 与 GitHub Code Scanning。

对标智谱 GLM-5.3 网络安全突破：**CyberGym 漏洞推理 84.5% · 发现 40 年老漏洞 · 累计 2404 个漏洞 · 两周内开源权重**。

## 目录

- [什么是 vulnforge](#什么是-vulnforge)
- [核心特性](#核心特性)
- [架构](#架构)
- [快速开始](#快速开始)
- [使用方式](#使用方式)
- [扫描器详解](#扫描器详解)
- [LLM Provider 配置](#llm-provider-配置)
- [报告格式](#报告格式)
- [部署](#部署)
- [CI 集成](#ci-集成)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

---

## 什么是 vulnforge

2025–2026 年，AI 在网络安全领域实现标志性突破：

| 能力 | 指标 |
| --- | --- |
| CyberGym 漏洞推理 | **84.5%** |
| 自主发现漏洞（含一个存在 **40 年**的老漏洞） | 2404 个 |
| 开源节奏 | **两周内**开源权重 |

vulnforge 把这一「AI 自主漏洞挖掘」范式工程化为一个**开箱即用、可离线、可接入任意大模型**的安全审计平台：

- **无需网络即可运行**：默认 `mock` 模式，零 API Key、零第三方依赖（仅标准库）。
- **接入任意 LLM**：OpenAI 兼容接口（GLM / DeepSeek / Qwen / GPT）、Anthropic、Gemini、本地 Ollama。
- **标准输出**：SARIF（GitHub Code Scanning）、CycloneDX（SBOM）、JSON、Markdown、HTML。
- **统一流水线**：静态规则 + LLM 推理 + Fuzz + 依赖 CVE 四类扫描器自动编排、去重、排序、统计。

---

## 核心特性

### 核心能力

- **静态规则扫描**（SAST）：15 类、60+ 条正则规则，覆盖 SQL 注入、XSS、命令注入、路径穿越、SSRF、反序列化、弱加密、密钥泄露、C/C++ 内存缺陷等，全部带 CWE 编号。
- **LLM 漏洞推理**：将代码切片交给大模型做漏洞推理，容错解析模型输出，支持 CVSS 向量自动推导严重度。
- **轻量 Fuzz**：字节级变异模糊测试（位翻转/替换/插入/删除/字典拼接），自动收集崩溃并持久化。
- **依赖 / SBOM 扫描**：解析 `requirements.txt`、`package.json`、`pom.xml`、`Cargo.lock`、`go.sum` 等，离线生成 SBOM，在线查询 OSV.dev 命中 CVE。
- **密钥扫描**：AWS / GitHub / Slack / Stripe / JWT / PEM 私钥等 15+ 类硬编码凭据（CWE-798）。
- **CVSS 3.1 评分**：官方 FIRST 基评分公式，精确到 0.1。
- **多格式报告**：JSON / Markdown / HTML / SARIF 2.1.0 / CycloneDX 1.5。
- **Web 控制台**：React 前端 + FastAPI 控制面。
- **CLI + Python SDK + TypeScript SDK**。
- **CI 集成**：GitHub Actions / CodeQL / GitLab CI，SARIF 无缝接入 Code Scanning。

### 技术特性

- **零依赖核心**：mock 模式仅用 Python 标准库。
- **容错降级**：单个扫描器异常不影响整体扫描。
- **确定性 mock**：LLM mock provider 输出确定性结果，CI 可复现。
- **去重排序**：`(rule_id, file_path, line)` 去重，按严重度降序。
- **内置 CVE 库**：离线也可产出丰富的 CVE 元数据。

---

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                        入口层                                 │
│   CLI (vulnforge.cli.main)   SDK   REST API (vulnforge.api)  │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    编排层 (core)                             │
│  config.load_config → TargetCollector → ScanEngine           │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       扫描器层 (scanners)                     │
│  StaticScanner │ LLMReasoningScanner │ FuzzScanner │ Dep      │
└──────┬──────────────┬──────────────────┬─────────────┬───────┘
       ▼              ▼                  ▼             ▼
┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌─────────────┐
│ static/  │  │  llm/      │  │  fuzz/       │  │  db/ (CVE/  │
│ rules    │  │  providers │  │  engine      │  │  OSV/cache) │
└──────────┘  └────────────┘  └──────────────┘  └─────────────┘
       └──────────────┴──────────────────┴─────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 去重/排序 (core.dedup, core.severity)         │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              报告层 (report)  json/md/html/sarif/cyclonedx   │
└─────────────────────────────────────────────────────────────┘
```

### 目录树

```
vulnforge/
├── vulnforge/                 # Python 包
│   ├── _version.py            # 版本号
│   ├── models.py              # Finding / Severity / Target / ScanReport
│   ├── config.py              # 配置加载 + 内置 YAML 解析 + 深度合并
│   ├── cwe.py                 # CWE 查询表
│   ├── errors.py              # 异常层级
│   ├── logging.py             # 日志
│   ├── webhook.py             # Webhook HMAC 校验
│   ├── core/                  # 编排层
│   │   ├── engine.py          # ScanEngine
│   │   ├── target.py          # TargetCollector
│   │   ├── dedup.py           # finding 去重
│   │   ├── severity.py        # 排序/过滤
│   │   └── scheduler.py       # 并行调度
│   ├── scanners/              # 扫描器层
│   │   ├── registry.py        # 注册表
│   │   ├── base.py            # BaseScanner
│   │   ├── static/            # 静态规则扫描器 + 规则库
│   │   ├── llm.py             # LLM 推理扫描器
│   │   ├── fuzz.py            # Fuzz 扫描器
│   │   └── dependency.py      # 依赖/SBOM 扫描器
│   ├── llm/                   # LLM provider
│   ├── fuzz/                  # 模糊测试引擎
│   ├── cvss/                  # CVSS 3.1 评分
│   ├── report/                # 报告渲染
│   ├── db/                    # 内置 CVE 库 + OSV 客户端
│   └── cli/                   # CLI 入口与子命令
├── docs/                      # 文档（22 篇）
├── tests/                     # pytest 测试套件（离线可跑）
├── examples/                  # 示例（含故意漏洞样例）
├── web/                       # React 前端
├── docker/                    # Dockerfile 等
├── deploy/                    # K8s / Helm
├── config.example.yaml        # 配置示例
├── pyproject.toml
├── README.md
├── README.zh-CN.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── CODE_OF_CONDUCT.md
```

---

## 快速开始

### 环境要求

- Python 3.9+

### 1. 克隆与安装

```bash
git clone https://github.com/huzjie/vulnforge.git
cd vulnforge
pip install -e .
```

### 2. 验证

```bash
vulnforge version   # 1.0.0
vulnforge doctor    # 自检环境
```

### 3. mock 扫描（无需网络 / API Key）

```bash
vulnforge scan examples/vulnerable --format json --format sarif
```

报告输出到 `./results/`。

### 4. 接入真实 LLM（以 GLM-5.3 为例）

编辑 `config.yaml`：

```yaml
llm:
  default_provider: glm
  providers:
    glm:
      type: openai_compat
      base_url: https://open.bigmodel.cn/api/paas/v4
      model: glm-5.3
```

```bash
export GLM_API_KEY=your-key
vulnforge scan src/
```

---

## 使用方式

### CLI

```bash
# 扫描
vulnforge scan src/ --format json --format sarif --severity high --no-llm

# 列出规则 / 扫描器 / provider
vulnforge rules
vulnforge scanners
vulnforge providers

# 生成 SBOM
vulnforge sbom . -o sbom.json

# 报告格式转换
vulnforge report results/scan.json --format html -o report.html

# 启动 Web 控制面
vulnforge serve

# 模糊测试
vulnforge fuzz mypkg.parser:parse_input --iterations 2000
```

### Python API

```python
from vulnforge.config import load_config
from vulnforge.core.target import TargetCollector
from vulnforge.core.engine import ScanEngine
from vulnforge.report import write

config = load_config()
targets = TargetCollector().collect(["src"], config)
report = ScanEngine(config).scan(targets)

print(report.stats)
write(report, "json", "./results/report.json")
write(report, "sarif", "./results/report.sarif")
```

### SDK

- Python：见 `docs/sdk-python.md`
- TypeScript：见 `docs/sdk-typescript.md`

### 完整文档

`docs/` 目录含 22 篇文档：快速上手、配置、架构、扫描器、静态规则、LLM、Fuzz、依赖扫描、CVSS、报告、API、CLI、SDK、部署、CI、Webhook、FAQ、路线图。

---

## 扫描器详解

| 扫描器 | 类 | 说明 |
| --- | --- | --- |
| `static` | `StaticScanner` | 正则规则静态分析 |
| `llm` | `LLMReasoningScanner` | 代码切片交给 LLM 推理 |
| `fuzz` | `FuzzScanner` | 变异模糊测试 |
| `dependency` | `DependencyScanner` | 依赖/SBOM + CVE 查询 |

### 静态规则清单（节选）

| 类别 | 规则 id 示例 | CWE |
| --- | --- | --- |
| SQL 注入 | `sql-query-concat`, `sql-fstring`, `sql-execute-concat`, `sql-format-method` | CWE-89 |
| XSS | `xss-innerhtml`, `xss-document-write`, `xss-dangerously-set-inner-html` | CWE-79 |
| 命令注入 | `cmd-os-system`, `cmd-subprocess-shell`, `cmd-exec` | CWE-78 |
| 路径穿越 | `path-traversal-open-concat`, `path-traversal-join-input`, `path-traversal-dotdot` | CWE-22 |
| 弱加密 | `crypto-md5`, `crypto-sha1`, `crypto-des`, `crypto-ecb-mode` | CWE-327/326 |
| 反序列化 | `deser-pickle-load`, `deser-yaml-load`, `deser-eval`, `deser-marshal` | CWE-502 |
| SSRF | `ssrf-requests-get`, `ssrf-urllib`, `ssrf-url-concat` | CWE-918 |
| 密钥 | `secrets-aws-access-key`, `secrets-github-token`, `secrets-password-assignment`, `secrets-private-key` | CWE-798 |

完整规则表见 `docs/static-rules.md`。

---

## LLM Provider 配置

| Provider | `type` | `base_url` | `model` | 环境变量 |
| --- | --- | --- | --- | --- |
| mock | `mock` | — | — | — |
| 智谱 GLM-5.3 | `openai_compat` | `https://open.bigmodel.cn/api/paas/v4` | `glm-5.3` | `GLM_API_KEY` |
| DeepSeek | `openai_compat` | `https://api.deepseek.com/v1` | `deepseek-v4-pro` | `DEEPSEEK_API_KEY` |
| 通义千问 | `openai_compat` | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen3.8-max` | `QWEN_API_KEY` |
| OpenAI | `openai_compat` | `https://api.openai.com/v1` | `gpt-4.1` | `OPENAI_API_KEY` |
| Anthropic | `anthropic` | — | `claude-fable-5` | `ANTHROPIC_API_KEY` |
| Gemini | `gemini` | — | `gemini-3.7-flash` | `GEMINI_API_KEY` |
| Ollama | `ollama` | `http://localhost:11434` | `llama3.1` | — |

---

## 报告格式

| 格式 | 说明 |
| --- | --- |
| `json` | 结构化（meta + stats + findings） |
| `markdown` | 人类可读 |
| `html` | HTML 报告 |
| `sarif` | SARIF 2.1.0（上传 GitHub Code Scanning） |
| `cyclonedx` | CycloneDX 1.5 SBOM |

---

## 部署

```bash
# Docker
docker build -f docker/Dockerfile -t vulnforge .
docker run --rm -v "$PWD:/src" vulnforge scan /src

# docker-compose
docker compose up -d

# Kubernetes / Helm
helm install vulnforge ./deploy/helm
```

详见 `docs/deployment.md`。

---

## CI 集成

```yaml
- name: Run vulnforge
  run: |
    pip install -e .
    vulnforge scan . --format sarif -o ./results
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results
```

详见 `docs/ci-integration.md`。

---

## 参与贡献

欢迎贡献！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

开发环境：

```bash
pip install -e ".[test]"
pytest tests/ -q
```

## 安全

本工具**仅限授权安全测试与防御性研究使用**。漏洞报告与免责声明见 [SECURITY.md](SECURITY.md)。

## 许可证

[Apache License 2.0](LICENSE)

---

<div align="center">
<sub>仅用于授权安全研究。GLM-5.3 / CyberGym 数据为背景引用。</sub>
</div>
