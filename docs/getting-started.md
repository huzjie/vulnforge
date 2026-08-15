# 快速入门

本文档介绍 vulnforge 的核心概念、最小工作流与关键术语，帮助你建立整体认知。

## 背景

2025-2026 年，AI 在网络安全领域实现关键突破：智谱 GLM-5.3 在 CyberGym 漏洞推理基准上达到 **84.5%**，自主发现一个存在 **40 年**的老漏洞，累计提交 **2404 个**漏洞，并在**两周内开源权重**。这标志着「AI 自主漏洞挖掘」从研究走向工程化。

vulnforge 对标这一能力，将**静态分析、LLM 推理、模糊测试、依赖扫描、密钥检测**整合进一个统一的、可离线的安全审计平台。

## 核心概念

| 概念 | 说明 |
| --- | --- |
| **Target** | 扫描目标：单个文件（`file`）、目录（`directory`）或仓库（`repo`）。 |
| **Finding** | 一条漏洞/可疑代码发现，包含 `rule_id`、`severity`、`cwe`、`cvss`、`file_path`、`line` 等字段。 |
| **Severity** | 严重度枚举：`info` < `low` < `medium` < `high` < `critical`。 |
| **Scanner** | 扫描器：`static`（静态规则）、`llm`（LLM 推理）、`fuzz`（模糊测试）、`dependency`（依赖/SBOM）。 |
| **ScanReport** | 一次完整扫描的聚合结果，含 `findings`、`stats`、`config`。 |
| **Provider** | LLM 提供方：`mock`、`openai_compat`、`anthropic`、`gemini`、`ollama`。 |

## 最小工作流

vulnforge 的一次扫描遵循「**收集 → 扫描 → 去重排序 → 报告**」四步：

```
[配置] ──> TargetCollector.collect() ──> [Targets]
                                          │
                                          ▼
                                 ScanEngine.scan()
                                          │
                          ┌───────────────┼────────────────┐
                          ▼               ▼                ▼
                     StaticScanner   LLMReasoningScanner  DependencyScanner / FuzzScanner
                          └───────────────┼────────────────┘
                                          ▼
                               dedupe() + sort_findings()
                                          ▼
                                 ScanReport + stats
                                          ▼
                           report.render() / write()
```

## 两条运行路径

### 1. 离线 mock 模式（默认）

- `general.mode = "mock"`，`llm.default_provider = "mock"`。
- 静态规则、密钥检测、依赖解析（离线 SBOM）、Fuzz、报告渲染全部可用。
- LLM 使用 `MockProvider`，返回**确定性**的样例结果，不联网。

### 2. 在线 live 模式（接入真实 LLM）

- 在 `config.yaml` 中配置 provider（如 GLM-5.3、DeepSeek、Qwen），设置 `api_key` 环境变量。
- `llm` 扫描器将代码切片发给模型，解析返回的 JSON finding 数组。

## 一个最小示例

```python
from vulnforge.config import load_config
from vulnforge.core.target import TargetCollector
from vulnforge.core.engine import ScanEngine

cfg = load_config()                     # 1. 加载配置（mock 默认）
targets = TargetCollector().collect(["src"], cfg)  # 2. 收集目标
report = ScanEngine(cfg).scan(targets)  # 3. 扫描
print(report.stats["total"])            # 4. 查看统计
```

## 术语速查

| 术语 | 含义 |
| --- | --- |
| SAST | 静态应用安全测试（规则匹配源码） |
| SBOM | 软件物料清单（依赖清单） |
| CWE | 通用弱点枚举（漏洞类型编号，如 CWE-89 = SQL 注入） |
| CVE | 通用漏洞披露（已知漏洞编号） |
| CVSS | 通用漏洞评分系统（0.0-10.0） |
| SARIF | 静态分析结果交换格式（可接入 GitHub Code Scanning） |
| CycloneDX | SBOM 标准格式 |
| HMAC | 用于 Webhook 签名校验的哈希消息认证码 |

## 下一步

- [quickstart.md](quickstart.md)：5 分钟跑通扫描
- [configuration.md](configuration.md)：完整配置
- [architecture.md](architecture.md)：架构与数据流细节
