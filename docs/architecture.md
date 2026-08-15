# 架构与数据流

本文档描述 vulnforge 的模块划分、扫描编排流程与数据模型。

## 总体架构

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
       │              │                  │             │
       ▼              ▼                  ▼             ▼
┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌─────────────┐
│ static/  │  │  llm/      │  │  fuzz/       │  │  db/ (CVE/  │
│ rules    │  │  providers │  │  engine      │  │  OSV/cache) │
└──────────┘  └────────────┘  └──────────────┘  └─────────────┘
       │              │                  │             │
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

## 模块职责

| 模块 | 职责 |
| --- | --- |
| `vulnforge.models` | 数据模型：`Finding`、`Severity`、`Target`、`ScanResult`、`ScanReport` |
| `vulnforge.config` | 配置加载、内置 YAML 解析、深度合并 |
| `vulnforge.core.engine` | `ScanEngine` 编排：实例化扫描器、聚合、去重、统计 |
| `vulnforge.core.target` | `TargetCollector` 目标发现与语言识别 |
| `vulnforge.core.dedup` | 按 `(rule_id, file_path, line)` 去重 |
| `vulnforge.core.severity` | 按严重度排序、阈值过滤 |
| `vulnforge.scanners` | 扫描器注册表 + 各扫描器实现 |
| `vulnforge.llm` | LLM provider 抽象与实现 |
| `vulnforge.fuzz` | 变异模糊测试引擎 |
| `vulnforge.cvss` | CVSS 3.1 基评分 |
| `vulnforge.report` | 报告渲染与写盘 |
| `vulnforge.db` | 内置 CVE 库、OSV 客户端、JSON 缓存 |
| `vulnforge.webhook` | Webhook HMAC 校验与事件解析 |

## 扫描编排流程

`ScanEngine.scan(targets)` 的执行步骤：

1. 读取 `config["scanners"]` 开关，`create_scanners(enabled)` 实例化启用的扫描器。
2. 逐个扫描器调用 `scanner.scan(targets, config)`，收集 finding。
   - 单个扫描器异常会被捕获并记录日志，**不影响其它扫描器**。
3. `dedupe(raw_findings)`：按 `(rule_id, file_path, line)` 去重，保留更严重/更高置信度的。
4. `sort_findings()`：按严重度降序 → 文件路径 → 行号 → rule_id 排序。
5. 构建 `stats`：总量、各严重度计数、`by_scanner`、`by_cwe`、`duration_ms`。
6. 返回 `ScanReport(scan_id, created_at, targets, findings, stats, config)`。

## 扫描器接口

所有扫描器继承 `BaseScanner`，实现：

```python
class BaseScanner(ABC):
    name = "base"
    def scan(self, targets: List[Target], config: dict) -> List[Finding]: ...
    def _iter_files(self, targets): ...  # 迭代目标下的文件
```

扫描器通过 `@register` 装饰器自动注册到 `scanners.registry`。

## 数据模型

### Finding

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `rule_id` | str | 规则 id（如 `sql-query-concat`） |
| `title` | str | 标题 |
| `description` | str | 描述 |
| `severity` | Severity | 严重度枚举 |
| `file_path` | str | 文件路径 |
| `line` | int | 行号（1 起） |
| `column` | int | 列号 |
| `code` | str | 代码片段 |
| `cwe` | str | CWE 编号 |
| `cvss` | float\|None | CVSS 分数 |
| `confidence` | float | 置信度 0-1 |
| `scanner` | str | 来源扫描器 |
| `recommendation` | str | 修复建议 |
| `references` | list | 参考链接 |
| `tags` | list | 标签 |
| `raw` | dict | 原始数据（SBOM/CVE 等附加信息） |

### Severity 枚举

```
INFO="info" < LOW="low" < MEDIUM="medium" < HIGH="high" < CRITICAL="critical"
```

提供 `.rank`（0-4）、`.from_str()`、`.from_score()` 与比较运算。

### Target

| 字段 | 说明 |
| --- | --- |
| `path` | 路径 |
| `kind` | `file` / `directory` / `repo` |
| `language` | 语言（如 `python`） |
| `size` | 字节大小 |

### ScanReport

| 字段 | 说明 |
| --- | --- |
| `scan_id` | 唯一扫描 id（UUID hex） |
| `created_at` | 创建时间（ISO8601 UTC） |
| `targets` | 目标列表 |
| `findings` | 去重排序后的 finding |
| `stats` | 统计信息 |
| `config` | 本次使用的配置 |

## 语言检测

`TargetCollector` 通过扩展名映射语言（`.py→python`、`.go→go`、`.java→java` 等），并跳过 `.git`、`node_modules`、`__pycache__`、`dist`、`build` 等目录及二进制/超大文件（>2MB）。
