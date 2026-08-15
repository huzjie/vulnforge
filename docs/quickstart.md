# 快速开始（5 分钟，mock 模式）

本文档带你用 **5 分钟**跑通一次 vulnforge 扫描，全程**离线、零配置、零 API Key**。

## 前置条件

- Python 3.9+
- 无第三方依赖要求（mock 模式仅用标准库）

## 第 1 步：安装

```bash
cd vulnforge
pip install -e .
```

## 第 2 步：确认环境

```bash
vulnforge version
# 1.0.0

vulnforge doctor
# 打印一张自检表：版本 / 依赖 / 配置加载 / 模块 / 规则数 / provider 数
```

## 第 3 步：跑一次扫描

仓库自带一批故意含漏洞的样例，位于 `examples/vulnerable/`：

```bash
vulnforge scan examples/vulnerable --format json --format sarif
```

输出示例：

```text
已写入: ./results/<scan_id>.json
已写入: ./results/<scan_id>.sarif

扫描统计
severity  rule_id                 file                        line  title
critical  deser-pickle-load       .../deserialization.py      4     Unsafe pickle deserialization
high      cmd-os-system           .../command_injection.py    6     os.system with concatenation
...
共 N 个 finding | critical:2 high:5 medium:3 low:1
```

## 第 4 步：查看报告

```bash
ls results/
# <scan_id>.json  <scan_id>.sarif
```

- `*.json`：结构化结果，含 `meta` / `stats` / `findings`。
- `*.sarif`：可直接上传到 GitHub Code Scanning。

## 第 5 步：用 Python API 扫描

```python
from vulnforge.config import load_config
from vulnforge.core.target import TargetCollector
from vulnforge.core.engine import ScanEngine
from vulnforge.report import write

config = load_config()
targets = TargetCollector().collect(["examples/vulnerable"], config)
report = ScanEngine(config).scan(targets)

print(report.stats)
write(report, "json", "./results/report.json")
```

## 下一步

- 想接入真实 LLM？看 [llm-providers.md](llm-providers.md)。
- 想理解架构？看 [architecture.md](architecture.md)。
- 想写自定义规则？看 [static-rules.md](static-rules.md)。
- 完整配置字段？看 [configuration.md](configuration.md)。

## 常见问题速览

| 问题 | 答案 |
| --- | --- |
| 需要网络吗？ | mock 模式完全不需要。 |
| 需要 API Key 吗？ | mock 模式不需要。 |
| 为什么没扫出 LLM 结果？ | mock 模式下 LLM 使用内置 `MockProvider`，输出是确定性的样例结果。 |
| 报告写到哪里？ | 默认 `./results/`，可用 `-o` 或配置 `general.output_dir` 修改。 |
