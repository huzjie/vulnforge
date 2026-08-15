# CLI 参考

vulnforge 的命令行入口：`vulnforge [--version] COMMAND ...`。

## 全局

| 参数 | 说明 |
| --- | --- |
| `--version` | 打印版本号 |
| `COMMAND` | 子命令（见下） |

## 子命令总览

| 命令 | 说明 |
| --- | --- |
| `scan` | 对路径执行漏洞扫描 |
| `serve` | 启动 FastAPI 控制面 |
| `rules` | 列出静态规则 |
| `providers` | 列出 LLM provider |
| `scanners` | 列出扫描器 |
| `fuzz` | 对目标函数/命令 fuzz |
| `sbom` | 生成 SBOM |
| `report` | 转换已有 JSON 结果为其它格式 |
| `doctor` | 自检环境 |
| `version` | 打印版本号 |

## scan

```bash
vulnforge scan PATH... [--format FMT] [--config FILE] [--severity SEV] [-o DIR] [--no-llm]
```

| 参数 | 说明 |
| --- | --- |
| `PATH` | 文件或目录（可多个） |
| `--format` | 输出格式（可多次）：`json/markdown/html/sarif/text` |
| `--config` | 配置文件路径 |
| `--severity` | 只报告不低于该严重度：`info/low/medium/high/critical` |
| `-o/--output` | 输出目录 |
| `--no-llm` | 禁用 LLM 扫描 |

示例：

```bash
vulnforge scan examples/vulnerable --format json --format sarif
vulnforge scan src/ --severity high --no-llm -o ./reports
```

## rules / providers / scanners

```bash
vulnforge rules
vulnforge providers
vulnforge scanners
```

分别列出静态规则表、LLM provider、已注册扫描器。

## fuzz

```bash
vulnforge fuzz TARGET [--iterations N] [--timeout SEC] [--config FILE]
```

| 参数 | 说明 |
| --- | --- |
| `TARGET` | 命令模板（含 `{input}`）或 `module:function` |
| `--iterations` | 迭代次数（默认 1000） |
| `--timeout` | 单次执行超时（秒，默认 5） |

## sbom

```bash
vulnforge sbom PATH... [-o FILE] [--ecosystem ECO] [--config FILE]
```

| 参数 | 说明 |
| --- | --- |
| `PATH` | 项目目录或清单文件 |
| `-o` | 输出文件（默认 `sbom.json`） |
| `--ecosystem` | `auto/pypi/npm/maven/cargo/go` |

## report

```bash
vulnforge report INPUT.json [--format FMT] [-o FILE]
```

将已有 JSON 扫描结果转换为 `json/markdown/html/sarif/text`。

## doctor

```bash
vulnforge doctor
```

自检：版本、可选依赖（fastapi/uvicorn/yaml/httpx）、配置加载、模块导入、静态规则数、provider 数，输出表格；全部通过返回 0。

## version

```bash
vulnforge version   # 1.0.0
```

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 1 | 命令失败 / 顶层异常兜底 |
| 130 | 键盘中断（Ctrl+C） |

## Python 调用

```python
from vulnforge.cli.main import main
code = main(["scan", "examples/vulnerable", "--format", "json"])
```
