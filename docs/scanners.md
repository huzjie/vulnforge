# 扫描器总览

vulnforge 内置四类扫描器，统一通过 `scanners.registry` 注册与调度。

## 扫描器清单

| 名称 | 类 | 说明 | 输出 |
| --- | --- | --- | --- |
| `static` | `StaticScanner` | 基于正则的规则式静态分析 | CWE-89/79/78/798/502/22/918/327... |
| `llm` | `LLMReasoningScanner` | 将代码切片交给 LLM 推理漏洞 | LLM 返回的 JSON finding |
| `fuzz` | `FuzzScanner` | 对可执行目标做变异模糊测试 | 崩溃 finding（CWE-20） |
| `dependency` | `DependencyScanner` | 解析依赖清单、构建 SBOM、查询 CVE | SBOM finding / CVE finding |

## 开关控制

`config.yaml` 中 `scanners` 段控制启用：

```yaml
scanners:
  static: true
  llm: true
  fuzz: true
  dependency: true
  secrets: true   # 密钥检测包含在 static 规则库中
```

## 编程接口

```python
from vulnforge.scanners.registry import list_scanners, all_scanners, get_scanner

list_scanners()     # ['dependency', 'fuzz', 'llm', 'static']
all_scanners()      # [<FuzzScanner>, <StaticScanner>, ...] 实例列表
get_scanner("static")  # 返回 StaticScanner 类（未实例化）
```

## 各扫描器详解

### 1. StaticScanner（静态规则扫描）

- 位置：`vulnforge/scanners/static/scanner.py`
- 将每个文件内容逐行（或整文件）与规则正则匹配，命中的规则产出 `Finding`。
- 规则库按类别组织在 `vulnforge/scanners/static/rules/`，聚合为 `RULES`。
- 详见 [static-rules.md](static-rules.md)。

### 2. LLMReasoningScanner（LLM 推理扫描）

- 位置：`vulnforge/scanners/llm.py`
- 将文件按 `chunk_lines`（默认 400 行）切块，调用配置的 LLM provider。
- 系统提示要求模型**只输出 JSON 数组**；对模型返回做容错解析（剥离 markdown 围栏、截取 `[...]`）。
- provider 失败会降级为告警，不中断整体扫描。
- 详见 [llm-providers.md](llm-providers.md)。

### 3. FuzzScanner（模糊测试扫描）

- 位置：`vulnforge/scanners/fuzz.py`
- 读取 `config["fuzz"]["targets"]`，解析 `module:function` 或 CLI 命令目标。
- 驱动 `vulnforge.fuzz.engine.FuzzEngine` 做变异模糊测试，收集崩溃并转为 finding。
- 未配置目标或 `scanners.fuzz=false` 时为空操作。
- 详见 [fuzzing.md](fuzzing.md)。

### 4. DependencyScanner（依赖/SBOM 扫描）

- 位置：`vulnforge/scanners/dependency.py`
- 识别 `requirements.txt`、`package.json`、`pom.xml`、`Cargo.lock`、`go.sum` 等清单。
- 离线模式产出 SBOM finding（`rule_id=dependency.package`，`severity=info`）。
- 在线模式额外查询 OSV.dev，命中 CVE 时产出 `dependency.cve.*` finding。
- 详见 [dependency-scan.md](dependency-scan.md)。

## 自定义扫描器

继承 `BaseScanner` 并用 `@register` 装饰即可：

```python
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.registry import register

@register
class MyScanner(BaseScanner):
    name = "my"
    def scan(self, targets, config):
        return []  # 返回 Finding 列表
```

## 执行隔离

`ScanEngine` 对每个扫描器用 `try/except` 包裹：单个扫描器抛异常不会拖垮整次扫描，仅记录错误日志，其它扫描器照常运行。
