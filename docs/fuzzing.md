# 模糊测试引擎

vulnforge 内置一个轻量级变异模糊测试引擎（`vulnforge.fuzz`），可对 Python 可调用对象或 CLI 命令做模糊测试，捕获崩溃并转为 finding。

## 核心组件

| 模块 | 职责 |
| --- | --- |
| `engine.FuzzEngine` | 驱动变异循环，收集崩溃 |
| `corpus.Corpus` | 种子语料库 |
| `mutator.mutate` | 字节级变异（位翻转/替换/插入/删除/字典拼接） |
| `crash.CrashCollector` | 崩溃记录与持久化 |
| `sanitizers.Sanitizer` | 崩溃分类（越界/栈溢出/断言等） |

## 直接使用 FuzzEngine

```python
from vulnforge.fuzz import FuzzEngine

def target(data: bytes):
    if data.startswith(b"\xff\xff"):
        raise ValueError("boom")   # 崩溃点

engine = FuzzEngine({"fuzz": {"max_iterations": 1000, "seed": 0}})
crashes = engine.fuzz(target, seeds=[b"hello"], iterations=1000)

for crash in crashes:
    print(crash.crash_type, crash.exc_type, crash.input_bytes[:16])
```

### FuzzEngine 参数

| 参数 | 说明 |
| --- | --- |
| `target_fn` | 接收 `bytes` 的可调用对象；抛异常即视为崩溃 |
| `seeds` | 初始种子（`List[bytes]`） |
| `iterations` | 迭代次数（默认取 `config["fuzz"]["max_iterations"]`） |
| `max_runtime` | 总时长上限（秒，超时抛 `FuzzTimeoutError`） |

### Crash 字段

| 字段 | 说明 |
| --- | --- |
| `input_bytes` | 触发崩溃的输入 |
| `crash_type` | 分类：`timeout/assertion/out-of-bounds/exception` |
| `exc_type` | 异常类型名 |
| `message` | 异常信息 |
| `iteration` | 触发迭代序号 |
| `traceback_text` | 堆栈文本 |

## 通过扫描器运行

`FuzzScanner` 从配置读取 fuzz 目标：

```yaml
fuzz:
  max_iterations: 2000
  max_runtime_seconds: 30
  crash_dir: ./.crash
  targets:
    - type: python_function
      value: "mypkg.parser:parse_input"   # module:function
      iterations: 500
    - type: cli
      value: "convert @@ out.png"          # @@ 被替换为临时输入文件
```

目标类型：

| type | 说明 |
| --- | --- |
| `python_function` | `module:function` 形式，导入并调用 |
| `cli` | shell 命令模板，`@@` 替换为临时输入文件路径，非零退出码视为崩溃 |

崩溃会转为 finding（`rule_id=fuzz.crash.<type>`，`scanner="fuzz"`，`cwe=CWE-20`），并持久化到 `crash_dir`。

## 变异策略

`mutate(data, rng)` 随机选择以下策略：

| 策略 | 说明 |
| --- | --- |
| 位翻转 | 翻转随机字节的一位 |
| 字节替换 | 替换随机字节 |
| 插入 | 插入字典 token（`\x00`、`../`、SQL payload 等） |
| 删除 | 删除 1-4 字节 |
| 字典拼接 | 在随机位置拼接 token |

## 可复现性

`config["fuzz"]["seed"]` 控制随机种子，设为固定值可复现崩溃。

```python
engine = FuzzEngine({"fuzz": {"seed": 42}})
```

## 使用建议

| 建议 | 说明 |
| --- | --- |
| 目标应确定性 | 避免随机/依赖外部状态的逻辑 |
| 合理设超时 | 防止单输入卡死 |
| 保存崩溃 | 复现时用 `crash.input_bytes` 重放 |
| 小步迭代 | 先少量迭代验证，再放大 |

## 完整示例

`examples/` 中无独立 fuzz 示例（需真实可执行目标），可直接用上面的最小 `target` 函数在 REPL 中体验，或参考 `tests/test_fuzz_engine.py`。
