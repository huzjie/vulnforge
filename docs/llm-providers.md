# LLM Provider 接入指南

vulnforge 的 `llm` 扫描器通过 provider 抽象调用大模型做漏洞推理。provider 均实现统一的 `complete(prompt, system="") -> str` 接口。

## 内置 Provider

| 类型 | 类 | 说明 |
| --- | --- | --- |
| `mock` | `MockProvider` | 离线确定性输出，无需网络/Key |
| `openai_compat` | `OpenAICompatProvider` | 兼容 OpenAI `/chat/completions` 的任何服务 |
| `anthropic` | `AnthropicProvider` | Anthropic Claude |
| `gemini` | `GeminiProvider` | Google Gemini |
| `ollama` | `OllamaProvider` | 本地 Ollama |

查看已注册 provider：

```python
from vulnforge.llm import list_providers, get_provider
list_providers()          # ['anthropic', 'gemini', 'mock', 'ollama', 'openai_compat']
get_provider("mock", {})  # 返回 MockProvider 实例
```

## 主流模型配置

### 智谱 GLM-5.3

```yaml
llm:
  default_provider: glm
  providers:
    glm:
      type: openai_compat
      base_url: https://open.bigmodel.cn/api/paas/v4
      model: glm-5.3
      api_key: ""
```

```bash
export GLM_API_KEY=your-zhipu-key
```

### DeepSeek

```yaml
llm:
  default_provider: deepseek
  providers:
    deepseek:
      type: openai_compat
      base_url: https://api.deepseek.com/v1
      model: deepseek-v4-pro
```

```bash
export DEEPSEEK_API_KEY=your-key
```

### 通义千问 Qwen

```yaml
llm:
  default_provider: qwen
  providers:
    qwen:
      type: openai_compat
      base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
      model: qwen3.8-max
```

```bash
export QWEN_API_KEY=your-key
```

### OpenAI

```yaml
llm:
  default_provider: openai
  providers:
    openai:
      type: openai_compat
      base_url: https://api.openai.com/v1
      model: gpt-4.1
```

```bash
export OPENAI_API_KEY=your-key
```

### Anthropic

```yaml
llm:
  providers:
    claude:
      type: anthropic
      model: claude-fable-5
```

```bash
export ANTHROPIC_API_KEY=your-key
```

### Gemini

```yaml
llm:
  providers:
    gemini:
      type: gemini
      model: gemini-3.7-flash
```

```bash
export GEMINI_API_KEY=your-key
```

### 本地 Ollama

```yaml
llm:
  default_provider: ollama
  providers:
    ollama:
      type: ollama
      base_url: http://localhost:11434
      model: llama3.1
```

## API Key 环境变量解析顺序

provider 的 `api_key` 留空时，`OpenAICompatProvider` 按序读取：

```
OPENAI_API_KEY → GLM_API_KEY → DEEPSEEK_API_KEY → QWEN_API_KEY
→ ANTHROPIC_API_KEY → GEMINI_API_KEY
```

## LLM 扫描器工作机制

`LLMReasoningScanner`：

1. 读取 `config["llm"]`，确定 `default_provider`。
2. 扁平化配置：顶层 `llm` 设置 + 所选 provider 的字段合并。
3. 用 `get_provider(provider_type, provider_cfg)` 实例化 provider。
4. 将每个文件按 `chunk_lines`（默认 400）切块，逐块发送：

```text
系统提示：要求只输出 JSON 数组，字段包含 rule_id/title/description/
severity/cwe/cvss/line/code/recommendation/references/tags
```

5. 对返回做**容错解析**：
   - 剥离 ` ```json ... ``` ` 围栏；
   - 截取首个 `[` 到末个 `]`；
   - `json.loads`，失败返回空；
   - 单对象自动包装为数组。
6. 将 JSON 项映射为 `Finding`（`scanner="llm"`）。
   - `severity` 无法识别时回退 `medium`；
   - 若模型给出 `cvss` 向量，则用 CVSS 分数重新推导严重度。

## 容错与降级

- provider 未知/实例化失败 → 记录警告并返回空（不中断扫描）。
- provider 调用失败（网络/鉴权）→ 记录警告并跳过该文件。
- 模型输出无法解析 → 该块产出 0 条 finding。

## 自定义 provider

实现 `BaseProvider` 并注册到 `vulnforge.llm.PROVIDERS`：

```python
from vulnforge.llm.base import BaseProvider
from vulnforge.llm import PROVIDERS

class MyProvider(BaseProvider):
    name = "my"
    def complete(self, prompt, system=""):
        return '[{"rule_id": "x", "severity": "low"}]'

PROVIDERS["my"] = MyProvider
```

## 建议

| 场景 | 建议 |
| --- | --- |
| CI / 离线 / 演示 | `mock` |
| 成本敏感 | DeepSeek |
| 中文安全推理强 | GLM-5.3 |
| 本地隐私 | Ollama |
| 通用质量 | Qwen / GPT |
