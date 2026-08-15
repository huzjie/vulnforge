# 静态规则详解

静态规则是 vulnforge 的基石：用正则表达式匹配源码中的可疑模式，产出带 CWE 编号的 `Finding`。

## 规则模型

`StaticRule`（`vulnforge/scanners/static/rule.py`）字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | str | 规则 id（如 `sql-query-concat`） |
| `title` | str | 标题 |
| `description` | str | 描述 |
| `severity` | str | 严重度（`info`..`critical`） |
| `patterns` | list[str] | 正则列表（命中任一即触发） |
| `cwe` | str | CWE 编号（可为空） |
| `recommendation` | str | 修复建议 |
| `extensions` | list\|None | 限定扩展名（`None` = 全语言） |
| `multiline` | bool | `True` 时整文件匹配 |
| `flags` | int | 正则标志（默认 `re.IGNORECASE`） |

## 规则类别与文件

规则库位于 `vulnforge/scanners/static/rules/`，按类别拆分：

| 模块 | 类别 | 主要 CWE |
| --- | --- | --- |
| `secrets.py` | 硬编码密钥/凭据 | CWE-798 |
| `sql_injection.py` | SQL 注入 | CWE-89 |
| `xss.py` | 跨站脚本 | CWE-79 |
| `command_injection.py` | 命令注入 | CWE-78 |
| `path_traversal.py` | 路径穿越 | CWE-22 |
| `crypto.py` | 弱加密算法 | CWE-327/326 |
| `deserialization.py` | 不安全反序列化 | CWE-502 |
| `ssrf.py` | 服务端请求伪造 | CWE-918 |
| `auth.py` | 认证/授权缺陷 | CWE-287 等 |
| `injection_other.py` | 其它注入 | 多种 |
| `code_quality.py` | 代码质量 | 无/一般 |
| `cpp_memory.py` | C/C++ 内存缺陷 | CWE-120/787 等 |
| `go_rules.py` | Go 语言规则 | 多种 |
| `java_rules.py` | Java 语言规则 | 多种 |
| `python_rules.py` | Python 语言规则 | 多种 |

聚合入口 `rules/__init__.py` 提供：

```python
from vulnforge.scanners.static.rules import RULES, register_all
RULES          # List[StaticRule] 全部规则
register_all() # 幂等返回 RULES
```

## 规则 id 速查表

### SQL 注入（CWE-89）

| rule_id | 说明 |
| --- | --- |
| `sql-string-concat` | SQL 字符串拼接 |
| `sql-fstring` | f-string 插值 SQL |
| `sql-execute-concat` | `execute()` 拼接 SQL |
| `sql-format-method` | `.format()` / `%` 构造 SQL |
| `sql-query-concat` | `query = "..." +` 拼接 |

### XSS（CWE-79）

| rule_id | 说明 |
| --- | --- |
| `xss-innerhtml` | `innerHTML=` 赋值 |
| `xss-document-write` | `document.write()` |
| `xss-dangerously-set-inner-html` | React `dangerouslySetInnerHTML` |
| `xss-insert-adjacent-html` | `insertAdjacentHTML()` |
| `xss-unescaped-output` | `v-html` / `<%=` / `|safe` 未转义输出 |

### 命令注入（CWE-78）

| rule_id | 说明 |
| --- | --- |
| `cmd-os-system` | `os.system()` 拼接 |
| `cmd-subprocess-shell` | `shell=True` |
| `cmd-subprocess-concat` | subprocess 拼接命令 |
| `cmd-exec` | `exec()` 执行 |
| `cmd-popen-shell` | `os.popen()` 拼接 |

### 路径穿越（CWE-22）

| rule_id | 说明 |
| --- | --- |
| `path-traversal-open-concat` | `open()` 拼接路径 |
| `path-traversal-join-input` | `os.path.join` 拼接用户输入 |
| `path-traversal-dotdot` | `../` / `..\` 序列 |
| `path-traversal-send-file` | `send_file` 用户输入 |
| `path-traversal-file-read` | 文件读取 API 用户输入 |

### 弱加密（CWE-327/326）

| rule_id | 说明 |
| --- | --- |
| `crypto-md5` | MD5 使用 |
| `crypto-sha1` | SHA-1 使用 |
| `crypto-des` | DES / 3DES |
| `crypto-rc4` | RC4 |
| `crypto-ecb-mode` | ECB 分组模式 |
| `crypto-fixed-iv` | 硬编码 IV |

### 反序列化（CWE-502）

| rule_id | 说明 |
| --- | --- |
| `deser-pickle-load` | `pickle.load/loads` |
| `deser-yaml-load` | 不安全 `yaml.load` |
| `deser-eval` | `eval()` |
| `deser-marshal` | `marshal.load/loads` |
| `deser-java-objectinput` | Java 原生反序列化 |
| `deser-jsonpickle` | `jsonpickle` 解码 |

### SSRF（CWE-918）

| rule_id | 说明 |
| --- | --- |
| `ssrf-requests-get` | `requests.*` 用户 URL |
| `ssrf-urllib` | `urlopen` 用户 URL |
| `ssrf-http-client` | HTTP 客户端用户 URL |
| `ssrf-url-concat` | URL 拼接构造 |

### 密钥（CWE-798）

| rule_id | 说明 |
| --- | --- |
| `secrets-aws-access-key` | AWS Access Key ID（`AKIA...`） |
| `secrets-aws-secret-key` | AWS Secret Key 赋值 |
| `secrets-github-token` | GitHub Token（`ghp_/gho_/github_pat_`） |
| `secrets-google-api-key` | Google API Key（`AIza...`） |
| `secrets-slack-token` | Slack Token（`xox...`） |
| `secrets-stripe-key` | Stripe live key（`sk_live_`） |
| `secrets-private-key` | PEM 私钥块 |
| `secrets-ssh-private-key` | OpenSSH 私钥块 |
| `secrets-password-assignment` | `password/secret/token = "..."` |
| `secrets-jwt` | JWT Token（`eyJ...`） |
| `secrets-npm-auth-token` | npm `_authToken` |
| `secrets-twilio` | Twilio SID/Token |
| `secrets-sendgrid` | SendGrid Key（`SG.`） |
| `secrets-heroku` | Heroku Key |
| `secrets-generic-api-key` | 通用 `api_key/secret_key` 赋值 |

## 编写自定义规则

1. 创建 `StaticRule`：

```python
from vulnforge.scanners.static.rule import StaticRule

rule = StaticRule(
    id="custom-no-print",
    title="Avoid print() in library code",
    description="print() 会泄露到 stdout，可能遗留在生产代码中。",
    severity="low",
    patterns=[r"\bprint\s*\("],
    recommendation="改用 logger。",
    extensions=[".py"],
)
```

2. 追加到 `RULES` 并（可选）调用 `register_all()`：

```python
from vulnforge.scanners.static.rules import RULES, register_all

RULES.append(rule)
register_all()
```

3. 用 `StaticScanner` 扫描：

```python
from vulnforge.scanners.static.scanner import StaticScanner
from vulnforge.models import Target

scanner = StaticScanner()
findings = scanner.scan([Target(path="a.py", kind="file")], config={})
```

完整示例见 `examples/custom_rule.py`。

## 注意事项

- 正则默认 `re.IGNORECASE`，`flags=0` 可关闭。
- `extensions` 用于限定语言（如 `.java` 专属规则）。
- `multiline=True` 用于跨行模式（如 XML 依赖块）。
- 匹配逐行进行（除 `multiline`），一行命中一个规则产出多条 finding。
