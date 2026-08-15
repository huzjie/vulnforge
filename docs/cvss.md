# CVSS 3.1 评分说明

vulnforge 实现了 CVSS v3.1 基评分（Base Score）算法，用于把漏洞严重度量化到 0.0-10.0。

## 核心 API

```python
from vulnforge.cvss.calculator import score_cvss31, severity_from_cvss, parse_vector

score_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # 9.8
severity_from_cvss(9.8)                               # "critical"
parse_vector("AV:N/AC:L")                             # {"AV": "N", "AC": "L"}
```

## 评分公式

### 影响子分数（ISC）

```
ISC_Base = 1 - (1 - C) × (1 - I) × (1 - A)

Scope = U:  Impact = 6.42 × ISC_Base
Scope = C:  Impact = 7.52 × (ISC_Base - 0.029) - 3.25 × (ISC_Base - 0.02)^15
```

### 可利用性（Exploitability）

```
Exploitability = 8.22 × AV × AC × PR × UI
```

### 基分数（Base）

```
Impact <= 0            -> 0.0
Scope = U: Base = Roundup(min(Impact + Exploitability, 10))
Scope = C: Base = Roundup(min(1.08 × (Impact + Exploitability), 10))
```

`Roundup` 向上取整到 0.1。

## 度量权重表

| 度量 | 值 | 权重 |
| --- | --- | --- |
| AV（攻击向量） | N / A / L / P | 0.85 / 0.62 / 0.55 / 0.2 |
| AC（攻击复杂度） | L / H | 0.77 / 0.44 |
| PR（所需权限） | N / L / H | 0.85 / 0.62(U)·0.68(C) / 0.27(U)·0.5(C) |
| UI（用户交互） | N / R | 0.85 / 0.62 |
| C/I/A（影响） | H / L / N | 0.56 / 0.22 / 0.0 |

## 已知向量对照

| 向量 | 分数 | 定性 |
| --- | --- | --- |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | Critical |
| `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 | High |
| `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 | Critical |
| `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 | High |
| `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | 5.4 | Medium |
| `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N` | 0.0 | None |

## 定性映射

`severity_from_cvss(score)`：

| 分数区间 | 定性 |
| --- | --- |
| `None` 或 `<= 0.0` | `none` |
| `0.0 < score < 4.0` | `low` |
| `4.0 <= score < 7.0` | `medium` |
| `7.0 <= score < 9.0` | `high` |
| `>= 9.0` | `critical` |

> 注意：`Severity.from_score()`（models 层）与 `severity_from_cvss()`（cvss 层）的 0 分映射不同：前者返回 `Severity.INFO`，后者返回字符串 `"none"`。

## 向量解析

`parse_vector` 忽略未知段与 `CVSS:3.1/` 前缀，仅识别 8 个基度量：

```python
parse_vector("CVSS:3.1/AV:N/FOO:x/AC:H")
# {"AV": "N", "AC": "H"}   # FOO:x 被忽略
```

缺失度量回退到「最坏情况」默认值（`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`），因此空向量得 9.8。

## 在 LLM / 依赖扫描中的应用

- LLM 扫描器：模型返回 `cvss` 向量时，用 `score_cvss31` 计算分数并重推导严重度。
- 依赖扫描器：OSV 记录的 CVSS 向量用于推导 CVE finding 严重度。
