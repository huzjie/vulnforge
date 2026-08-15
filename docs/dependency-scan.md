# SBOM 与依赖 CVE 扫描

`DependencyScanner` 识别项目依赖清单，构建 SBOM，并可（在线时）查询已知 CVE。

## 支持的清单文件

| 文件 | 生态 | OSV 生态名 |
| --- | --- | --- |
| `requirements.txt` | Python | `PyPI` |
| `Pipfile.lock` | Python | `PyPI` |
| `poetry.lock` | Python | `PyPI` |
| `package.json` | Node | `npm` |
| `package-lock.json` | Node | `npm` |
| `yarn.lock` | Node | `npm` |
| `Cargo.lock` | Rust | `crates.io` |
| `go.sum` | Go | `Go` |
| `pom.xml` | Maven | `Maven` |

## 离线模式（默认）

`dependency.offline=true` 时，扫描器**不联网**，仅为每个包产出 SBOM finding：

```python
Finding(
    rule_id="dependency.package",
    title="依赖: requests@2.31.0 (PyPI)",
    severity=Severity.INFO,
    scanner="dependency",
    raw={
        "package": "requests",
        "version": "2.31.0",
        "ecosystem": "PyPI",
        "purl": "pkg:pypi/requests@2.31.0",
        "pending_osv": True,   # 待在线查询
    },
)
```

## 在线模式（CVE 查询）

`dependency.offline=false` 时，对每个包查询 OSV.dev：

```yaml
dependency:
  offline: false
  osv_endpoint: https://api.osv.dev/v1/query
```

命中漏洞时产出：

```python
Finding(
    rule_id="dependency.cve.cve-2021-44228",
    severity=...,   # 由 CVSS 推导
    cwe="CWE-502",
    cvss="CVSS:3.1/...",
    scanner="dependency",
)
```

严重度推导优先级：OSV severity（CVSS）→ 内置 CVE 库（`db/cve.py`）→ `medium` 回退。

## 内置 CVE 库

`vulnforge.db.cve.CVEDB` 内置精选高危 CVE（如 Log4Shell CVE-2021-44228、Struts2 CVE-2017-5638），用于离线时丰富报告元数据。

```python
from vulnforge.db.cve import CVEDB
db = CVEDB()
rec = db.lookup("CVE-2021-44228")
# {'id': ..., 'severity': 'CRITICAL', 'cvss': 10.0, ...}
```

## SBOM 导出

依赖扫描产出的 SBOM finding（`tags` 含 `sbom`）可由 CycloneDX 渲染器导出为标准 SBOM：

```python
from vulnforge.report import write
write(report, "cyclonedx", "./sbom.json")
```

CLI 提供 `sbom` 子命令直接生成 SBOM：

```bash
vulnforge sbom . -o sbom.json --ecosystem auto
```

## 编程示例

```python
from vulnforge.models import Target
from vulnforge.scanners.dependency import DependencyScanner

scanner = DependencyScanner()
target = Target(path="requirements.txt", kind="file")
findings = scanner.scan([target], {"dependency": {"offline": True}})
for f in findings:
    print(f.raw["package"], f.raw["version"], f.raw["purl"])
```

## OSV 客户端

`vulnforge.db.osv.OSVClient` 提供离线优先的 OSV 查询：

- 命中缓存直接返回；
- `offline=true` 时跳过网络；
- 网络异常静默返回空列表，不中断扫描。

## 注意事项

- 版本范围（`>=`、`~=`）只解析基准版本号，不做精确范围匹配。
- `pom.xml` 含 `${property}` 占位符的依赖会被跳过。
- 离线模式只产出 SBOM，不产出 CVE finding。
