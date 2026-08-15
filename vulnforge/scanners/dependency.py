"""Dependency / SBOM scanner.

Identifies dependency manifest files (requirements.txt, Pipfile.lock,
poetry.lock, package.json, package-lock.json, yarn.lock, Cargo.lock, go.sum,
pom.xml), parses ``package@version`` pairs, and emits SBOM findings.  In
offline mode (default) packages are only marked as pending OSV lookup; when
online, each package is queried against OSV.dev and known CVEs are emitted as
findings (severity derived from CVSS, with a built-in CVE DB fallback).
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from vulnforge.cvss.calculator import score_cvss31, severity_from_cvss
from vulnforge.db.cve import CVEDB
from vulnforge.db.osv import OSVClient
from vulnforge.models import Finding, Severity
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.registry import register

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "none": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Manifest basename -> ecosystem (OSV ecosystem name).
_MANIFEST_ECOSYSTEM = {
    "requirements.txt": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "Cargo.lock": "crates.io",
    "go.sum": "Go",
    "pom.xml": "Maven",
}

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(===|==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.\-\+]+)")
_GO_SUM = re.compile(r"^(\S+)\s+(v\d[^\s/]*)\s+")
_TOML_PKG_HEAD = re.compile(r"^\[\[package\]\]")
_TOML_KV = re.compile(r"^(\w+)\s*=\s*\"([^\"]*)\"")
_YARN_HEAD = re.compile(r"^\"?(@?[^\"@\n]+)@[^:\n]+:")
_YARN_VERSION = re.compile(r"^\s*version\s+\"([^\"]+)\"")
_POM_DEP = re.compile(
    r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>"
    r"\s*<version>([^<]+)</version>", re.DOTALL
)


def _to_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    if value is None:
        return Severity.MEDIUM
    return _SEVERITY_MAP.get(str(value).strip().lower(), Severity.MEDIUM)


def _purl(package: str, version: str, ecosystem: str) -> str:
    """Construct a Package URL from package/version/ecosystem."""
    if ecosystem == "PyPI":
        return f"pkg:pypi/{package}@{version}"
    if ecosystem == "npm":
        return f"pkg:npm/{package}@{version}"
    if ecosystem == "Maven":
        if ":" in package:
            group, artifact = package.split(":", 1)
            return f"pkg:maven/{group}/{artifact}@{version}"
        return f"pkg:maven/{package}@{version}"
    if ecosystem == "Go":
        return f"pkg:golang/{package}@{version}"
    if ecosystem == "crates.io":
        return f"pkg:cargo/{package}@{version}"
    return f"pkg:generic/{package}@{version}"


# --- parsers ----------------------------------------------------------------

def _parse_requirements(text: str) -> List[Tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            out.append((m.group(1), m.group(3)))
    return out


def _parse_pipfile_lock(text: str) -> List[Tuple[str, str]]:
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    out = []
    for section in ("default", "develop"):
        for name, meta in (obj.get(section, {}) or {}).items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version", ""))
            version = version.lstrip("=><~!")
            if version:
                out.append((name, version))
    return out


def _parse_poetry_lock(text: str) -> List[Tuple[str, str]]:
    return _parse_toml_packages(text)


def _parse_cargo_lock(text: str) -> List[Tuple[str, str]]:
    return _parse_toml_packages(text)


def _parse_toml_packages(text: str) -> List[Tuple[str, str]]:
    out = []
    in_package = False
    name = None
    for line in text.splitlines():
        if _TOML_PKG_HEAD.match(line.strip()):
            if in_package and name:
                pass  # handled on version capture
            in_package = True
            name = None
            version = None
            continue
        if in_package:
            if line.strip() == "" or line.strip().startswith("["):
                in_package = False
                continue
            m = _TOML_KV.match(line.strip())
            if m:
                key, value = m.group(1), m.group(2)
                if key == "name":
                    name = value
                elif key == "version":
                    version = value
                    if name:
                        out.append((name, version))
    return out


def _parse_package_json(text: str) -> List[Tuple[str, str]]:
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (obj.get(section, {}) or {}).items():
            out.append((name, str(version).lstrip("^~>=<")))
    return out


def _parse_package_lock(text: str) -> List[Tuple[str, str]]:
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    out = []
    # npm v7+ format: "packages": {"": {...}, "node_modules/foo": {"version": "1.0"}}
    packages = obj.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = (meta.get("name") or path.rsplit("node_modules/", 1)[-1]).strip()
            version = str(meta.get("version") or "")
            if name and version:
                out.append((name, version))
        if out:
            return out
    # npm v6 format: nested "dependencies"
    for _, meta in (obj.get("dependencies", {}) or {}).items():
        if isinstance(meta, dict):
            name = meta.get("name") or ""
            version = str(meta.get("version") or "")
            if name and version:
                out.append((name, version))
    return out


def _parse_yarn_lock(text: str) -> List[Tuple[str, str]]:
    out = []
    current = None
    for line in text.splitlines():
        head = _YARN_HEAD.match(line)
        if head:
            current = head.group(1).strip()
            continue
        if current is not None and line.strip() == "":
            current = None
            continue
        if current is not None:
            m = _YARN_VERSION.match(line)
            if m:
                out.append((current, m.group(1)))
                current = None
    return out


def _parse_go_sum(text: str) -> List[Tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = _GO_SUM.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_pom(text: str) -> List[Tuple[str, str]]:
    out = []
    for m in _POM_DEP.finditer(text):
        group, artifact, version = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        if "${" in version:  # property placeholder, skip
            continue
        out.append((f"{group}:{artifact}", version))
    return out


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "Pipfile.lock": _parse_pipfile_lock,
    "poetry.lock": _parse_poetry_lock,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "Cargo.lock": _parse_cargo_lock,
    "go.sum": _parse_go_sum,
    "pom.xml": _parse_pom,
}


def _osv_cvss(vuln: Dict[str, Any]) -> Optional[float]:
    """Return the numeric CVSS 3.x base score from an OSV record, if any."""
    for entry in vuln.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if isinstance(score, str) and score.startswith("CVSS:"):
            try:
                return score_cvss31(score)
            except Exception:
                continue
        if isinstance(score, (int, float)):
            return float(score)
    return None


def _osv_severity(vuln: Dict[str, Any]) -> Optional[str]:
    """Best-effort severity string from an OSV vulnerability record."""
    score = _osv_cvss(vuln)
    if score is not None:
        try:
            return severity_from_cvss(score)
        except Exception:
            pass
    ds = vuln.get("database_specific", {}) or {}
    sev = ds.get("severity")
    if sev:
        return str(sev).upper()
    return None


def _first_cve(vuln: Dict[str, Any]) -> Optional[str]:
    for alias in vuln.get("aliases", []) or []:
        if str(alias).upper().startswith("CVE-"):
            return str(alias).upper()
    return None


@register
class DependencyScanner(BaseScanner):
    """Parse dependency manifests, build SBOM, and (optionally) query CVEs."""

    name = "dependency"

    def scan(self, targets, config: Dict[str, Any]) -> List[Finding]:
        dep_cfg: Dict[str, Any] = config.get("dependency", {}) or {}
        offline = bool(dep_cfg.get("offline", True))
        cve_db = CVEDB()

        findings: List[Finding] = []
        for _target, file_path in self._iter_files(targets):
            file_path = str(file_path)
            basename = os.path.basename(file_path)
            if basename not in _PARSERS:
                continue
            ecosystem = _MANIFEST_ECOSYSTEM[basename]
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as exc:
                logger.warning("Dependency scanner: cannot read %s: %s", file_path, exc)
                continue

            packages = _PARSERS[basename](text)
            if not packages:
                continue

            for package, version in packages:
                findings.append(
                    self._sbom_finding(str(file_path), package, version, ecosystem, offline)
                )

            if not offline:
                findings.extend(
                    self._query_vulns(str(file_path), packages, ecosystem, dep_cfg, cve_db)
                )

        return findings

    def _sbom_finding(self, file_path: str, package: str, version: str,
                      ecosystem: str, offline: bool) -> Finding:
        note = "待 OSV 查询" if offline else "已纳入 SBOM"
        return Finding(
            rule_id="dependency.package",
            title=f"依赖: {package}@{version} ({ecosystem})",
            description=f"识别到依赖 {package}@{version}（生态 {ecosystem}），{note}。",
            severity=Severity.INFO,
            file_path=file_path,
            line=0,
            column=0,
            code="",
            cwe="",
            cvss=None,
            confidence=1.0,
            scanner="dependency",
            recommendation="上线前通过 OSV / 漏洞库核对该版本的已知漏洞。",
            references=[],
            tags=["sbom", "dependency"],
            raw={
                "package": package,
                "version": version,
                "ecosystem": ecosystem,
                "purl": _purl(package, version, ecosystem),
                "pending_osv": offline,
            },
        )

    def _query_vulns(self, file_path: str, packages: List[Tuple[str, str]],
                     ecosystem: str, dep_cfg: Dict[str, Any],
                     cve_db: CVEDB) -> List[Finding]:
        client = OSVClient({"dependency": dep_cfg})
        specs = [
            {"package": p, "version": v, "ecosystem": ecosystem}
            for p, v in packages
        ]
        findings: List[Finding] = []
        for result in client.query_batch(specs):
            for vuln in result.get("vulns", []) or []:
                findings.append(
                    self._vuln_finding(file_path, result, vuln, cve_db)
                )
        return findings

    def _vuln_finding(self, file_path: str, pkg: Dict[str, Any],
                      vuln: Dict[str, Any], cve_db: CVEDB) -> Finding:
        cve_id = _first_cve(vuln) or str(vuln.get("id", "OSV"))
        summary = vuln.get("summary") or ""
        details = vuln.get("details") or summary

        severity_name = _osv_severity(vuln)
        cvss_score = _osv_cvss(vuln)
        cwe = ""

        # Fall back to the built-in CVE DB for enriched metadata.
        known = cve_db.lookup(cve_id) if cve_id.startswith("CVE-") else None
        if known:
            if severity_name is None:
                severity_name = known.get("severity")
            if not cwe:
                cwe = known.get("cwe", "")
            if cvss_score is None:
                cvss_score = known.get("cvss")
            if not summary:
                summary = known.get("summary", "")

        severity = _to_severity(severity_name)

        references = vuln.get("references", []) or []
        if known:
            references = references + (known.get("references", []) or [])

        return Finding(
            rule_id=f"dependency.cve.{cve_id.lower()}",
            title=f"{cve_id}: {summary or details[:120]}",
            description=details or summary,
            severity=severity,
            file_path=file_path,
            line=0,
            column=0,
            code="",
            cwe=cwe,
            cvss=cvss_score,
            confidence=1.0,
            scanner="dependency",
            recommendation="升级到已修复版本，或参考官方安全公告采取缓解措施。",
            references=list(references),
            tags=["cve", "dependency"],
            raw={
                "package": pkg.get("package"),
                "version": pkg.get("version"),
                "ecosystem": pkg.get("ecosystem"),
                "vuln": vuln,
            },
        )
