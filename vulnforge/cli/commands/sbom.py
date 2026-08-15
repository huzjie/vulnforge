"""``vulnforge sbom``：生成 CycloneDX 风格 SBOM。

仅依赖标准库。从常见依赖清单（requirements.txt / package.json / go.mod /
Cargo.toml / pom.xml）中抽取组件。
"""

from __future__ import annotations

import json
import os
import re
from typing import Iterator, List


_MANIFEST_NAMES = {
    "requirements.txt",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def _iter_manifests(root: str) -> Iterator[str]:
    """遍历目录产出依赖清单文件路径。"""
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in _MANIFEST_NAMES:
                yield os.path.join(dirpath, fn)


def _component(ecosystem: str, name: str, version: str) -> dict:
    version = version.lstrip("^~v") or "unknown"
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}@{version}",
    }


def _parse_requirements(path: str) -> List[dict]:
    comps = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return comps
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=<>~!]=?|===)?\s*([A-Za-z0-9_.\-\+]+)?", line)
        if m:
            comps.append(_component("pypi", m.group(1), m.group(2) or "unknown"))
    return comps


def _parse_package_json(path: str) -> List[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    comps = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            comps.append(_component("npm", name, str(version)))
    return comps


def _parse_go_mod(path: str) -> List[dict]:
    comps = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return comps
    in_require = False
    for line in lines:
        s = line.strip()
        if s.startswith("require ("):
            in_require = True
            continue
        if in_require and s == ")":
            in_require = False
            continue
        if in_require or s.startswith("require "):
            m = re.match(r"^(?:require\s+)?(\S+)\s+(\S+)", s)
            if m:
                comps.append(_component("golang", m.group(1), m.group(2)))
    return comps


def _parse_cargo(path: str) -> List[dict]:
    comps = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return comps
    in_deps = False
    for line in lines:
        s = line.strip()
        if re.match(r"^\[.*dependencies.*\]", s):
            in_deps = True
            continue
        if s.startswith("["):
            in_deps = False
            continue
        if in_deps:
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*=\s*[\"']?([^\"'\s]+)", s)
            if m:
                comps.append(_component("cargo", m.group(1), m.group(2)))
    return comps


def _parse_pom(path: str) -> List[dict]:
    comps = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return comps
    pattern = re.compile(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>"
    )
    for m in pattern.finditer(text):
        g, a, v = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        comps.append({"type": "library", "name": f"{g}:{a}", "version": v,
                      "purl": f"pkg:maven/{g}/{a}@{v}"})
    return comps


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Cargo.toml": _parse_cargo,
    "pom.xml": _parse_pom,
}


def cmd_sbom(args) -> int:
    """生成 SBOM 并写入 JSON 文件。"""
    components: List[dict] = []
    for path in args.paths:
        for manifest in _iter_manifests(path):
            parser = _PARSERS.get(os.path.basename(manifest))
            if parser:
                components.extend(parser(manifest))

    # 去重（按 purl）。
    seen = set()
    unique = []
    for comp in components:
        key = comp.get("purl") or (comp.get("name"), comp.get("version"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": unique,
    }
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(sbom, fh, indent=2, ensure_ascii=False)
    print(f"已写入 SBOM: {args.output}（{len(unique)} 个组件）")
    return 0
