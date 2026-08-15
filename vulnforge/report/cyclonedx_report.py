"""CycloneDX 1.5 SBOM renderer.

Builds a CycloneDX BOM from the SBOM findings produced by the dependency
scanner (findings tagged ``sbom``), extracting package/version/ecosystem/purl
from each finding's ``raw`` payload.
"""

import json
import time
import uuid
from typing import Any, Dict, List

_SPEC_VERSION = "1.5"


def _components(report) -> List[Dict[str, Any]]:
    findings = list(getattr(report, "findings", []) or [])
    seen = set()
    components: List[Dict[str, Any]] = []
    for f in findings:
        tags = list(getattr(f, "tags", []) or [])
        if "sbom" not in tags:
            continue
        raw = getattr(f, "raw", {}) or {}
        if not isinstance(raw, dict):
            continue
        package = raw.get("package") or ""
        version = raw.get("version") or ""
        if not package:
            continue
        key = (package, version)
        if key in seen:
            continue
        seen.add(key)
        purl = raw.get("purl") or ""
        component: Dict[str, Any] = {
            "type": "library",
            "name": package,
            "version": version,
        }
        if purl:
            component["purl"] = purl
        components.append(component)
    return components


def _metadata(report) -> Dict[str, Any]:
    """Build deterministic metadata (stable serial number + timestamp)."""
    scan_id = str(getattr(report, "scan_id", "") or "")
    serial = str(uuid.uuid5(uuid.NAMESPACE_URL, "vulnforge:" + scan_id))
    created_at = str(getattr(report, "created_at", "") or "")
    if not created_at:
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "timestamp": created_at,
        "tools": [
            {"vendor": "vulnforge", "name": "vulnforge", "version": "1.0.0"}
        ],
        "component": {
            "type": "application",
            "name": "vulnforge-scan-target",
            "bom-ref": "pkg:generic/vulnforge-scan-target",
        },
    }


def render(report) -> str:
    """Render ``report`` as a CycloneDX 1.5 SBOM JSON string."""
    components = _components(report)
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'vulnforge:' + str(getattr(report, 'scan_id', '') or ''))}",
        "version": 1,
        "metadata": _metadata(report),
        "components": components,
    }
    return json.dumps(document, ensure_ascii=False, indent=2)
