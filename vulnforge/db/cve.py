"""Built-in CVE knowledge base.

:class:`CVEDB` ships a small, curated set of well-known CVE records so the
dependency scanner and report renderers can produce enriched output even when
fully offline.  Records are keyed by CVE id and include severity, a CVSS 3.1
vector/score, CWE id, a description and affected packages.
"""

from typing import Any, Dict, Optional


class CVEDB:
    """Static in-memory CVE database."""

    def __init__(self) -> None:
        self._records: Dict[str, Dict[str, Any]] = {
            rec["id"]: rec for rec in _BUILTIN_CVES
        }

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Return the record for ``cve_id`` (case-insensitive) or ``None``."""
        if not cve_id:
            return None
        return self._records.get(cve_id.upper())

    def all(self) -> Dict[str, Dict[str, Any]]:
        """Return a copy of the full CVE table."""
        return dict(self._records)

    def __len__(self) -> int:
        return len(self._records)


_BUILTIN_CVES = [
    {
        "id": "CVE-2021-44228",
        "summary": "Log4Shell: JNDI lookup RCE in Apache Log4j2",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "description": "Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features do not "
        "protect against attacker-controlled LDAP/JNDI lookups, enabling remote code execution.",
        "affected": [{"package": "log4j-core", "ecosystem": "Maven"},
                     {"package": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    {
        "id": "CVE-2017-5638",
        "summary": "Struts2 Jakarta multipart parser RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "description": "The Jakarta Multipart parser in Apache Struts2 mishandles "
        "file upload error handling, allowing remote code execution via a crafted Content-Type header.",
        "affected": [{"package": "struts2-core", "ecosystem": "Maven"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    },
    {
        "id": "CVE-2021-33503",
        "summary": "ReDoS in urllib3 due to catastrophic backtracking",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "description": "urllib3 prior to 1.26.5 mishandles URL authority components, "
        "allowing a denial of service via a crafted URL causing excessive backtracking.",
        "affected": [{"package": "urllib3", "ecosystem": "PyPI"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33503"],
    },
    {
        "id": "CVE-2024-3094",
        "summary": "Malicious backdoor in XZ Utils (liblzma)",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-506",
        "description": "Malicious code embedded in XZ Utils 5.6.0/5.6.1 liblzma "
        "interferes with sshd authentication, enabling remote code execution.",
        "affected": [{"package": "xz", "ecosystem": "Debian"},
                     {"package": "xz-utils", "ecosystem": "PyPI"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
    },
    {
        "id": "CVE-2021-34527",
        "summary": "PrintNightmare Windows Print Spooler RCE",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "description": "Windows Print Spooler service fails to restrict access to "
        "RpcAddPrinterDriverEx, allowing remote code execution with SYSTEM privileges.",
        "affected": [{"package": "windows", "ecosystem": "Microsoft"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
    },
    {
        "id": "CVE-2023-4863",
        "summary": "Heap buffer overflow in libwebp (WebP)",
        "severity": "HIGH",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cwe": "CWE-787",
        "description": "Heap buffer overflow in libwebp's Huffman coding allows "
        "remote code execution when processing a crafted WebP image.",
        "affected": [{"package": "libwebp", "ecosystem": "Debian"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"],
    },
    {
        "id": "CVE-2022-22965",
        "summary": "Spring4Shell RCE in Spring Framework",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "description": "Spring Framework 5.3.0-5.3.17 allows remote code execution "
        "via data binding on JDK 9+ when running on Tomcat as a WAR deployment.",
        "affected": [{"package": "spring-beans", "ecosystem": "Maven"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    },
    {
        "id": "CVE-2021-41773",
        "summary": "Apache HTTP Server path traversal / RCE",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-22",
        "description": "Path traversal flaw in Apache HTTP Server 2.4.49 allows "
        "URLs to be mapped to files outside the document root, and in some cases code execution.",
        "affected": [{"package": "apache2", "ecosystem": "Debian"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    {
        "id": "CVE-2014-0160",
        "summary": "Heartbleed OpenSSL information disclosure",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "description": "A missing bounds check in OpenSSL's TLS heartbeat extension "
        "allows reading up to 64KB of adjacent memory from a vulnerable server.",
        "affected": [{"package": "openssl", "ecosystem": "Debian"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
    },
    {
        "id": "CVE-2017-0144",
        "summary": "EternalBlue SMBv1 remote code execution",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "description": "The SMBv1 server in Microsoft Windows mishandles crafted "
        "packets, allowing remote code execution (used by WannaCry).",
        "affected": [{"package": "windows", "ecosystem": "Microsoft"}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
]
