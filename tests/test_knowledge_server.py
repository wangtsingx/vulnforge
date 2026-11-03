
from vulnforge.mcp_servers.knowledge_server import CVE_RE, CWE_RE


def test_cve_regex():
    assert CVE_RE.fullmatch("CVE-2024-12345")
    assert not CVE_RE.fullmatch("cve-2024-12345")
    assert not CVE_RE.fullmatch("CVE-2024-123")


def test_cwe_regex():
    assert CWE_RE.fullmatch("CWE-120")
    assert not CWE_RE.fullmatch("cwe-120")
    assert not CWE_RE.fullmatch("CWE-99999")
