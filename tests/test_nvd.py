import httpx
import pytest

from viper.rag.nvd import NVD_URL, fetch_nvd, parse_nvd
from viper.rag.types import IngestError


def _client(transport: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=transport, follow_redirects=False)


def _vuln(cve: str = "CVE-2021-44228", severity: str = "CRITICAL", score: float = 10.0,
          exploit: bool = True) -> dict:  # type: ignore[type-arg]
    refs = [{"url": "https://logging.apache.org/advisory", "tags": ["Vendor Advisory"]}]
    if exploit:
        refs.append({"url": "https://www.exploit-db.com/exploits/50592", "tags": ["Exploit"]})
    return {"cve": {
        "id": cve,
        "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI remote code execution."},
                         {"lang": "es", "value": "ignored non-english"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
        "references": refs}}


def test_parse_builds_nvd_documents() -> None:
    docs = {d.id: d for d in parse_nvd([_vuln()])}
    d = docs["nvd:CVE-2021-44228"]
    assert d.source == "nvd" and d.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert "JNDI remote code execution" in d.text and "ignored non-english" not in d.text
    assert "CVSS 10.0 CRITICAL" in d.text
    assert d.meta["cvss_score"] == pytest.approx(10.0)
    assert d.meta["cwe"] == ["CWE-502"]
    assert d.meta["exploit_refs"] == ["https://www.exploit-db.com/exploits/50592"]


def test_parse_marks_no_exploit_when_untagged() -> None:
    d = {x.id: x for x in parse_nvd([_vuln(exploit=False)])}["nvd:CVE-2021-44228"]
    assert d.meta["exploit_refs"] == []


def test_parse_skips_malformed_and_rejects_empty() -> None:
    good = _vuln("CVE-2024-0001")
    bad = {"cve": {"id": "not-a-cve", "descriptions": []}}
    docs = parse_nvd([good, bad, {"nope": 1}])
    assert [d.id for d in docs] == ["nvd:CVE-2024-0001"]
    with pytest.raises(IngestError):
        parse_nvd([{"cve": {"id": "x"}}])


def test_fetch_paginates_and_pins_host() -> None:
    assert NVD_URL.startswith("https://services.nvd.nist.gov/")
    pages = [
        {"resultsPerPage": 2, "startIndex": 0, "totalResults": 3,
         "vulnerabilities": [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")]},
        {"resultsPerPage": 1, "startIndex": 2, "totalResults": 3,
         "vulnerabilities": [_vuln("CVE-2024-0003")]},
    ]
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=pages[len(seen) - 1])

    vulns = fetch_nvd({"cvssV3Severity": "CRITICAL"}, client=_client(httpx.MockTransport(handler)))
    assert len(vulns) == 3 and len(seen) == 2
    assert all("services.nvd.nist.gov" in str(r.url) for r in seen)


def test_fetch_sends_api_key_header_when_present() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"totalResults": 0, "startIndex": 0,
                                         "resultsPerPage": 0, "vulnerabilities": []})

    fetch_nvd({}, api_key="secret-key", client=_client(httpx.MockTransport(handler)))
    assert seen[0].headers.get("apiKey") == "secret-key"


def test_fetch_refuses_untrusted_host_and_bad_json() -> None:
    with pytest.raises(IngestError):
        fetch_nvd({}, url="https://evil.example/cves",
                  client=_client(httpx.MockTransport(lambda r: httpx.Response(200, json={}))))
    with pytest.raises(IngestError):
        fetch_nvd({}, client=_client(httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"not json"))))
