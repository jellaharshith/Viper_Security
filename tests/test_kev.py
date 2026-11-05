import pytest

from viper.rag.cisa_kev import fetch_kev, parse_kev
from viper.rag.types import IngestError


def _entry(cve: str = "CVE-2024-0001", **kw: str) -> dict[str, str]:
    base = {"cveID": cve, "vendorProject": "Acme", "product": "Widget",
            "vulnerabilityName": "Acme Widget RCE", "dateAdded": "2024-01-01",
            "shortDescription": "Remote code execution.", "requiredAction": "Apply updates.",
            "dueDate": "2024-01-22", "knownRansomwareCampaignUse": "Known"}
    return {**base, **kw}


def test_parse_normalizes_and_keeps_provenance() -> None:
    docs = parse_kev({"catalogVersion": "2024.01.01", "vulnerabilities": [_entry()]})
    d = docs[0]
    assert d.id == "cisa-kev:CVE-2024-0001"
    assert d.source == "CISA KEV" and d.url.endswith("CVE-2024-0001")
    assert "Remote code execution" in d.text and d.meta["catalog_version"] == "2024.01.01"


def test_duplicates_collapse_and_junk_skipped() -> None:
    payload = {"catalogVersion": "v", "vulnerabilities": [_entry(), _entry(), {"cveID": "bogus"}]}
    assert len(parse_kev(payload)) == 1


@pytest.mark.parametrize("payload", [{}, {"catalogVersion": "v", "vulnerabilities": []},
                                     {"vulnerabilities": [_entry()]},
                                     {"catalogVersion": "v", "vulnerabilities": [{"cveID": "x"}]}])
def test_invalid_feed_rejected(payload: dict) -> None:  # type: ignore[type-arg]
    with pytest.raises(IngestError):
        parse_kev(payload)


@pytest.mark.parametrize("url", ["http://www.cisa.gov/x.json", "https://evil.example/x.json",
                                 "https://www.cisa.gov.evil.example/x.json"])
def test_untrusted_urls_refused(url: str) -> None:
    with pytest.raises(IngestError):
        fetch_kev(url)
