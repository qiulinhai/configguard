"""Tests for rule schema extensions (v0.2.1+)."""
from configguard.models import Reference, Severity


def test_reference_dataclass_basic():
    ref = Reference(type="cis-benchmark", id="1.1.1", url="https://example.com/cis")
    assert ref.type == "cis-benchmark"
    assert ref.id == "1.1.1"
    assert ref.url == "https://example.com/cis"


def test_reference_dataclass_to_dict():
    ref = Reference(type="cve", id="CVE-2017-6736", url="https://nvd.nist.gov/vuln/detail/CVE-2017-6736")
    d = ref.to_dict()
    assert d == {
        "type": "cve",
        "id": "CVE-2017-6736",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-6736",
    }
