import pytest
from infra_mgmt.utils.proxy_detection import detect_proxy_certificate

class CertInfoStub:
    def __init__(self, fingerprint=None, issuer=None, serial_number=None):
        self.fingerprint = fingerprint
        self.issuer = issuer
        self.serial_number = serial_number

class MockSettings:
    def __init__(self, enabled=True, fingerprints=None, subjects=None, serials=None):
        self._data = {
            "proxy_detection.enabled": enabled,
            "proxy_detection.ca_fingerprints": fingerprints or [],
            "proxy_detection.ca_subjects": subjects or [],
            "proxy_detection.ca_serials": serials or [],
        }
    def get(self, key, default=None):
        return self._data.get(key, default)


def test_detect_proxy_by_fingerprint():
    cert = CertInfoStub(fingerprint="abc123")
    settings = MockSettings(fingerprints=["abc123"])
    is_proxy, reason = detect_proxy_certificate(cert, settings)
    assert is_proxy
    assert "fingerprint" in reason

def test_detect_proxy_by_subject():
    cert = CertInfoStub(issuer={"common_name": "CorpProxy Root CA"})
    settings = MockSettings(subjects=["CorpProxy Root CA"])
    is_proxy, reason = detect_proxy_certificate(cert, settings)
    assert is_proxy
    assert "subject" in reason

def test_detect_proxy_by_serial():
    cert = CertInfoStub(serial_number="9999")
    settings = MockSettings(serials=["9999"])
    is_proxy, reason = detect_proxy_certificate(cert, settings)
    assert is_proxy
    assert "serial number" in reason

def test_no_proxy_match():
    cert = CertInfoStub(fingerprint="notfound", issuer={"common_name": "Legit CA"}, serial_number="0000")
    settings = MockSettings(fingerprints=["abc123"], subjects=["CorpProxy"], serials=["9999"])
    is_proxy, reason = detect_proxy_certificate(cert, settings)
    assert not is_proxy
    assert reason is None

def test_proxy_detection_disabled():
    cert = CertInfoStub(fingerprint="abc123")
    settings = MockSettings(enabled=False, fingerprints=["abc123"])
    is_proxy, reason = detect_proxy_certificate(cert, settings)
    assert not is_proxy
    assert reason is None

def test_none_cert_info():
    settings = MockSettings(fingerprints=["abc123"])
    is_proxy, reason = detect_proxy_certificate(None, settings)
    assert not is_proxy
    assert reason is None 