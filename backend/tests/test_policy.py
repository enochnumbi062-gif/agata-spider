import pytest

from app import auditlog, config, policy


def test_normalize():
    assert policy.normalize_target("LOCALHOST.") == "localhost"


@pytest.mark.parametrize("bad", ["127.0.0.1/path", "a@b", "x?y", "host#1", ""])
def test_reject_malformed(bad):
    with pytest.raises(ValueError):
        policy.normalize_target(bad)


def test_default_allowlist():
    assert policy.target_is_allowed("127.0.0.1") and policy.target_is_allowed("localhost")
    assert not policy.target_is_allowed("example.com")


def test_cidr(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_TARGETS", ["10.0.0.0/24"])
    assert policy.target_is_allowed("10.0.0.7") and not policy.target_is_allowed("10.0.1.7")


def test_active_checks_disabled_by_default(monkeypatch):
    monkeypatch.setattr(config, "ACTIVE_CHECKS", False)
    with pytest.raises(PermissionError):
        policy.validate_connect_check("127.0.0.1", [8000], "ENG-001", True)


def test_port_allowlist(monkeypatch):
    monkeypatch.setattr(config, "ACTIVE_CHECKS", True)
    with pytest.raises(PermissionError):
        policy.validate_connect_check("127.0.0.1", [22], "ENG-001", True)
    assert policy.validate_connect_check("127.0.0.1", [8000], "ENG-001", True) == "127.0.0.1"


def test_cloud_metadata_blocked():
    with pytest.raises(PermissionError):
        policy.resolve_pinned("169.254.169.254")


def test_audit_chain_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(auditlog, "_last", None)
    auditlog.append_event({"event": "a"})
    auditlog.append_event({"event": "b"})
    assert auditlog.verify_chain() == {"valid": True, "records": 2}
    f = tmp_path / "audit.jsonl"
    f.write_text(f.read_text().replace('"a"', '"x"'))
    assert not auditlog.verify_chain()["valid"]


def test_simulation_is_reproducible():
    from app import lab
    assert lab.simulate(7, 4) == lab.simulate(7, 4)
    assert lab.simulate(7, 4) != lab.simulate(8, 4)
