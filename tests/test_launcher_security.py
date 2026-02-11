"""Tests for launcher security checks around nftables/SO_MARK."""

from __future__ import annotations

import logging

from secrets_proxy import launcher


def test_nftables_setup_proceeds_when_so_mark_is_available(
    monkeypatch,
) -> None:
    calls: dict[str, object] = {}

    class _DummySocket:
        def setsockopt(self, level: int, optname: int, value: int) -> None:
            calls["setsockopt"] = (level, optname, value)

        def close(self) -> None:
            calls["closed"] = True

    def _fake_setup(uid: int, proxy_port: int) -> bool:
        calls["setup"] = (uid, proxy_port)
        return True

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.socket, "SO_MARK", 36, raising=False)
    monkeypatch.setattr(launcher.socket, "socket", lambda *_a, **_k: _DummySocket())
    monkeypatch.setattr(launcher, "_setup_nftables", _fake_setup)

    assert launcher._select_network_enforcement(1234, 8080) is True
    assert calls["setup"] == (1234, 8080)
    assert calls["closed"] is True


def test_nftables_falls_back_when_so_mark_requires_cap_net_admin(
    monkeypatch, caplog
) -> None:
    setup_called = False

    class _PermissionDeniedSocket:
        def setsockopt(self, _level: int, _optname: int, _value: int) -> None:
            raise PermissionError("operation not permitted")

        def close(self) -> None:
            pass

    def _fake_setup(_uid: int, _proxy_port: int) -> bool:
        nonlocal setup_called
        setup_called = True
        return True

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.socket, "SO_MARK", 36, raising=False)
    monkeypatch.setattr(
        launcher.socket, "socket", lambda *_a, **_k: _PermissionDeniedSocket()
    )
    monkeypatch.setattr(launcher, "_setup_nftables", _fake_setup)

    with caplog.at_level(logging.INFO):
        assert launcher._select_network_enforcement(1234, 8080) is False

    assert setup_called is False
    assert any(
        "CAP_NET_ADMIN required for SO_MARK" in rec.message for rec in caplog.records
    )
    assert any(
        "Network enforcement mode: env-var-only (SO_MARK unavailable)" in rec.message
        for rec in caplog.records
    )

