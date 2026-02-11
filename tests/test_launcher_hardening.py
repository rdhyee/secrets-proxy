"""Tests for launcher hardening fixes (#18, #15)."""

from __future__ import annotations

import json
import importlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
for mod_name in list(sys.modules):
    if mod_name == "secrets_proxy" or mod_name.startswith("secrets_proxy."):
        del sys.modules[mod_name]

module_cli = importlib.import_module("secrets_proxy.__main__")
launcher = importlib.import_module("secrets_proxy.launcher")
ProxyConfig = importlib.import_module("secrets_proxy.config").ProxyConfig


def test_nft_chain_names_include_pid(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.os, "getpid", lambda: 4321)
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    monkeypatch.setattr(launcher, "_NFT_NAT_CHAIN_NAME", None)
    monkeypatch.setattr(launcher, "_NFT_FILTER_CHAIN_NAME", None)

    assert launcher._setup_nftables(1000, 8080) is True
    assert launcher._NFT_NAT_CHAIN_NAME == "secrets_proxy_4321"
    assert launcher._NFT_FILTER_CHAIN_NAME == "secrets_proxy_filter_4321"
    assert [
        "nft",
        "add",
        "chain",
        "inet",
        launcher._NFT_TABLE,
        "secrets_proxy_4321",
    ] in [cmd[:6] for cmd in calls]
    assert [
        "nft",
        "add",
        "chain",
        "inet",
        launcher._NFT_TABLE,
        "secrets_proxy_filter_4321",
    ] in [cmd[:6] for cmd in calls]


def test_setup_and_teardown_use_matching_chain_names(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.os, "getpid", lambda: 2468)
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    monkeypatch.setattr(launcher, "_NFT_NAT_CHAIN_NAME", None)
    monkeypatch.setattr(launcher, "_NFT_FILTER_CHAIN_NAME", None)

    assert launcher._setup_nftables(1000, 8080) is True
    launcher._teardown_nftables(1000, 8080)

    assert ["nft", "flush", "chain", "inet", launcher._NFT_TABLE, "secrets_proxy_2468"] in calls
    assert ["nft", "delete", "chain", "inet", launcher._NFT_TABLE, "secrets_proxy_2468"] in calls
    assert ["nft", "flush", "chain", "inet", launcher._NFT_TABLE, "secrets_proxy_filter_2468"] in calls
    assert ["nft", "delete", "chain", "inet", launcher._NFT_TABLE, "secrets_proxy_filter_2468"] in calls


def test_two_instances_get_different_chain_names(monkeypatch) -> None:
    calls: list[list[str]] = []
    pids = iter([1111, 2222])

    def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.os, "getpid", lambda: next(pids))
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)

    assert launcher._setup_nftables(1000, 8080) is True
    assert launcher._setup_nftables(1001, 8081) is True

    nat_chains = [
        cmd[5]
        for cmd in calls
        if len(cmd) > 5
        and cmd[:3] == ["nft", "add", "chain"]
        and cmd[5].startswith("secrets_proxy_")
        and not cmd[5].startswith("secrets_proxy_filter_")
    ]
    assert nat_chains == ["secrets_proxy_1111", "secrets_proxy_2222"]
    assert len(set(nat_chains)) == 2


def test_cleanup_command_removes_matching_chains(monkeypatch, capsys) -> None:
    calls: list[list[str]] = []
    ruleset = {
        "nftables": [
            {"table": {"family": "inet", "name": "secrets_proxy"}},
            {"chain": {"family": "inet", "table": "secrets_proxy", "name": "secrets_proxy_1111"}},
            {"chain": {"family": "inet", "table": "secrets_proxy", "name": "secrets_proxy_filter_1111"}},
            {"chain": {"family": "inet", "table": "secrets_proxy", "name": "unrelated"}},
        ]
    }

    def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if cmd == ["nft", "-j", "list", "ruleset"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(ruleset), stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)

    rc = module_cli.main(["cleanup"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "secrets_proxy_1111" in captured.out
    assert "secrets_proxy_filter_1111" in captured.out
    assert ["nft", "flush", "chain", "inet", "secrets_proxy", "secrets_proxy_1111"] in calls
    assert ["nft", "delete", "chain", "inet", "secrets_proxy", "secrets_proxy_1111"] in calls
    assert ["nft", "flush", "chain", "inet", "secrets_proxy", "secrets_proxy_filter_1111"] in calls
    assert ["nft", "delete", "chain", "inet", "secrets_proxy", "secrets_proxy_filter_1111"] in calls
    assert ["nft", "flush", "chain", "inet", "secrets_proxy", "unrelated"] not in calls


def test_startup_prints_recovery_hint(monkeypatch, tmp_path: Path, capsys) -> None:
    class _FakeProc:
        def __init__(self, returncode: int | None = None) -> None:
            self.returncode = returncode

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: int | None = None) -> int:
            del timeout
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def terminate(self) -> None:
            if self.returncode is None:
                self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    bundle_path = tmp_path / "ca-bundle.pem"
    addon_path = tmp_path / "addon.py"
    bundle_path.write_text("bundle")
    addon_path.write_text("addon")

    monkeypatch.setattr(launcher, "_check_mitmdump", lambda: None)
    monkeypatch.setattr(launcher, "_generate_mitmproxy_ca_if_needed", lambda: None)
    monkeypatch.setattr(launcher, "setup_ca_trust", lambda _: (bundle_path, {}))
    monkeypatch.setattr(launcher, "_create_addon_script", lambda _: (str(addon_path), {}))
    monkeypatch.setattr(launcher, "_setup_nftables", lambda *_: False)
    monkeypatch.setattr(launcher, "start_proxy", lambda *_, **__: _FakeProc(returncode=None))
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *_, **__: _FakeProc(returncode=None))
    monkeypatch.setattr(launcher.signal, "signal", lambda *_: None)

    rc = launcher.run(ProxyConfig(), ["echo", "hello"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "If this process is killed with SIGKILL, run: secrets-proxy cleanup" in captured.out
