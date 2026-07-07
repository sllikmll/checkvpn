from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import CompletedProcess

from app.models import CheckStatus
from app.vless_probe import VlessProbeBackend, probe_vless_uri


REALITY_URI = (
    "vless://12345678-1234-1234-1234-123456789012@202.71.13.115:9443"
    "?encryption=none&fp=firefox&pbk=PUBKEY&security=reality&sid=ac&sni=yandex.ru&spx=%2F&type=tcp#demo"
)


@dataclass
class FakeProcess:
    args: list[str]
    terminated: bool = False
    killed: bool = False
    waited: bool = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout: float | None = None):
        self.waited = True
        return 0


@dataclass
class FakeBackend(VlessProbeBackend):
    command_log: list[list[str]] = field(default_factory=list)
    popen_log: list[list[str]] = field(default_factory=list)
    sleeps: list[float] = field(default_factory=list)
    curl_output: str = "198.51.100.77"
    process: FakeProcess | None = None
    last_config: dict | None = None

    def run(self, args: list[str], timeout: float = 10.0) -> CompletedProcess[str]:
        self.command_log.append(args)
        if args and args[0] == "curl":
            return CompletedProcess(args, 0, stdout=self.curl_output, stderr="")
        return CompletedProcess(args, 0, stdout="", stderr="")

    def popen(self, args: list[str]) -> FakeProcess:
        self.popen_log.append(args)
        config_path = Path(args[-1])
        self.last_config = json.loads(config_path.read_text())
        self.process = FakeProcess(args=args)
        return self.process

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def test_probe_vless_reality_reports_online_for_usable_connectivity():
    backend = FakeBackend()

    outcome = probe_vless_uri(REALITY_URI, backend=backend, socks_port=10809)

    assert outcome.status is CheckStatus.ONLINE
    assert outcome.stage == "usable_connectivity"
    assert outcome.details["egress_ip"] == "198.51.100.77"
    assert outcome.details["socks_port"] == 10809
    assert backend.popen_log == [["xray", "run", "-config", backend.popen_log[0][-1]]]
    assert backend.last_config is not None
    outbound = backend.last_config["outbounds"][0]
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["vnext"][0]["address"] == "202.71.13.115"
    assert outbound["streamSettings"]["security"] == "reality"
    assert outbound["streamSettings"]["realitySettings"]["serverName"] == "yandex.ru"
    assert outbound["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY"
    curl_cmd = next(cmd for cmd in backend.command_log if cmd and cmd[0] == "curl")
    assert "--socks5-hostname" in curl_cmd
    assert "https://api.ipify.org" in curl_cmd
    assert backend.process is not None
    assert backend.process.terminated is True
    assert backend.process.waited is True


def test_probe_vless_reports_offline_when_proxy_http_check_fails():
    backend = FakeBackend()

    def failing_run(args: list[str], timeout: float = 10.0):
        backend.command_log.append(args)
        if args and args[0] == "curl":
            return CompletedProcess(args, 28, stdout="", stderr="curl: (28) Connection timed out")
        return CompletedProcess(args, 0, stdout="", stderr="")

    backend.run = failing_run  # type: ignore[method-assign]

    outcome = probe_vless_uri(REALITY_URI, backend=backend, socks_port=10809)

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "proxy_http"
    assert "timed out" in outcome.summary.lower()


def test_probe_vless_reality_requires_reality_fields():
    backend = FakeBackend()
    bad_uri = (
        "vless://12345678-1234-1234-1234-123456789012@example.com:443"
        "?encryption=none&security=reality&type=tcp&sni=yandex.ru#demo"
    )

    outcome = probe_vless_uri(bad_uri, backend=backend, socks_port=10809)

    assert outcome.status is CheckStatus.DEGRADED
    assert outcome.stage == "config_validation"
    assert "pbk" in outcome.summary.lower()
