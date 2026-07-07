from __future__ import annotations

from dataclasses import dataclass, field
from subprocess import CompletedProcess

from app.models import CheckStatus, Protocol
from app.vpn_probe import ProbeBackend, probe_vpn_tunnel


@dataclass
class FakeProcess:
    args: list[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    terminated: bool = False
    killed: bool = False
    waited: bool = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout: float | None = None):
        self.waited = True
        return self.returncode


@dataclass
class FakeBackend(ProbeBackend):
    command_log: list[list[str]] = field(default_factory=list)
    popen_log: list[list[str]] = field(default_factory=list)
    sleeps: list[float] = field(default_factory=list)
    handshake_output: str = "peer-public-key\t1700000000\n"
    dig_output: str = "93.184.216.34\n"
    curl_output: str = "ip=198.51.100.77\nwarp=off\n"
    strip_output: str = "[Interface]\nPrivateKey = hidden\n[Peer]\nPublicKey = peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
    process: FakeProcess | None = None

    def run(self, args: list[str], timeout: float = 10.0) -> CompletedProcess[str]:
        self.command_log.append(args)

        if args[:2] == ["wg-quick", "strip"] or args[:2] == ["awg-quick", "strip"]:
            return CompletedProcess(args, 0, stdout=self.strip_output, stderr="")
        if len(args) >= 4 and args[1] == "show" and args[3] == "latest-handshakes":
            return CompletedProcess(args, 0, stdout=self.handshake_output, stderr="")
        if args and args[0] == "dig":
            return CompletedProcess(args, 0, stdout=self.dig_output, stderr="")
        if args and args[0] == "curl":
            return CompletedProcess(args, 0, stdout=self.curl_output, stderr="")
        return CompletedProcess(args, 0, stdout="", stderr="")

    def popen(self, args: list[str]) -> FakeProcess:
        self.popen_log.append(args)
        self.process = FakeProcess(args=args)
        return self.process

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def test_probe_wireguard_tunnel_reports_online_for_real_usable_connectivity():
    backend = FakeBackend()
    config_text = """
[Interface]
PrivateKey = priv=
Address = 10.91.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = pub=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25
""".strip()

    outcome = probe_vpn_tunnel(
        Protocol.WIREGUARD,
        config_text,
        backend=backend,
        interface_name="cvwgtest0",
    )

    assert outcome.status is CheckStatus.ONLINE
    assert outcome.stage == "usable_connectivity"
    assert outcome.details["interface_name"] == "cvwgtest0"
    assert outcome.details["dns_server"] == "1.1.1.1"
    assert outcome.details["egress_ip"] == "198.51.100.77"
    assert ["ip", "link", "add", "dev", "cvwgtest0", "type", "wireguard"] in backend.command_log
    assert any(cmd[:2] == ["wg-quick", "strip"] for cmd in backend.command_log)
    assert any(cmd[:2] == ["wg", "setconf"] for cmd in backend.command_log)
    assert any(cmd and cmd[0] == "dig" for cmd in backend.command_log)
    curl_cmd = next(cmd for cmd in backend.command_log if cmd and cmd[0] == "curl")
    assert "--location" in curl_cmd
    assert "https://1.1.1.1/cdn-cgi/trace" in curl_cmd


def test_probe_wireguard_tunnel_reports_offline_when_handshake_never_happens():
    backend = FakeBackend(handshake_output="peer-public-key\t0\n")
    config_text = """
[Interface]
PrivateKey = priv=
Address = 10.91.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = pub=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.10:51820
""".strip()

    outcome = probe_vpn_tunnel(
        Protocol.WIREGUARD,
        config_text,
        backend=backend,
        interface_name="cvwgfail0",
    )

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "handshake"
    assert "handshake" in outcome.summary.lower()
    assert any(cmd[:3] == ["wg", "show", "cvwgfail0"] for cmd in backend.command_log)


def test_probe_amneziawg_tunnel_uses_userspace_daemon_and_awg_tooling():
    backend = FakeBackend()
    config_text = """
[Interface]
PrivateKey = priv=
Address = 10.90.34.6/32
DNS = 1.1.1.1, 8.8.8.8
Jc = 4
Jmin = 10
Jmax = 50
S1 = 128
S2 = 16
S3 = 52
S4 = 1
H1 = 179418504-2089534163
H2 = 2120807420-2128146913
H3 = 2145380182-2147316795
H4 = 2147319142-2147338333

[Peer]
PublicKey = pub=
PresharedKey = psk=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.20:9734
PersistentKeepalive = 25
""".strip()

    outcome = probe_vpn_tunnel(
        Protocol.AMNEZIAWG,
        config_text,
        backend=backend,
        interface_name="cvawgtest0",
    )

    assert outcome.status is CheckStatus.ONLINE
    assert backend.popen_log == [["amneziawg-go", "cvawgtest0"]]
    assert any(cmd[:2] == ["awg-quick", "strip"] for cmd in backend.command_log)
    assert any(cmd[:2] == ["awg", "setconf"] for cmd in backend.command_log)
    assert ["ip", "link", "add", "dev", "cvawgtest0", "type", "wireguard"] not in backend.command_log
    assert backend.process is not None
    assert backend.process.terminated is True
    assert backend.process.waited is True


def test_probe_reports_http_timeout_as_offline():
    backend = FakeBackend(curl_output="")

    def failing_run(args: list[str], timeout: float = 10.0):
        backend.command_log.append(args)
        if args[:2] == ["wg-quick", "strip"]:
            return CompletedProcess(args, 0, stdout=backend.strip_output, stderr="")
        if len(args) >= 4 and args[1] == "show" and args[3] == "latest-handshakes":
            return CompletedProcess(args, 0, stdout=backend.handshake_output, stderr="")
        if args and args[0] == "dig":
            return CompletedProcess(args, 0, stdout=backend.dig_output, stderr="")
        if args and args[0] == "curl":
            return CompletedProcess(args, 28, stdout="", stderr="curl: (28) Connection timed out after 10002 milliseconds")
        return CompletedProcess(args, 0, stdout="", stderr="")

    backend.run = failing_run  # type: ignore[method-assign]
    config_text = """
[Interface]
PrivateKey = priv=
Address = 10.91.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = pub=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.10:51820
""".strip()

    outcome = probe_vpn_tunnel(
        Protocol.WIREGUARD,
        config_text,
        backend=backend,
        interface_name="cvwghttp0",
    )

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "http"
    assert "http probe failed" in outcome.summary.lower()


def test_probe_returns_degraded_for_split_tunnel_configs():
    backend = FakeBackend()
    config_text = """
[Interface]
PrivateKey = priv=
Address = 10.91.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = pub=
AllowedIPs = 10.0.0.0/8
Endpoint = 203.0.113.10:51820
""".strip()

    outcome = probe_vpn_tunnel(
        Protocol.WIREGUARD,
        config_text,
        backend=backend,
        interface_name="cvwgsplit0",
    )

    assert outcome.status is CheckStatus.DEGRADED
    assert outcome.stage == "config_validation"
    assert "full-tunnel" in outcome.summary.lower()
    assert backend.command_log == []
