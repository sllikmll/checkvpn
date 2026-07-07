from __future__ import annotations

import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from app.checkers.base import CheckOutcome
from app.models import CheckStatus, Protocol
from app.netutils import resolve_host
from app.parsers import parse_target_config


@dataclass(frozen=True)
class TunnelToolchain:
    control_binary: str
    quick_binary: str
    userspace_binary: str | None = None


class ProbeBackend:
    def run(self, args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        raise NotImplementedError

    def popen(self, args: list[str]):
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError


class SubprocessProbeBackend(ProbeBackend):
    def run(self, args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)

    def popen(self, args: list[str]):
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


_TOOLCHAINS = {
    Protocol.WIREGUARD: TunnelToolchain(control_binary="wg", quick_binary="wg-quick"),
    Protocol.AMNEZIAWG: TunnelToolchain(control_binary="awg", quick_binary="awg-quick", userspace_binary="amneziawg-go"),
}


class ProbeCommandError(RuntimeError):
    def __init__(self, args: list[str], stderr: str, stdout: str = ""):
        joined = " ".join(args)
        message = stderr.strip() or stdout.strip() or f"command failed: {joined}"
        super().__init__(message)
        self.args_list = args
        self.stderr = stderr
        self.stdout = stdout


def probe_vpn_tunnel(
    protocol: Protocol,
    config_text: str,
    *,
    backend: ProbeBackend | None = None,
    interface_name: str | None = None,
) -> CheckOutcome:
    backend = backend or SubprocessProbeBackend()
    parsed = parse_target_config(protocol, config_text)
    toolchain = _TOOLCHAINS[protocol]
    resolved_ips = _safe_resolve(parsed["host"])

    if not _is_full_tunnel(parsed.get("allowed_ips", [])):
        return CheckOutcome(
            protocol=protocol,
            status=CheckStatus.DEGRADED,
            stage="config_validation",
            summary="Config is not full-tunnel; usable connectivity probe requires AllowedIPs to include 0.0.0.0/0",
            details={
                "host": parsed.get("host"),
                "port": parsed.get("port"),
                "resolved_ips": resolved_ips,
                "allowed_ips": parsed.get("allowed_ips", []),
            },
        )

    local_address = _first_ipv4_cidr(parsed.get("addresses", []))
    local_ip = local_address.split("/", 1)[0] if local_address else None
    dns_server = _first_ipv4(parsed.get("dns_servers", []))
    iface = interface_name or _default_interface_name(protocol)

    if not local_address or not local_ip or not dns_server:
        return CheckOutcome(
            protocol=protocol,
            status=CheckStatus.ERROR,
            stage="config_validation",
            summary="Config is missing an IPv4 Address or DNS server required for usable connectivity probe",
            details={
                "host": parsed.get("host"),
                "port": parsed.get("port"),
                "resolved_ips": resolved_ips,
                "addresses": parsed.get("addresses", []),
                "dns_servers": parsed.get("dns_servers", []),
            },
        )

    daemon = None
    started = time.perf_counter()
    current_stage = "setup"
    try:
        with tempfile.TemporaryDirectory(prefix=f"checkvpn-{iface}-") as temp_dir:
            raw_path = Path(temp_dir) / "raw.conf"
            stripped_path = Path(temp_dir) / "stripped.conf"
            raw_path.write_text(config_text)

            stripped = _run_checked(backend, [toolchain.quick_binary, "strip", str(raw_path)], timeout=10.0).stdout
            stripped_path.write_text(stripped)

            if toolchain.userspace_binary:
                daemon = backend.popen([toolchain.userspace_binary, iface])
                backend.sleep(0.2)
            else:
                _run_checked(backend, ["ip", "link", "add", "dev", iface, "type", "wireguard"], timeout=10.0)

            _run_checked(backend, [toolchain.control_binary, "setconf", iface, str(stripped_path)], timeout=10.0)
            _run_checked(backend, ["ip", "address", "add", local_address, "dev", iface], timeout=10.0)
            _run_checked(backend, ["ip", "link", "set", "up", "dev", iface], timeout=10.0)
            _run_checked(backend, ["ip", "route", "replace", f"{dns_server}/32", "dev", iface], timeout=10.0)
            _run_checked(backend, ["ip", "route", "replace", "1.1.1.1/32", "dev", iface], timeout=10.0)
            current_stage = "handshake"
            _run_checked(backend, ["ping", "-I", local_ip, "-c", "1", "-W", "2", "1.1.1.1"], timeout=5.0)

            handshake_epoch = _poll_handshake_epoch(backend, toolchain.control_binary, iface)
            if handshake_epoch <= 0:
                return CheckOutcome(
                    protocol=protocol,
                    status=CheckStatus.OFFLINE,
                    stage="handshake",
                    summary="VPN tunnel did not complete a handshake",
                    details={
                        "host": parsed.get("host"),
                        "port": parsed.get("port"),
                        "resolved_ips": resolved_ips,
                        "interface_name": iface,
                        "dns_server": dns_server,
                    },
                )

            current_stage = "dns"
            dig_result = _run_checked(
                backend,
                ["dig", "+short", "+time=2", "+tries=1", f"@{dns_server}", "example.com", "A", "-b", local_ip],
                timeout=5.0,
            )
            dns_answer = _first_nonempty_line(dig_result.stdout)
            if not dns_answer:
                return CheckOutcome(
                    protocol=protocol,
                    status=CheckStatus.OFFLINE,
                    stage="dns",
                    summary="VPN tunnel handshake succeeded but DNS resolution via tunnel failed",
                    details={
                        "host": parsed.get("host"),
                        "port": parsed.get("port"),
                        "resolved_ips": resolved_ips,
                        "interface_name": iface,
                        "dns_server": dns_server,
                        "handshake_epoch": handshake_epoch,
                    },
                )

            current_stage = "http"
            curl_result = _run_checked(
                backend,
                [
                    "curl",
                    "--interface",
                    local_ip,
                    "--location",
                    "--max-time",
                    "10",
                    "--silent",
                    "--show-error",
                    "https://1.1.1.1/cdn-cgi/trace",
                ],
                timeout=12.0,
            )
            egress_ip = _extract_trace_value(curl_result.stdout, "ip")
            if not egress_ip:
                return CheckOutcome(
                    protocol=protocol,
                    status=CheckStatus.OFFLINE,
                    stage="http",
                    summary="VPN tunnel passed handshake and DNS, but HTTP egress probe failed",
                    details={
                        "host": parsed.get("host"),
                        "port": parsed.get("port"),
                        "resolved_ips": resolved_ips,
                        "interface_name": iface,
                        "dns_server": dns_server,
                        "handshake_epoch": handshake_epoch,
                        "dns_answer": dns_answer,
                    },
                )

            latency_ms = int((time.perf_counter() - started) * 1000)
            return CheckOutcome(
                protocol=protocol,
                status=CheckStatus.ONLINE,
                stage="usable_connectivity",
                summary="VPN tunnel established; DNS and external HTTP are reachable via the tunnel",
                latency_ms=latency_ms,
                details={
                    "host": parsed.get("host"),
                    "port": parsed.get("port"),
                    "resolved_ips": resolved_ips,
                    "interface_name": iface,
                    "local_address": local_address,
                    "dns_server": dns_server,
                    "dns_answer": dns_answer,
                    "handshake_epoch": handshake_epoch,
                    "egress_ip": egress_ip,
                    "toolchain": toolchain.control_binary,
                    "is_awg": parsed.get("is_awg", False),
                },
            )
    except ProbeCommandError as exc:
        status = CheckStatus.ERROR
        summary = f"VPN tunnel probe failed: {exc}"
        if current_stage in {"handshake", "dns", "http"}:
            status = CheckStatus.OFFLINE
            summary = f"VPN tunnel {current_stage} probe failed: {exc}"
        return CheckOutcome(
            protocol=protocol,
            status=status,
            stage=current_stage if current_stage != "setup" else "command",
            summary=summary,
            details={
                "host": parsed.get("host"),
                "port": parsed.get("port"),
                "resolved_ips": resolved_ips,
                "interface_name": iface,
                "failed_command": exc.args_list,
            },
        )
    finally:
        _cleanup_interface(backend, iface)
        if daemon is not None:
            daemon.terminate()
            try:
                daemon.wait(timeout=2)
            except Exception:
                daemon.kill()
                daemon.wait(timeout=2)


def _run_checked(backend: ProbeBackend, args: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    completed = backend.run(args, timeout=timeout)
    if completed.returncode != 0:
        raise ProbeCommandError(args, completed.stderr, completed.stdout)
    return completed


def _cleanup_interface(backend: ProbeBackend, iface: str) -> None:
    try:
        backend.run(["ip", "link", "delete", "dev", iface], timeout=5.0)
    except Exception:
        pass


def _poll_handshake_epoch(backend: ProbeBackend, control_binary: str, iface: str) -> int:
    for attempt in range(5):
        result = _run_checked(backend, [control_binary, "show", iface, "latest-handshakes"], timeout=5.0)
        epoch = _parse_handshake_epoch(result.stdout)
        if epoch > 0:
            return epoch
        if attempt < 4:
            backend.sleep(1.0)
    return 0


def _parse_handshake_epoch(stdout: str) -> int:
    for line in stdout.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        candidate = parts[-1]
        if candidate.isdigit():
            return int(candidate)
    return 0


def _extract_trace_value(stdout: str, key: str) -> str | None:
    prefix = f"{key}="
    for line in stdout.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return None


def _first_nonempty_line(stdout: str) -> str | None:
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _first_ipv4(values: list[str]) -> str | None:
    for value in values:
        if ":" not in value:
            return value
    return None


def _first_ipv4_cidr(values: list[str]) -> str | None:
    for value in values:
        if ":" not in value:
            return value
    return None


def _is_full_tunnel(allowed_ips: list[str]) -> bool:
    return any(entry.strip() == "0.0.0.0/0" for entry in allowed_ips)


def _safe_resolve(host: str) -> list[str]:
    try:
        return resolve_host(host)
    except Exception:
        return []


def _default_interface_name(protocol: Protocol) -> str:
    prefix = "cvawg" if protocol is Protocol.AMNEZIAWG else "cvwg"
    return f"{prefix}{int(time.time()) % 100000:05d}"
