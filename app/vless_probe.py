from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from app.checkers.base import CheckOutcome
from app.models import CheckStatus, Protocol
from app.netutils import resolve_host
from app.parsers import parse_target_config


class VlessProbeCommandError(RuntimeError):
    def __init__(self, args_list: list[str], stderr: str, returncode: int):
        message = stderr.strip() or f"command exited with code {returncode}"
        super().__init__(message)
        self.args_list = args_list
        self.stderr = stderr
        self.returncode = returncode


class VlessProbeBackend:
    def run(self, args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)

    def popen(self, args: list[str]) -> subprocess.Popen[str]:
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _run_checked(backend: VlessProbeBackend, args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    result = backend.run(args, timeout=timeout)
    if result.returncode != 0:
        raise VlessProbeCommandError(args, result.stderr, result.returncode)
    return result


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _build_stream_settings(parsed: dict) -> dict:
    network = parsed.get("type") or "tcp"
    security = parsed.get("security") or "none"
    stream: dict = {"network": network, "security": security}

    if network == "ws":
        ws_headers = {}
        if parsed.get("host_header"):
            ws_headers["Host"] = parsed["host_header"]
        stream["wsSettings"] = {
            "path": parsed.get("path") or "/",
            "headers": ws_headers,
        }
    elif network != "tcp":
        raise ValueError(f"Unsupported VLESS transport type for deep-check: {network}")

    if security == "reality":
        if not parsed.get("pbk") or not parsed.get("sni"):
            raise ValueError("VLESS Reality deep-check requires pbk and sni")
        stream["realitySettings"] = {
            "show": False,
            "fingerprint": parsed.get("fp") or "firefox",
            "serverName": parsed["sni"],
            "publicKey": parsed["pbk"],
            "shortId": parsed.get("sid") or "",
            "spiderX": parsed.get("spx") or "/",
        }
    elif security == "tls":
        if not parsed.get("sni"):
            raise ValueError("VLESS TLS deep-check requires sni")
        stream["tlsSettings"] = {
            "serverName": parsed["sni"],
            "fingerprint": parsed.get("fp") or "firefox",
            "allowInsecure": False,
        }
    elif security not in {"", "none"}:
        raise ValueError(f"Unsupported VLESS security for deep-check: {security}")

    return stream


def _build_xray_config(parsed: dict, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": parsed["host"],
                            "port": parsed["port"],
                            "users": [
                                {
                                    "id": parsed["uuid"],
                                    "encryption": parsed.get("encryption") or "none",
                                    "flow": parsed.get("flow") or "",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": _build_stream_settings(parsed),
            }
        ],
    }


def probe_vless_uri(config_text: str, *, backend: VlessProbeBackend | None = None, socks_port: int | None = None) -> CheckOutcome:
    backend = backend or VlessProbeBackend()
    parsed = parse_target_config(Protocol.VLESS, config_text)
    resolved_ips = resolve_host(parsed["host"])

    security = parsed.get("security") or "none"
    if security == "reality" and (not parsed.get("pbk") or not parsed.get("sni")):
        return CheckOutcome(
            protocol=Protocol.VLESS,
            status=CheckStatus.DEGRADED,
            stage="config_validation",
            summary="VLESS Reality deep-check requires pbk and sni",
            details={"host": parsed["host"], "port": parsed["port"], "security": security, "resolved_ips": resolved_ips},
        )

    if not parsed.get("uuid"):
        return CheckOutcome(
            protocol=Protocol.VLESS,
            status=CheckStatus.DEGRADED,
            stage="config_validation",
            summary="VLESS URI missing UUID",
            details={"host": parsed["host"], "port": parsed["port"], "security": security, "resolved_ips": resolved_ips},
        )

    socks_port = socks_port or _pick_free_port()
    stage = "config_build"
    started = time.perf_counter()
    process = None

    try:
        xray_config = _build_xray_config(parsed, socks_port)
    except ValueError as exc:
        return CheckOutcome(
            protocol=Protocol.VLESS,
            status=CheckStatus.DEGRADED,
            stage="config_validation",
            summary=str(exc),
            details={"host": parsed["host"], "port": parsed["port"], "security": security, "resolved_ips": resolved_ips},
        )

    try:
        with tempfile.TemporaryDirectory(prefix="checkvpn-vless-") as temp_dir:
            config_path = Path(temp_dir) / "xray-config.json"
            config_path.write_text(json.dumps(xray_config, ensure_ascii=False, indent=2))

            stage = "xray_boot"
            process = backend.popen(["xray", "run", "-config", str(config_path)])
            backend.sleep(1.0)

            stage = "proxy_http"
            curl_result = _run_checked(
                backend,
                [
                    "curl",
                    "--socks5-hostname",
                    f"127.0.0.1:{socks_port}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "12",
                    "--silent",
                    "--show-error",
                    "https://api.ipify.org",
                ],
                timeout=15.0,
            )
            egress_ip = curl_result.stdout.strip()
            if not egress_ip:
                return CheckOutcome(
                    protocol=Protocol.VLESS,
                    status=CheckStatus.OFFLINE,
                    stage="proxy_http",
                    summary="VLESS proxy returned empty external IP response",
                    details={"host": parsed["host"], "port": parsed["port"], "security": security, "resolved_ips": resolved_ips, "socks_port": socks_port},
                )

            latency_ms = int((time.perf_counter() - started) * 1000)
            return CheckOutcome(
                protocol=Protocol.VLESS,
                status=CheckStatus.ONLINE,
                stage="usable_connectivity",
                summary="VLESS tunnel established; outbound HTTP is reachable through Xray proxy",
                latency_ms=latency_ms,
                details={
                    "host": parsed["host"],
                    "port": parsed["port"],
                    "security": security,
                    "network": parsed.get("type") or "tcp",
                    "resolved_ips": resolved_ips,
                    "socks_port": socks_port,
                    "egress_ip": egress_ip,
                },
            )
    except VlessProbeCommandError as exc:
        return CheckOutcome(
            protocol=Protocol.VLESS,
            status=CheckStatus.OFFLINE,
            stage=stage if stage != "config_build" else "command",
            summary=f"VLESS deep-check failed: {exc}",
            details={
                "host": parsed["host"],
                "port": parsed["port"],
                "security": security,
                "resolved_ips": resolved_ips,
                "socks_port": socks_port,
                "failed_command": exc.args_list,
            },
        )
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except Exception:
                process.kill()
                process.wait(timeout=3)
