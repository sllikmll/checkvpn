from __future__ import annotations

import socket
import subprocess
import time
from typing import Sequence


def measure_tcp_connect(host: str, port: int, timeout: float = 3.0) -> int:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout):
        pass
    return int((time.perf_counter() - started) * 1000)


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def run_command(args: Sequence[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
