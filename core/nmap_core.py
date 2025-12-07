# core/nmap_core.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import time
from datetime import datetime
from typing import List, Dict, Any


def run_nmap(target: str, fast: bool = False) -> Dict[str, Any]:
    """
    Nmap을 실행하고, 메타데이터 + 원본 출력 문자열을 함께 반환.

    반환 예:
    {
      "target": "192.168.96.133",
      "cmd": "nmap -sT -sV -Pn -p- --min-rate 1000 192.168.96.133",
      "started_at": "2025-12-02T16:07:00",
      "finished_at": "2025-12-02T16:09:09",
      "duration_sec": 129.34,
      "raw_output": "Starting Nmap 7.95 ...",
    }
    """
    base_cmd = ["nmap", "-sT", "-sV", "-Pn"]

    if fast:
        # Fast scan: top 1000 ports, 타이밍 공격적으로 (-T4)
        cmd = base_cmd + ["-T4", target]
        print(f"[+] Running FAST Nmap scan on {target} ...")
    else:
        # Full scan: 전체 포트 -p- + min-rate 유지
        cmd = base_cmd + ["-p-", "--min-rate", "1000", target]
        print(f"[+] Running FULL Nmap scan on {target} ...")

    started_at = datetime.now()
    t0 = time.time()
    out = subprocess.check_output(cmd, text=True)
    duration = time.time() - t0
    finished_at = datetime.now()

    # Nmap 원본 출력도 콘솔에 보여주고 싶으면:
    print(out.rstrip())

    return {
        "target": target,
        "cmd": " ".join(cmd),
        "started_at": started_at.isoformat(timespec="seconds"),
        "finished_at": finished_at.isoformat(timespec="seconds"),
        "duration_sec": duration,
        "raw_output": out,
    }


def parse_nmap(nmap_output: str) -> List[Dict[str, str]]:
    """
    Nmap -sV 출력에서 (port, service, version) 목록을 추출.
    """
    print("[+] Parsing Nmap result...")
    services: List[Dict[str, str]] = []

    for line in nmap_output.splitlines():
        # 예: "21/tcp   open  ftp         vsftpd 2.3.4"
        m = re.match(r"(\d+)/tcp\s+open\s+([\w-]+)\s+(.*)", line)
        if not m:
            continue

        port = m.group(1)
        service = m.group(2)
        version = m.group(3).strip()

        services.append(
            {
                "port": port,
                "service": service,
                "version": version,
            }
        )

    return services


def scan_services(target: str, fast: bool = False) -> Dict[str, Any]:
    """
    Nmap 실행 + 파싱까지 한 번에 수행하고,
    '메타데이터 + 서비스 리스트'를 묶어서 반환.

    반환 예:
    {
      "target": "...",
      "cmd": "...",
      "started_at": "...",
      "finished_at": "...",
      "duration_sec": 123.45,
      "raw_output": "...",
      "services": [ {port, service, version}, ... ]
    }
    """
    meta = run_nmap(target, fast=fast)
    services = parse_nmap(meta["raw_output"])
    meta["services"] = services
    return meta

