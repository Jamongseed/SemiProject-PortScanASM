#smb_basic.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SMB 기본 정보 수집 플러그인.

- 대상 포트: 139, 445 (service == netbios-ssn)
- nmap smb 관련 스크립트를 사용해서:
  - OS / hostname / domain / workgroup
  - SMBv1 여부 (대충 문자열로만)
  - signing: enabled/required 여부
"""

import subprocess
from typing import Dict, Any, List


def _run_nmap_smb(target: str, ports: List[str]) -> str:
    """
    간단히 nmap smb 스크립트 몇 개만 돌린다.

    - smb-os-discovery: OS / 도메인 / 워크그룹
    - smb2-security-mode: signing 여부
    """
    port_arg = ",".join(ports)
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        port_arg,
        "--script",
        "smb-os-discovery,smb2-security-mode",
        target,
    ]
    print(f"[+] [SMB] Running nmap SMB scripts on {target}:{port_arg} ...")
    try:
        out = subprocess.check_output(cmd, text=True)
        return out
    except subprocess.CalledProcessError as e:
        print(f"[-] [SMB] nmap SMB script failed: {e}")
        return ""


def _parse_nmap_smb(output: str) -> Dict[str, Any]:
    """
    nmap SMB 스크립트 출력에서 최소한의 정보만 뽑는다.
    """
    info: Dict[str, Any] = {
        "raw_output": output,
        "os": None,
        "computer_name": None,
        "workgroup": None,
        "domain": None,
        "signing_enabled": None,
        "signing_required": None,
        "smbv1_enabled": None,
    }

    if not output:
        return info

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("|") or line.startswith("|_"):
            line_clean = line.lstrip("|_").strip()
        else:
            line_clean = line

        lc = line_clean.lower()

        # OS
        if lc.startswith("os:"):
            info["os"] = line_clean.split(":", 1)[1].strip()

        # Computer name
        elif lc.startswith("computer name:"):
            info["computer_name"] = line_clean.split(":", 1)[1].strip()

        # Workgroup / Domain
        elif lc.startswith("workgroup:"):
            info["workgroup"] = line_clean.split(":", 1)[1].strip()
        elif lc.startswith("domain:"):
            info["domain"] = line_clean.split(":", 1)[1].strip()

        # signing
        elif "message signing" in lc:
            if "enabled" in lc:
                info["signing_enabled"] = True
            if "not required" in lc:
                info["signing_required"] = False
            if "required" in lc and "not required" not in lc:
                info["signing_required"] = True

        # SMBv1 힌트 (완벽하진 않지만 대충 체크)
        elif "smbv1" in lc:
            if "disabled" in lc:
                info["smbv1_enabled"] = False
            elif "enabled" in lc:
                info["smbv1_enabled"] = True

    return info


def enum_smb_basic(target: str, services: list[Dict[str, Any]]) -> Dict[str, Any]:
    """
    dispatcher에서 호출되는 엔트리 포인트.

    반환 형식:
      {
        "ports": ["139", "445"],
        "nmap_output": "...",
        "parsed": { ... }
      }
    """
    smb_ports: List[str] = []
    for s in services:
        if s.get("service") == "netbios-ssn":
            smb_ports.append(s.get("port"))

    if not smb_ports:
        return {}

    nmap_out = _run_nmap_smb(target, smb_ports)
    parsed = _parse_nmap_smb(nmap_out)

    return {
        "ports": smb_ports,
        "nmap_output": nmap_out,
        "parsed": parsed,
    }

