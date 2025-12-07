# core/dispatcher.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Any

from plugins import cve_search
from plugins import http_basic
from plugins import smb_basic  # ← SMB 전역 플러그인(139/445 한 번만 nmap 스크립트)


def run_enumeration(target: str, services: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    각 서비스에 대해 플러그인을 실행하고 결과를 모은다.
    + 일부 플러그인은 '전체 서비스 리스트'를 기반으로 전역 정보를 수집(global_enum).
    """
    results: List[Dict[str, Any]] = []

    # ── 1) per-service enum ───────────────────────────────────
    for svc in services:
        port = svc["port"]
        service = svc["service"]
        version = svc["version"]

        enum_result: Dict[str, Any] = {}

        # 1) CVE 검색 플러그인
        enum_result["cve_search"] = cve_search.enum_cves(service, version, port)

        # 2) HTTP/HTTPS 플러그인
        if service in ("http", "https"):
            enum_result["http_basic"] = http_basic.enum_http(target, port)

        results.append(
            {
                "port": port,
                "service": service,
                "version": version,
                "enum": enum_result,
            }
        )

    # ── 2) global enum (전체 서비스 기반 플러그인) ─────────────
    global_enum: Dict[str, Any] = {}

    # SMB 기본 정보 수집: netbios-ssn(139/445) 있으면 한 번만 nmap smb 스크립트 실행
    smb_info = smb_basic.enum_smb_basic(target, services)
    if smb_info:
        global_enum["smb_basic"] = smb_info

    # 필요해지면 여기서 http_basic에 대한 전역 분석도 추가할 수 있음
    # ex) global_enum["http_basic"] = http_basic.aggregate_http(services, results)

    return {
        "target": target,
        "services": results,
        "global_enum": global_enum,  # ← 새로 추가된 전역 정보
    }

