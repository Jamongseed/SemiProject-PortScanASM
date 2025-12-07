# core/main.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from core.nmap_core import scan_services
from core.dispatcher import run_enumeration
from core.ttp_engine import suggest_ttps

PROJECT_ROOT = Path(__file__).resolve().parent


def _safe_target_name(target: str) -> str:
    return target.replace(":", "_").replace("/", "_")


def run_gpt_suggester(target: str) -> None:
    """
    1번 모드: gpt_query_suggest_cached.py 실행해서 query_suggestions.json 생성/업데이트
    """
    script = Path(__file__).resolve().parent / "gpt_query_suggest_cached.py"
    if not script.exists():
        print(f"[!] gpt_query_suggest_cached.py not found at {script}")
        return

    cmd = [sys.executable, str(script), target]
    print(f"[+] Running GPT query suggester for target {target} ...")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] gpt_query_suggest_cached.py failed: {e}")


def _scan_and_enum(target: str, fast: bool) -> None:
    """
    Fast/Full 공통: Nmap 스캔 + 플러그인 enum + TTP/Attack TODO까지 처리.
    """
    # 1) Nmap 기반 서비스 스캔 (메타 포함)
    scan_result = scan_services(target, fast=fast)
    services = scan_result["services"]

    # 2) 플러그인 기반 추가 enum
    enum_result = run_enumeration(target, services)

    # 3) recon_<target>.json 구조 구성
    recon = {
        "target": target,
        "scan_meta": {
            "started_at": scan_result["started_at"],
            "finished_at": scan_result["finished_at"],
            "duration_sec": scan_result["duration_sec"],
            "nmap_cmd": scan_result["cmd"],
        },
        "services": enum_result["services"],
        "global_enum": enum_result.get("global_enum", {}),
    }

    safe_target = _safe_target_name(target)
    recon_file = PROJECT_ROOT / f"recon_{safe_target}.json"

    with open(recon_file, "w", encoding="utf-8") as f:
        json.dump(recon, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved raw enumeration to {recon_file}")

    # 4) TTP + Attack TODO 생성 및 출력
    _print_ttp_and_todo(recon)


def run_fast_scan(target: str) -> None:
    """
    2번 모드: Fast scan (top 1000 ports, -T4) + 플러그인 enum + TTP/Attack TODO
    """
    print("[+] Mode 2: Fast scan (top 1000 ports, -T4)")
    _scan_and_enum(target, fast=True)


def run_full_scan(target: str) -> None:
    """
    3번 모드: Full scan (Nmap -p- + 플러그인 enum + TTP/Attack TODO)
    """
    print("[+] Mode 3: Full scan (Nmap -p-)")
    _scan_and_enum(target, fast=False)


def run_ttp_only(target: str) -> None:
    """
    4번 모드: 기존 recon_<target>.json만 가지고 TTP/Attack TODO 다시 계산
    (재스캔 없이 보고만 갈 때)
    """
    safe_target = _safe_target_name(target)
    recon_file = PROJECT_ROOT / f"recon_{safe_target}.json"

    if not recon_file.exists():
        print(f"[!] {recon_file} not found. 먼저 2번(Fast) 또는 3번(Full)부터 실행해야 합니다.")
        return

    with open(recon_file, "r", encoding="utf-8") as f:
        recon = json.load(f)

    _print_ttp_and_todo(recon)


def _print_ttp_and_todo(recon: dict) -> None:
    """
    recon(dict) 전체를 받아서:
    - scan_meta 출력
    - services_summary / ttp_suggestions / attack_todo 출력
    """
    # 1) Scan Meta
    scan_meta = recon.get("scan_meta")
    if scan_meta:
        print("\n=== Scan Meta ===")
        print(f" - Started : {scan_meta.get('started_at')}")
        print(f" - Finished: {scan_meta.get('finished_at')}")
        dur = scan_meta.get("duration_sec")
        if isinstance(dur, (int, float)):
            print(f" - Duration: {dur:.2f} sec")
        else:
            print(f" - Duration: {dur}")
        print(f" - Cmd     : {scan_meta.get('nmap_cmd')}")

    # 2) TTP/Attack TODO 계산
    ttp = suggest_ttps(recon)

    print("\n=== Services Summary ===")
    for line in ttp.get("services_summary", []):
        print(" -", line)

    print("\n=== TTP Suggestions ===")
    if not ttp.get("ttp_suggestions"):
        print(" (no specific suggestions yet)")
    else:
        for s in ttp["ttp_suggestions"]:
            print(" -", s)

    print("\n=== Attack TODO ===")
    if not ttp.get("attack_todo"):
        print(" (no auto TODO yet)")
    else:
        for s in ttp["attack_todo"]:
            print(" -", s)


def _prompt_mode(default: Optional[str] = None) -> str:
    print("\n[ Mode 선택 ]")
    print("  1) GPT 기반 CVE 검색 쿼리 생성 (gpt_query_suggest_cached.py)")
    print("  2) Fast scan (top 1000 ports, -T4)")
    print("  3) Full scan (Nmap -p- + 플러그인 enum + TTP/Attack TODO)")
    print("  4) 기존 recon_<target>.json에서 TTP/Attack TODO만 다시 계산")
    while True:
        choice = input("  → 모드 선택 [1/2/3/4]: ").strip()
        if choice in {"1", "2", "3", "4"}:
            return choice
        if choice == "" and default:
            return default
        print("  [!] 1, 2, 3, 4 중 하나를 입력하세요.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PortScan_exploiter - Nmap + CVE + TTP 엔진"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="스캔할 타겟 IP 또는 호스트네임 (예: 192.168.96.133, 10.10.11.95, host8.dreamhack.games)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["1", "2", "3", "4"],
        help=(
            "1: GPT 쿼리 생성, "
            "2: Fast scan, "
            "3: Full scan, "
            "4: 기존 recon에서 TTP/Attack TODO만"
        ),
    )
    args = parser.parse_args()

    # 타겟 결정
    target = args.target
    if not target:
        target = input("Target (IP/hostname): ").strip()
        if not target:
            print("[!] Target을 입력해야 합니다.")
            return

    # 모드 결정
    mode = args.mode or _prompt_mode()

    if mode == "1":
        run_gpt_suggester(target)
    elif mode == "2":
        run_fast_scan(target)
    elif mode == "3":
        run_full_scan(target)
    elif mode == "4":
        run_ttp_only(target)
    else:
        print("[!] Unknown mode.")


if __name__ == "__main__":
    main()

