#ttp_engine.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, List


def suggest_ttps(enum_result: Dict[str, Any]) -> Dict[str, Any]:
    services = enum_result.get("services", [])
    ttp_suggestions: List[str] = []
    attack_todo: List[str] = []

    # ── HTTP / DB / Web 취약점 플래그 ──
    has_flask = False
    has_mssql = False

    has_apache_http = False
    has_tomcat_http = False
    has_ajp13 = False

    has_ssti_hint = False
    has_xss_hint = False
    has_lfi_hint = False

    # ── 서비스별 플래그 (메타스플로이터블용) ────────────────
    has_vsftpd_234 = False
    has_proftpd = False
    has_distccd = False
    has_unreal_ircd = False
    has_bind = False
    has_postfix = False
    has_telnet = False
    has_postgres = False
    has_vnc = False
    has_x11 = False

    # ── SMB/AD 관련 전역 정보 ─────────────────────────────
    global_enum = enum_result.get("global_enum") or {}
    smb_info = global_enum.get("smb_basic") or {}
    smb_parsed = smb_info.get("parsed") or {}

    smb_signing_enabled = smb_parsed.get("signing_enabled")
    smb_signing_required = smb_parsed.get("signing_required")
    smb_os = (smb_parsed.get("os") or "").lower()
    smb_domain = smb_parsed.get("domain") or ""
    smb_workgroup = smb_parsed.get("workgroup") or ""
    smb_computer = (smb_parsed.get("computer_name") or "").lower()
    smbv1_enabled = smb_parsed.get("smbv1_enabled")

    is_windows = "windows" in smb_os if smb_os else False
    # DC 추정: 이름이 dc* 이거나, domain 필드가 있고 workgroup과 다르면
    is_dc = False
    if smb_computer.startswith("dc") or (smb_domain and smb_domain != smb_workgroup):
        is_dc = True

    # ── CVE high score 후보 목록 ─────────────────────────
    critical_candidates: List[Dict[str, Any]] = []

    # ── 서비스 루프 ───────────────────────────────────────
    for s in services:
        svc_name = s["service"]
        port = s["port"]
        version = str(s.get("version", "")).lower()
        enum = s.get("enum", {})

        # HTTP 스택/퀵체크
        http_info = enum.get("http_basic") or {}
        stack_guess = http_info.get("stack_guess") or []
        quick_checks = http_info.get("quick_checks") or []

        if "flask" in stack_guess:
            has_flask = True

        if svc_name in ("ms-sql-s",):
            has_mssql = True

        if svc_name == "http" and "apache httpd" in version:
            has_apache_http = True
        if svc_name == "http" and "tomcat" in version:
            has_tomcat_http = True
        if svc_name == "ajp13":
            has_ajp13 = True

        # quick_checks → SSTI / XSS / LFI 힌트
        for qc in quick_checks:
            kind = qc.get("kind")
            indicators = qc.get("indicators") or []
            if kind and isinstance(indicators, list):
                if kind.startswith("ssti") and "calc_49" in indicators:
                    has_ssti_hint = True
                if kind == "xss_reflect" and "payload_reflected" in indicators:
                    has_xss_hint = True
                if kind == "path_traversal" and (
                    "passwd_leak" in indicators or "lfi_error" in indicators
                ):
                    has_lfi_hint = True

        # 서비스별 플래그
        v_lower = version
        if svc_name == "ftp" and "vsftpd 2.3.4" in v_lower:
            has_vsftpd_234 = True
        if svc_name == "ftp" and "proftpd 1.3.1" in v_lower:
            has_proftpd = True
        if svc_name == "distccd":
            has_distccd = True
        if svc_name == "irc" and "unrealircd" in v_lower:
            has_unreal_ircd = True
        if svc_name == "domain" and "bind" in v_lower:
            has_bind = True
        if svc_name == "smtp" and "postfix" in v_lower:
            has_postfix = True
        if svc_name == "telnet":
            has_telnet = True
        if svc_name == "postgresql":
            has_postgres = True
        if svc_name == "vnc":
            has_vnc = True
        if svc_name == "x11":
            has_x11 = True

        # CVE high_score 수집
        cve_info = enum.get("cve_search") or {}
        high = cve_info.get("high_score")
        if high:
            score = high.get("score") or 0.0
            if score >= 9.0:
                critical_candidates.append(
                    {
                        "service": svc_name,
                        "port": port,
                        "version": s.get("version", ""),
                        "cve": high,
                        "score": score,
                    }
                )

    # 점수 순으로 정렬
    critical_candidates.sort(key=lambda x: x["score"], reverse=True)

    # ── 1) HIGH CVE 기반 상단 TTP 메시지 ────────────────────
    max_high_cve = 7
    for item in critical_candidates[:max_high_cve]:
        svc = item["service"]
        port = item["port"]
        cve = item["cve"]
        ttp_suggestions.append(
            f"[HIGH CVE] {svc} on port {port} → {cve['id']} (score={cve['score']})"
        )

    # ── 2) HTTP/DB 조합 및 WEB 패턴 기반 TTP ────────────────
    if has_flask and has_mssql:
        ttp_suggestions.append(
            "[WEB→DB] Flask + MSSQL 조합 감지. "
            "→ SSTI / SQLi / DB credential leak를 통해 DB에서 privesc 가능성 체크."
        )

    if has_apache_http and has_tomcat_http:
        ttp_suggestions.append(
            "[WEB] Apache + Tomcat 구조 감지. "
            "→ /manager, /host-manager, 디폴트 크리덴셜, WAR 업로드 RCE 가능성 체크."
        )

    if has_tomcat_http and has_ajp13:
        ttp_suggestions.append(
            "[WEB] Tomcat + AJP(ajp13) 조합 감지. "
            "→ AJP 파일 열람 / Ghostcat 계열 취약점 여부 확인."
        )

    if has_ssti_hint:
        ttp_suggestions.append(
            "[WEB] 파라미터 주입 테스트에서 49 계산 결과가 노출됨 → SSTI 의심 엔드포인트 존재."
        )

    if has_xss_hint:
        ttp_suggestions.append(
            "[WEB] 반사형 콘텐츠에 테스트 payload가 그대로 포함됨 → 반사 XSS 의심 엔드포인트 존재."
        )

    if has_lfi_hint:
        ttp_suggestions.append(
            "[WEB] 경로 조작 시 /etc/passwd 내용 또는 파일 관련 에러 노출 → LFI/DT 의심."
        )

    # ── 3) CVE 기반 Attack TODO ─────────────────────────────
    for item in critical_candidates[:max_high_cve]:
        svc = item["service"]
        port = item["port"]
        version_str = str(item.get("version", ""))
        cve = item["cve"]
        v_lower = version_str.lower()

        if svc == "ftp" and "vsftpd 2.3.4" in v_lower:
            attack_todo.append(
                f"[FTP] {port}/tcp vsftpd 2.3.4 → CVE-2011-2523 backdoor 테스트 "
                "(포트 6200/tcp로 직접 접속 시도)."
            )
            continue

        if svc == "distccd":
            attack_todo.append(
                f"[distccd] {port}/tcp → classic distccd remote command execution PoC 시도."
            )
            continue

        if svc == "irc" and "unrealircd" in v_lower:
            attack_todo.append(
                f"[IRC] {port}/tcp UnrealIRCd → 알려진 backdoored UnrealIRCd PoC 테스트."
            )
            continue

        if svc == "http" and "tomcat" in v_lower:
            attack_todo.append(
                f"[Tomcat] {port}/tcp → /manager, /host-manager 접근, "
                "기본 계정(tomcat:tomcat 등) / WAR 업로드를 통한 RCE 시도."
            )
            continue

        if svc == "ftp" and "proftpd 1.3.1" in v_lower:
            attack_todo.append(
                f"[FTP] {port}/tcp ProFTPD 1.3.1 → mod_copy 기반 파일 복사/웹쉘 업로드 PoC 검토."
            )
            continue

        if svc == "domain" and "bind" in v_lower:
            attack_todo.append(
                f"[DNS] {port}/tcp BIND → AXFR(Zone Transfer) 시도 및 Cache Poisoning 관련 설정 검토."
            )
            continue

        if svc == "smtp" and "postfix" in v_lower:
            attack_todo.append(
                f"[SMTP] {port}/tcp Postfix → VRFY/EXPN 기반 계정 enum 및 Open Relay 여부 테스트."
            )
            continue

        if svc == "telnet":
            attack_todo.append(
                f"[Telnet] {port}/tcp → 기본 계정(brute-force) 및 cleartext credential sniffing 가능성 검토."
            )
            continue

        if svc == "postgresql":
            attack_todo.append(
                f"[PostgreSQL] {port}/tcp → 기본 계정 테스트 및 DB 함수 기반 RCE 가능성 검토."
            )
            continue

        if svc == "vnc":
            attack_todo.append(
                f"[VNC] {port}/tcp → NoAuth 모드 / 약한 비밀번호 brute-force를 통한 화면 캡처 시도."
            )
            continue

        if svc == "x11":
            attack_todo.append(
                f"[X11] {port}/tcp → 무인증 X11 액세스 여부 확인, xwd/xinput 기반 스크린/키로그 시도."
            )
            continue

        # 기본 fallback
        attack_todo.append(
            f"[CVE] {svc} {port}/tcp → {cve['id']} (score={cve['score']}) 관련 exploit 문서 확인."
        )

    # AJP 관련 TODO
    if has_tomcat_http and has_ajp13:
        for s in services:
            if s["service"] == "ajp13":
                ajp_port = s["port"]
                attack_todo.append(
                    f"[AJP] {ajp_port}/tcp → AJP 엔드포인트 대상 Ghostcat/파일 열람 PoC 시도."
                )
                break

    # SSTI / XSS / LFI 관련 TODO
    if has_ssti_hint:
        attack_todo.append(
            "[WEB] SSTI 의심 파라미터에 대해 템플릿 엔진별 payload 확장 및 RCE 체인 검토."
        )

    if has_xss_hint:
        attack_todo.append(
            "[WEB] 반사 XSS 의심 위치에 대해 쿠키 탈취/세션 하이재킹용 payload 튜닝."
        )

    if has_lfi_hint:
        attack_todo.append(
            "[WEB] LFI/DT 의심 위치에서 로그 포이즈닝, 래퍼 기반 코드 실행 가능성 검토."
        )

    # ── 4) SMB/AD 기반 TTP & Attack TODO ────────────────────
    if smb_info:
        # SMBv1
        if smbv1_enabled is True:
            ttp_suggestions.append(
                "[SMB] SMBv1 enabled. → EternalBlue 계열 취약점 및 legacy 공격 벡터에 매우 취약."
            )

        # signing 관련
        if smb_signing_enabled is False:
            ttp_suggestions.append(
                "[SMB] SMB signing disabled. → 전통적인 NTLM relay 공격에 매우 취약."
            )
            attack_todo.append(
                "[SMB] SMB signing disabled → LDAP/HTTP 등 다른 서비스와 조합한 classic NTLM relay PoC 검토."
            )
        elif smb_signing_enabled is True and smb_signing_required is False:
            ttp_suggestions.append(
                "[SMB] SMB signing enabled but NOT required. → NTLM relay / AD CS 악용 가능성 검토."
            )
            attack_todo.append(
                "[SMB] SMB signing not required → ntlmrelayx / printerbug / ADCS와 연계한 relay 공격 시나리오 검토."
            )

        # DC 추정 시
        if is_windows and is_dc:
            ttp_suggestions.append(
                "[AD] 이 호스트는 Domain Controller로 추정됨. → Kerberoasting, AS-REP Roast, ACL 기반 privesc 루트 검토."
            )

        # 도메인 정보
        if smb_domain:
            ttp_suggestions.append(
                f"[AD] 도메인 '{smb_domain}' 감지. → AD 전체 공격 그래프 상에서 이 호스트의 역할 분석."
            )

    # ── 최종 요약 ────────────────────────────────────────────
    services_summary = [
        f"{s['port']}/tcp {s['service']} {s['version']}" for s in services
    ]

    return {
        "target": enum_result.get("target"),
        "services_summary": services_summary,
        "ttp_suggestions": ttp_suggestions,
        "attack_todo": attack_todo,
    }

