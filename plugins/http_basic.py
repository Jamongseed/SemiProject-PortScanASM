#http_basic.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from typing import Dict, Any, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# ── 기본 설정 ──────────────────────────────────────────────
COMMON_PATHS = [
    "/",
    "/login",
    "/admin",
    "/debug",
    "/backup",
    "/test",
    "/api",
    "/api/v1",
    "/server-status",
]

TEST_PAYLOADS = {
    "ssti_jinja": "{{7*7}}",
    "ssti_el": "${7*7}",
    "xss_reflect": "\"><script>alert(1)</script>",
    "path_traversal": "../etc/passwd",
}

DEFAULT_TIMEOUT = 5
DEFAULT_HEADERS = {
    "User-Agent": "NOTFOUND-Scanner/1.0 (+internal)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _guess_stack(headers: Dict[str, str], body: str) -> List[str]:
    stack: List[str] = []
    server = (headers.get("Server") or "").lower()
    powered = (headers.get("X-Powered-By") or "").lower()
    text = (body[:3000] or "").lower()

    def add(tag: str) -> None:
        if tag not in stack:
            stack.append(tag)

    # Web server
    if "apache" in server:
        add("apache")
    if "nginx" in server:
        add("nginx")
    if "iis" in server:
        add("iis")

    # Runtime / framework
    if "php" in powered or "php" in text:
        add("php")
    if "flask" in text or "werkzeug" in text:
        add("flask")
    if "django" in text:
        add("django")
    if "express" in text or "node.js" in text or "nodejs" in text:
        add("nodejs/express")
    if "spring" in text:
        add("java/spring")

    return stack


def _enum_paths(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        entry = {
            "path": path,
            "status": r.status_code,
            "length": len(r.text or ""),
        }
        found.append(entry)
    return found


def _extract_forms(html: str) -> List[Dict[str, Any]]:
    forms_info: List[Dict[str, Any]] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return forms_info

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""
        inputs = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            itype = inp.get("type") or "text"
            if name:
                inputs.append({"name": name, "type": itype})
        forms_info.append(
            {
                "method": method,
                "action": action,
                "inputs": inputs,
            }
        )

    return forms_info


def _test_injection_payloads(
    session: requests.Session, base_url: str, extra_paths: List[str]
) -> List[Dict[str, Any]]:
    """
    간단한 인젝션 힌트만 잡아내는 부분.
    - kind: ssti_jinja / ssti_el / xss_reflect / path_traversal
    - indicators: calc_49, payload_reflected, passwd_leak, lfi_error, server_error
    """
    results: List[Dict[str, Any]] = []
    paths_to_test: List[str] = ["/"]
    for p in extra_paths:
        if p not in paths_to_test:
            paths_to_test.append(p)

    for path in paths_to_test:
        url = urljoin(base_url, path)
        for kind, payload in TEST_PAYLOADS.items():
            try:
                r = session.get(
                    url,
                    params={"scanner_test": payload},
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                )
            except Exception:
                continue

            body = r.text or ""
            indicators: List[str] = []

            # SSTI → 7*7=49
            if kind.startswith("ssti") and "49" in body:
                indicators.append("calc_49")

            # XSS → payload 그대로 반사
            if kind == "xss_reflect" and payload in body:
                indicators.append("payload_reflected")

            # LFI / DT
            if kind == "path_traversal":
                if "root:x:0:0:" in body or "/etc/passwd" in body:
                    indicators.append("passwd_leak")
                if "No such file" in body or "No such file or directory" in body:
                    indicators.append("lfi_error")

            # 서버 에러 힌트 (WAF / 필터링 실패 등)
            if r.status_code >= 500:
                indicators.append("server_error")

            if indicators:
                results.append(
                    {
                        "url": r.url,
                        "kind": kind,
                        "status": r.status_code,
                        "indicators": indicators,
                    }
                )

    return results


def enum_http(target: str, port: str) -> Dict[str, Any]:
    base_url = f"http://{target}:{port}"
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    try:
        r = session.get(base_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        html = r.text or ""
        headers = {k: v for k, v in r.headers.items()}
    except Exception as e:
        return {
            "base_url": base_url,
            "error": f"HTTP request failed: {e!r}",
        }

    stack = _guess_stack(headers, html)
    paths = _enum_paths(session, base_url)
    forms = _extract_forms(html)

    path_candidates = [p["path"] for p in paths if p.get("status") in (200, 302, 403)]
    quick_checks = _test_injection_payloads(session, base_url, path_candidates[:5])

    return {
        "base_url": base_url,
        "status": r.status_code,
        "stack_guess": stack,
        "important_headers": {
            "Server": headers.get("Server"),
            "X-Powered-By": headers.get("X-Powered-By"),
        },
        "paths": paths,
        "forms": forms,
        "quick_checks": quick_checks,
    }

