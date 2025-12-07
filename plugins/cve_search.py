#cve_search.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import time
from typing import Dict, Any, List, Optional

import requests

# ── 설정 ─────────────────────────────────────
LOCAL_CVE_API_BASE = "http://13.125.219.89:8001"
LOCAL_CVE_API_ENDPOINT = f"{LOCAL_CVE_API_BASE}/api/local/search"

SUGGEST_FILE = "query_suggestions.json"   # GPT가 만든 쿼리 후보
CACHE_FILE   = "cve_cache.json"           # (service|version) 단위 CVE 캐시
EPSS_CACHE_FILE = "epss_cache.json"       # CVE 단위 EPSS 캐시

MIN_INTERVAL = 0.2
_last_call = 0.0

# 전역 캐시
SUGGESTIONS: Dict[str, Any] = {}
CVE_CACHE: Dict[str, Any] = {}   # key: "service|version" → {"used_query": ..., "cves": [...]}
EPSS_CACHE: Dict[str, Any] = {}  # key: "CVE-YYYY-NNNN" → {"cve":..., "epss":..., "percentile":..., "date":...}

# ── 문자열 전처리 ─────────────────────────────
STOPWORDS = {
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "suse",
    "oracle",
    "linux",
    "protocol",
    "rpc",
    "workgroup",
    "db",
    "engine",
    "metasploitable",
    "root",
    "shell",
    "openbsd",
    "solaris",
}


def _log_plus(msg: str) -> None:
    print(f"\033[32m[+]\033[0m [CVE] {msg}")


def _log_minus(msg: str) -> None:
    print(f"\033[31m[-]\033[0m [CVE] {msg}")


# ── 파일 로드/저장 ────────────────────────────
def _load_suggestions(path: str = SUGGEST_FILE) -> Dict[str, Any]:
    if not os.path.exists(path):
        _log_plus(f"Suggestion file '{path}' not found. GPT 쿼리 후보는 사용하지 않습니다.")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _log_plus(f"Loaded {len(data)} query suggestions from '{path}'.")
            return data
        _log_minus(f"Suggestion file '{path}' is not a JSON object. Ignoring.")
        return {}
    except Exception as e:
        _log_minus(f"Failed to load suggestion file '{path}': {e!r}")
        return {}


def _load_cache(path: str = CACHE_FILE) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except Exception as e:
        _log_minus(f"Failed to load CVE cache file '{path}': {e!r}")
        return {}


def _save_cache(path: str = CACHE_FILE) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(CVE_CACHE, f, indent=2, ensure_ascii=False)
        _log_plus(f"Saved CVE cache to '{path}'.")
    except Exception as e:
        _log_minus(f"Failed to save CVE cache to '{path}': {e!r}")


def _load_epss_cache(path: str = EPSS_CACHE_FILE) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except Exception as e:
        _log_minus(f"Failed to load EPSS cache file '{path}': {e!r}")
        return {}


def _save_epss_cache(path: str = EPSS_CACHE_FILE) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(EPSS_CACHE, f, indent=2, ensure_ascii=False)
        _log_plus(f"Saved EPSS cache to '{path}'.")
    except Exception as e:
        _log_minus(f"Failed to save EPSS cache to '{path}': {e!r}")


# 모듈 import 시 한 번 로드
SUGGESTIONS = _load_suggestions()
CVE_CACHE   = _load_cache()
EPSS_CACHE  = _load_epss_cache()


# ── EPSS 조회 ─────────────────────────────────
def get_epss(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    FIRST.org EPSS API에서 단일 CVE의 EPSS 정보를 받아온다.
    반환 예: {'cve': 'CVE-2011-2523', 'epss': '0.97345', 'percentile': '0.9991', 'date': '2024-09-01'}
    """
    global EPSS_CACHE

    if not cve_id:
        return None

    # 1) 캐시 먼저 확인
    cached = EPSS_CACHE.get(cve_id)
    if cached:
        return cached

    url = "https://api.first.org/data/v1/epss"
    params = {"cve": cve_id}

    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code != 200:
            _log_minus(f"EPSS API HTTP {r.status_code} for {cve_id}")
            return None

        data = r.json().get("data", [])
        if not data:
            return None

        info = data[0]  # {'cve':..., 'epss':..., 'percentile':..., 'date':...}

        EPSS_CACHE[cve_id] = info
        _save_epss_cache()
        # 필요시 rate limit 완화용 딜레이 (심하면 0.1~0.2)
        time.sleep(0.1)

        return info

    except Exception as e:
        _log_minus(f"EPSS API error for {cve_id}: {e!r}")
        return None


# ── 쿼리 후보 생성 ────────────────────────────
def _normalize_tokens(service: str, version: str) -> List[str]:
    s = f"{service} {version}".lower()
    s = re.sub(r"\(.*?\)", " ", s)
    s = re.sub(r"[/,#]", " ", s)
    tokens = [t for t in re.split(r"\s+", s) if t]

    cleaned: List[str] = []
    for t in tokens:
        if t in STOPWORDS:
            continue
        cleaned.append(t)

    return cleaned


def _split_product_and_version(tokens: List[str]) -> (str, str):
    version_token = None
    version_index = None

    for i, t in enumerate(tokens):
        if any(c.isdigit() for c in t):
            version_token = t
            version_index = i
            break

    if version_token is None:
        product = " ".join(tokens)
        return product.strip(), ""

    product_tokens = tokens[:version_index]
    if not product_tokens:
        product_tokens = tokens[version_index + 1 :]

    product = " ".join(product_tokens).strip()

    m = re.match(r"(\d+(?:\.\d+){0,2})", version_token)
    if m:
        ver = m.group(1)
    else:
        ver = version_token

    return product, ver


def _build_query_candidates(service: str, version: str) -> List[str]:
    """
    우선순위:
      0) query_suggestions.json 에 (service|version) 키가 있으면 그 리스트 그대로 사용
      1) raw: "service version"
      2) product + version_simple
      3) product
      4) service + product
    """
    key = f"{service}|{version}"
    if SUGGESTIONS:
        qs = SUGGESTIONS.get(key)
        if isinstance(qs, list):
            cleaned = [str(q).strip() for q in qs if isinstance(q, str) and q.strip()]
            if cleaned:
                return cleaned

    candidates: List[str] = []
    raw = f"{service} {version}".strip()
    if raw:
        candidates.append(raw.lower())

    tokens = _normalize_tokens(service, version)
    if tokens:
        product, ver = _split_product_and_version(tokens)
    else:
        product, ver = "", ""

    base_product = product or service.lower().strip()

    if base_product and ver:
        candidates.append(f"{base_product} {ver}")

    if base_product:
        candidates.append(base_product)

    s = service.lower().strip()
    if s and s not in base_product:
        combo = f"{s} {base_product}"
        candidates.append(combo)

    seen = set()
    out: List[str] = []
    for q in candidates:
        q = q.strip()
        if not q or q in seen:
            continue
        seen.add(q)
        out.append(q)

    return out


# ── 로컬 CVE API 호출 + 캐시 ─────────────────
def _query_local_cves(service: str, version: str, limit: int = 30) -> Dict[str, Any]:
    """
    반환값:
      {
        "query": 사용된 검색어 (또는 None),
        "cves":  [ {id, score, summary}, ... ]
      }

    캐시 정책:
    - key = "service|version"
    - 캐시에 cves가 non-empty로 들어있으면 무조건 재사용
    - cves가 비어있는 경우는 캐시에 저장하지 않고, 다음에도 다시 질의
    """
    global _last_call, CVE_CACHE

    cache_key = f"{service}|{version}"
    cached = CVE_CACHE.get(cache_key)
    if cached and cached.get("cves"):
        _log_plus(f"Using cached CVEs for {cache_key} (query='{cached.get('used_query')}').")
        return {
            "query": cached.get("used_query"),
            "cves": cached.get("cves", []),
        }

    queries = _build_query_candidates(service, version)
    used_query: Optional[str] = None
    results: List[Dict[str, Any]] = []

    for q in queries:
        now = time.time()
        delta = now - _last_call
        if delta < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - delta)

        params = {"q": q, "limit": str(limit)}

        try:
            _log_plus(f"Querying local CVE-Search for: {q}")
            resp = requests.get(LOCAL_CVE_API_ENDPOINT, params=params, timeout=30)
            _last_call = time.time()
        except Exception as e:
            _log_minus(f"Error calling local CVE API for q='{q}': {e!r}")
            continue

        if resp.status_code != 200:
            _log_minus(f"Local CVE API HTTP {resp.status_code} for q='{q}': {resp.text[:200]}")
            continue

        try:
            data = resp.json()
        except Exception as e:
            _log_minus(f"JSON decode error for q='{q}': {e!r}, body={resp.text[:200]}")
            continue

        cves = data.get("cves", [])
        if not isinstance(cves, list):
            continue

        tmp: List[Dict[str, Any]] = []
        for c in cves:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if not cid:
                continue
            tmp.append(
                {
                    "id": cid,
                    "score": c.get("score"),
                    "summary": c.get("summary"),
                }
            )

        if tmp:
            used_query = q
            results = tmp
            break

    # 결과 있음 → 캐시에 저장 (다음부터 재사용)
    if used_query and results:
        CVE_CACHE[cache_key] = {
            "used_query": used_query,
            "cves": results,
        }
        _save_cache()

    return {
        "query": used_query,
        "cves": results,
    }


# ── 플러그인 외부 인터페이스 ─────────────────
def enum_cves(service: str, version: str, port: str) -> Dict[str, Any]:
    """
    dispatcher에서 호출하는 엔트리포인트.

    입력:
      - service: "ftp"
      - version: "vsftpd 2.3.4"
      - port   : "21"

    반환:
      {
        "used_query": "...",
        "cves": [...],
        "high_score": {id, score, summary, epss?, ...} 또는 None
      }
    """
    res = _query_local_cves(service, version, limit=30)
    cves: List[Dict[str, Any]] = res.get("cves", [])
    used_query = res.get("query")

    # ── EPSS 값 주입 ──────────────────────────
    for c in cves:
        cve_id = c.get("id")
        if not cve_id:
            continue

        epss_info = get_epss(cve_id)
        if not epss_info:
            continue

        # 문자열일 수 있으니 float 변환
        try:
            c["epss"] = float(epss_info.get("epss", 0.0))
        except Exception:
            c["epss"] = 0.0

        try:
            c["epss_percentile"] = float(epss_info.get("percentile", 0.0))
        except Exception:
            c["epss_percentile"] = 0.0

        c["epss_date"] = epss_info.get("date")

    high = None
    if cves:
        high = max(cves, key=lambda c: (c.get("score") or 0.0))

    return {
        "used_query": used_query,
        "cves": cves,
        "high_score": high,
    }

