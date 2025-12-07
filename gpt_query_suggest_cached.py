#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
1) Nmap -sV 결과로부터 service / version 목록을 추출하고,
2) 각 (service, version)에 대해 GPT API로 CVE 검색용 쿼리 후보를 뽑는다.
3) 결과를 query_suggestions.json 파일에 캐시해서, 같은 조합은 다시 호출하지 않는다.

- 메타스플로이터 한 번 스캔해서 쿼리 후보를 쭉 뽑아두고,
  이후에는 이 파일을 보고 수동으로 DB 검색 실험을 해볼 수 있음.

※ 수정: TARGET을 하드코딩하지 않고, CLI 인자로 받도록 변경.
"""

import json
import os
import subprocess
import re
import time
import argparse
from typing import List, Dict, Any

from openai import OpenAI

# ───────────────── 설정 ─────────────────
SUGGEST_FILE = "query_suggestions.json"

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise SystemExit("환경변수 OPENAI_API_KEY 가 설정되어 있지 않습니다.")

client = OpenAI(api_key=OPENAI_API_KEY)


def run_nmap(target: str) -> str:
    """
    nmap -sV 실행 후 원본 출력 문자열을 반환.
    """
    cmd = ["nmap", "-sT", "-sV", "-Pn", "-p-", "--min-rate", "1000", target]
    print(f"[+] Running Nmap scan on {target} ...")
    out = subprocess.check_output(cmd, text=True)
    print(out.rstrip())
    return out


def parse_nmap(nmap_output: str) -> List[Dict[str, str]]:
    """
    Nmap -sV 출력에서 (port, service, version) 목록을 추출.
    """
    print("[+] Parsing Nmap result...")
    services: List[Dict[str, str]] = []

    for line in nmap_output.splitlines():
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


def strip_code_fences(content: str) -> str:
    content = content.strip()
    if not content.startswith("```"):
        return content

    lines = content.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]

    return "\n".join(lines).strip()


def suggest_cve_queries(service: str, version: str, top_n: int = 5) -> List[str]:
    prompt = f"""
You are helping to map Nmap service/version strings to useful CVE database search queries.

I will give you:
- Nmap service name
- Nmap version string (often messy: includes OS, distro, workgroup names, etc.)

Your task:
1. Infer the actual product name and relevant version(s) that should be used to search a CVE database.
2. Return a small list of search query candidates that would work well for a MongoDB text index over fields like "summary", "vulnerable_product", "products", "vendors".
3. Keep queries short and focused. Prefer PRODUCT + MAJOR/MINOR VERSION.

Very important rules:
- Output MUST be valid JSON with this exact schema:
  {{
    "queries": ["query1", "query2", ...]
  }}
- Do NOT add any explanations or extra fields.
- Put the most promising query first.
- At most {top_n} queries.

Examples:

Input:
  service = "netbios-ssn"
  version = "Samba smbd 3.X - 4.X (workgroup: WORKGROUP)"

Output JSON:
  {{
    "queries": [
      "samba smbd 3",
      "samba smbd 4",
      "samba 3.x 4.x"
    ]
  }}

Input:
  service = "exec"
  version = "netkit-rsh rexecd"

Output JSON:
  {{
    "queries": [
      "netkit-rsh rexecd",
      "rexecd",
      "netkit rexecd"
    ]
  }}

Now, here is the real input:

service = "{service}"
version = "{version}"

Return ONLY the JSON object.
"""

    resp = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": "You are a precise CVE search query generator."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )

    content = resp.choices[0].message.content.strip()
    content = strip_code_fences(content)

    try:
        data = json.loads(content)
        queries = data.get("queries", [])
        return [q for q in queries if isinstance(q, str) and q.strip()]
    except Exception as e:
        print("[!] Failed to parse JSON from GPT:", e)
        print("    Raw content:", content)
        return []


def load_suggestions(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except Exception as e:
        print(f"[!] Failed to load suggestion file '{path}': {e!r}")
        return {}


def save_suggestions(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved suggestions to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate CVE search query suggestions using GPT based on Nmap -sV output."
    )
    parser.add_argument(
        "target",
        help="Nmap -sV를 돌릴 타겟 (IP 또는 호스트네임)",
    )
    args = parser.parse_args()
    target = args.target

    suggestions = load_suggestions(SUGGEST_FILE)
    print(f"[*] Loaded {len(suggestions)} existing suggestion entries from {SUGGEST_FILE}")

    nmap_output = run_nmap(target)
    services = parse_nmap(nmap_output)

    for svc in services:
        service = svc["service"]
        version = svc["version"]

        key = f"{service}|{version}"
        print("=" * 80)
        print(f"Service : {service}")
        print(f"Version : {version}")

        if key in suggestions:
            print("[*] Using cached suggestions:")
            for i, q in enumerate(suggestions[key], 1):
                print(f"  {i}. {q}")
            continue

        print("[+] Calling GPT API to suggest queries...")
        queries = suggest_cve_queries(service, version, top_n=5)
        suggestions[key] = queries

        if queries:
            print("[*] Suggested CVE search queries:")
            for i, q in enumerate(queries, 1):
                print(f"  {i}. {q}")
        else:
            print("[*] No queries suggested (empty list).")

        time.sleep(0.5)

    save_suggestions(SUGGEST_FILE, suggestions)


if __name__ == "__main__":
    main()

