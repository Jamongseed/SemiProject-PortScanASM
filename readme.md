PortScanASM

공격자가 바로 쓸 수 있는 포트 기반 익스플로잇 정보를 자동 생성하는 스캐너 및 시각화 대시보드입니다.

이 프로젝트는 포트 스캔 결과를 기반으로 서비스·버전 인식 → 취약점 후보 매핑(CVE) → 공격 벡터 제안 → 익스플로잇 플러그인 감지 → 대시보드 시각화까지 한 번에 제공하는 통합 공격 보조 도구입니다.

CTF·실전 침투 테스트에서 가장 시간을 잡아먹는 “어디에, 무엇을, 어떻게 공격할 것인가?”를 최대한 자동화하는 것이 목표입니다.

주요 기능 (Features)
```
✔ 고정밀 포트 스캐닝 (Nmap 기반)

빠르고 정확한 open/filtered/closed 감지

Service / Version 자동 파싱

추가 fingerprint 기반 Stack Guessing 지원
```
```
✔ 서비스 기반 취약점 후보(CVE) 자동 매핑

“ftp vsftpd 2.3.4” → CVE 자동 추천

Local CVE-Search 서버 연동 가능

GPT 기반 취약점 후보 보완 추천(Optional)
```
```
✔ Exploit 후보 분석 플러그인 시스템

plugins/ 디렉토리에 신규 취약점 분석 모듈 쉽게 추가

서비스 버전 기반 자동 트리거

공격자가 바로 활용 가능한 Exploit 힌트 출력
```
```
✔ 시각화 대시보드 (dashboard.py)

JSON 스캔 결과를 가독성 높은 형태로 분석

포트별 공격 가능성·취약점 목록을 UI로 표시

포트 기반 공격 체인 흐름 확인 가능
```
```
✔ GPT Query Suggestion Engine

스캐닝된 서비스 정보만으로
이 서비스에 어떤 취약점이 가능할까? 를 자동 질의

반복 실행 시 캐싱 기능으로 비용 절약
```

프로젝트 구조 (Project Structure)
```
PortScanASM/
├── main.py                     # 핵심 스캔 및 분석 엔진
├── dashboard.py                # 시각화 대시보드 출력
├── gpt_query_suggest_cached.py # GPT 기반 자동 분석 모듈
├── core/                       # 포트/서비스 분석 로직
├── plugins/                    # 서비스 기반 Exploit 후보 모듈
├── requirements.txt            # Installation
└── README.md
```
설치 방법 (Installation)
Requirements

Ubuntu / Linux 환경

Python 3.10+

Nmap

(Optional) Local CVE-Search 서버

(Optional) GPT/OpenAI API Key

```
Install
git clone https://github.com/Jamongseed/SemiProject-PortScanASM.git
cd SemiProject-PortScanASM
pip install -r requirements.txt
```
사용 방법 (Usage)
기본 포트 스캔 + 분석
```
python3 main.py
```

예:
```
python3 main.py
```
```
분석 결과 대시보드 출력
python3 dashboard.py results.json
```
```
GPT 기반 취약점 후보 분석 실행
python3 gpt_query_suggest_cached.py
```
🔌 플러그인 시스템 (Plugin System)

plugins/ 안에 Python 모듈을 추가하면 자동으로 인식된다.

플러그인이 수행하는 역할:

서비스 이름/버전을 입력받아 취약점 후보 탐지

공격 가능한 Exploit 체인 제시

실제 사용 가능한 공격 스크립트 방향성 추천

Nmap 결과와 결합하여 자동 활성화

예:
```
plugins/
└── ftp_vsftpd_234.py
```
