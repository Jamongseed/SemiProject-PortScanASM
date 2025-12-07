import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import json
import os
import random
import numpy as np
import io
import subprocess
import sys
from datetime import datetime, timedelta
import calendar 
from bs4 import BeautifulSoup
import urllib.parse
import csv
import requests

# [라이브러리 안전 임포트]
try:
    from openai import OpenAI
except ImportError:
    pass

# -----------------------------------------------------------------------------
# 0. Page Configuration & CSS Styling
# -----------------------------------------------------------------------------
st.set_page_config(page_title="NOT FOUND Security Dashboard", layout="wide")

# [Custom CSS]
st.markdown("""
    <style>
    /* 전체 폰트 및 배경 */
    .stApp {
        background-color: #FFFFFF;
        color: #333333;
        font-family: 'Roboto', 'Helvetica Neue', Arial, sans-serif;
    }
    
    /* 텍스트 색상 */
    h1, h2, h3, h4, h5, h6, p, div, span, label, li {
        color: #333333 !important;
        font-weight: normal !important;
    }
    
    /* 숫자 메트릭 스타일 */
    [data-testid="metric-container"]:nth-child(2) [data-testid="stMetricValue"] {
        color: #D32F2F !important; /* Critical만 빨강 */
    }
    [data-testid="stMetricValue"] {
        color: #424242 !important; /* 나머지는 진한 회색 */
        font-weight: normal !important;
    }
    
    /* 컨테이너 및 Expander 스타일 */
    .block-container { padding-top: 2rem; }
    div[data-testid="stExpander"] {
        border: 1px solid #E0E0E0;
        background-color: #FFFFFF;
        border-radius: 6px;
        box-shadow: none;
        margin-bottom: 10px;
    }
    
    /* 버튼 스타일 */
    button[kind="primary"] {
        background-color: #D32F2F;
        border: none;
        color: white !important;
    }
    
    /* 키워드 태그 스타일 */
    .keyword-tag-critical {
        background-color: #D32F2F;
        color: white !important;
        padding: 5px 12px;
        border-radius: 15px;
        margin: 3px;
        display: inline-block;
        font-size: 14px;
    }
    .keyword-tag-high {
        background-color: #FBC02D;
        color: #333333 !important;
        padding: 5px 12px;
        border-radius: 15px;
        margin: 3px;
        display: inline-block;
        font-size: 14px;
        font-weight: bold !important;
    }
    </style>
    """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 1. Constants & Settings
# -----------------------------------------------------------------------------
SEVERITY_COLORS = {
    "Critical": "#D32F2F", # Red
    "High": "#FBC02D",     # Yellow
    "Medium": "#9E9E9E",   # Medium Gray
    "Low": "#E0E0E0"       # Light Gray
}

STATUS_COLORS = {
    "Open": "#D32F2F",       # Red
    "In Progress": "#FBC02D",# Yellow
    "Resolved": "#757575",   # Dark Gray
    "Risk Accepted": "#BDBDBD" # Light Gray
}

# Global NVD Top 10 (Mock Data for Comparison Reference)
GLOBAL_TOP_10 = [
    {"id": "CVE-2011-2523", "desc": "Vsftpd Backdoor"},
    {"id": "CVE-2021-44228", "desc": "Log4Shell"},
    {"id": "CVE-2017-0144", "desc": "EternalBlue"},
    {"id": "CVE-2020-1472", "desc": "Zerologon"},
    {"id": "CVE-2007-2447", "desc": "Samba Usermap"},
    {"id": "CVE-2019-11510", "desc": "Pulse Secure VPN"},
    {"id": "CVE-2010-2075", "desc": "UnrealIRCd"},
    {"id": "CVE-2023-32971", "desc": "Apache TomCat Info"},
    {"id": "CVE-2022-26134", "desc": "Confluence OGNL"},
    {"id": "CVE-2014-0160", "desc": "Heartbleed"}
]

EXPLOIT_EPSS_THRESHOLD = 0.6

EXPLOIT_SCENARIOS = {
    "CVE-2011-2523": {"name": "Vsftpd Backdoor", "logs": ["Connecting...", "Root shell opened"], "desc": "vsftpd 2.3.4 backdoor."},
    "CVE-2007-2447": {"name": "Samba Usermap", "logs": ["Payload sent...", "Command executed"], "desc": "Samba remote execution."},
    "CVE-2010-2075": {"name": "UnrealIRCd Backdoor", "logs": ["Triggering...", "Shell spawned"], "desc": "UnrealIRCd backdoor."}
}

SCANNER_SCRIPT_NAME = "main.py"

# -----------------------------------------------------------------------------
# 2. Utility Functions (Real Data Only)
# -----------------------------------------------------------------------------
@st.cache_data
def load_data(uploaded_file_content=None):
    """
    - 구포맷: {"results": [ {service, version, port, cves:[...]} ]}
    - 신포맷: {"target": "...", "services": [ {port, service, version, enum:{cve_search:{cves:[...]}} } ]}
    를 모두 지원한다.
    """
    raw_data = None

    # 1) 업로드된 파일이 있으면 그걸 먼저 사용
    if uploaded_file_content:
        try:
            uploaded_file_content.seek(0)
            content = uploaded_file_content.read().decode('utf-8')
            raw_data = json.loads(content)
        except Exception:
            return pd.DataFrame()
    else:
        # 2) 기본 파일 경로 (recon_result.json)
        file_path = 'recon_result.json'
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    raw_data = json.load(f)
            except Exception:
                return pd.DataFrame()
        else:
            return pd.DataFrame()

    if not raw_data:
        return pd.DataFrame()

    # 어떤 포맷인지 판별
    if 'results' in raw_data:
        records = raw_data['results']
        mode = 'results'
    elif 'services' in raw_data:
        records = raw_data['services']
        mode = 'services'
    else:
        # 알 수 없는 포맷
        return pd.DataFrame()

    processed_list = []

    for result in records:
        if mode == 'results':
            service_name = result.get('service', 'Unknown')
            version_name = result.get('version', 'Unknown')
            port = result.get('port', '0')
            cves = result.get('cves', [])
        else:  # mode == 'services'
            service_name = result.get('service', 'Unknown')
            version_name = result.get('version', 'Unknown')
            port = result.get('port', '0')

            enum = result.get('enum') or {}
            cve_block = enum.get('cve_search') or {}
            cves = cve_block.get('cves', [])

        if not cves:
            continue

        product_label = f"{service_name} ({version_name})"

        for cve in cves:
            cve_id = cve.get('id', 'Unknown')
            cvss = cve.get('score', 0.0)
            summary = cve.get('summary', 'No description.')

            # epss 있으면 쓰고, 없으면 0
            real_epss = cve.get('epss')
            epss = float(real_epss) if real_epss is not None else 0.0

            try:
                year = int(cve_id.split('-')[1])
            except Exception:
                year = 2025

            if cvss >= 9.0:
                severity = "Critical"
            elif cvss >= 7.0:
                severity = "High"
            elif cvss >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"

            # 데모용 날짜 생성 (포트+CVSS로 seed 줘서 재현 가능)
            try:
                seed_val = int(port) + int(float(cvss) * 100)
                random.seed(seed_val)
            except Exception:
                random.seed(42)

            base_year = 2025
            day_offset = random.randint(0, 364)
            detect_date = datetime(base_year, 1, 1) + timedelta(days=day_offset)

            processed_list.append({
                "CVE_NAME": cve_id,
                "PORT": port,
                "PRODUCT_NAME": product_label,
                "SERVICE_TYPE": service_name,
                "CVSS_SCORE": float(cvss) if cvss else 0.0,
                "EPSS_SCORE": epss,
                "SEVERITY": severity,
                "EXPLOIT_STATUS": epss >= EXPLOIT_EPSS_THRESHOLD,
                "PUBLISH_YEAR": year,
                "DESCRIPTION": summary,
                "DETECT_DATE": detect_date,
                "DETECT_DATE_STR": detect_date.strftime("%Y-%m-%d"),
                "YEAR": detect_date.year,
                "IS_DETECTED": True,
                "NVD_SEARCHES": random.randint(100, 1000),
            })

    return pd.DataFrame(processed_list)

EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

@st.cache_data(show_spinner=False)
def _load_exploitdb_index() -> list[dict]:
    """
    Exploit-DB GitLab에서 files_exploits.csv를 받아와
    Dict 리스트로 캐시해 둔다.
    """
    resp = requests.get(EXPLOITDB_CSV_URL, timeout=20)
    resp.raise_for_status()  # 200이 아니면 예외

    # CSV 텍스트 → DictReader
    buf = io.StringIO(resp.text)
    reader = csv.DictReader(buf)
    rows = [row for row in reader]
    return rows


@st.cache_data(show_spinner=False)
def fetch_exploitdb_for_cve(cve_id: str):
    """
    CSV 인덱스를 이용해 특정 CVE가 들어있는 Exploit-DB 레코드를 찾는다.

    반환: [ {edb_id, title, url, date, verified}, ... ]
    """
    cve = cve_id.upper().strip()
    rows = _load_exploitdb_index()

    results: list[dict] = []
    for r in rows:
        codes = (r.get("codes") or "").upper()
        if cve not in codes:
            continue

        edb_id = (r.get("id") or r.get("EDB-ID") or "").strip()
        if not edb_id:
            continue

        title = (r.get("description") or "").strip()
        date_text = (r.get("date") or "").strip()

        # verified 컬럼이 있으면 대충 해석해서 bool로
        verified_raw = (r.get("verified") or "").strip().lower()
        verified = verified_raw in ("1", "true", "yes", "y", "✔", "✓")

        url = f"https://www.exploit-db.com/exploits/{edb_id}"

        results.append(
            {
                "edb_id": edb_id,
                "title": title,
                "url": url,
                "date": date_text,
                "verified": verified,
            }
        )

    return results

def get_top_keywords(df):
    import re
    from collections import Counter
    text = " ".join(df['DESCRIPTION'].astype(str).tolist()).lower()
    words = re.findall(r'\b[a-z]{4,15}\b', text)
    stopwords = {'allow', 'remote', 'attackers', 'user', 'service', 'arbitrary', 'code', 'execution', 'vulnerability', 'via', 'this', 'that', 'with', 'from', 'version', 'earlier', 'before', 'allows', 'support', 'properly'}
    filtered_words = [w for w in words if w not in stopwords]
    return Counter(filtered_words).most_common(12)

def to_excel(df):
    output = io.BytesIO()
    try:
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Sheet1')
    except ImportError:
        return None
    return output.getvalue()

def run_scanner_script():
    if not os.path.exists(SCANNER_SCRIPT_NAME):
        st.error(f"Scanner script '{SCANNER_SCRIPT_NAME}' not found.")
        return False
    try:
        result = subprocess.run([sys.executable, SCANNER_SCRIPT_NAME], capture_output=True, text=True)
        if result.returncode == 0:
            return True
        else:
            st.error(f"Scanner failed: {result.stderr}")
            return False
    except Exception as e:
        st.error(f"Error executing scanner: {e}")
        return False

# -----------------------------------------------------------------------------
# 3. Sidebar
# -----------------------------------------------------------------------------
if 'df' not in st.session_state:
    st.session_state['df'] = load_data()
    st.session_state['plan_data'] = pd.DataFrame()
if 'selected_cves' not in st.session_state:
    st.session_state['selected_cves'] = []
if 'last_uploaded_file' not in st.session_state:
    st.session_state['last_uploaded_file'] = None

# Init Plan Data
if not st.session_state['df'].empty and st.session_state['plan_data'].empty:
    plan_init = st.session_state['df'][['CVE_NAME', 'PRODUCT_NAME', 'CVSS_SCORE', 'SEVERITY']].copy()
    plan_init['Status'] = 'Open'
    plan_init['Priority'] = 'Medium'
    plan_init['Owner'] = 'Security Team'
    plan_init['Note'] = ''
    st.session_state['plan_data'] = plan_init

uploaded_file = st.sidebar.file_uploader("Upload JSON", type=['json'], help="스캔된 결과 JSON 파일을 이곳에 업로드하여 분석을 시작합니다.")
if uploaded_file is not None:
    file_id = f"{uploaded_file.name}_{uploaded_file.size}"
    if st.session_state['last_uploaded_file'] != file_id:
        with st.spinner("Analyzing..."):
            st.cache_data.clear()
            new_df = load_data(uploaded_file_content=uploaded_file)
            if not new_df.empty:
                st.session_state.df = new_df
                st.session_state.plan_data = pd.DataFrame()
                st.session_state['last_uploaded_file'] = file_id
                st.rerun()

with st.sidebar:
    st.caption("Ver 57.1 (Graph Size Fix & Immediate Search)")
    
    openai_api_key = st.text_input("OpenAI API Key", type="password", help="AI 분석 기능(Ask AI Analyst) 사용 시 필요한 API 키입니다.")

    st.markdown("---")
    
    if not st.session_state.df.empty:
        start_date = st.session_state.df['DETECT_DATE'].min().date()
        end_date = st.session_state.df['DETECT_DATE'].max().date()
    else:
        start_date = datetime.now().date()
        end_date = datetime.now().date()
        
    st.subheader("Scanner Settings", help="취약점 스캔 모드를 선택합니다.")
    scan_mode = st.radio("Scan Mode", ["Virtual Demo", "Real Scan"], horizontal=True)
    
    if scan_mode == "Virtual Demo":
        if st.button("Run Demo Scan", use_container_width=True, help="가상의 샘플 데이터를 사용하여 대시보드 기능을 테스트합니다."):
            st.cache_data.clear()
            st.session_state.df = load_data() 
            st.session_state.plan_data = pd.DataFrame()
            st.rerun()
    else:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Ubuntu", help="우분투 환경에서 실제 스캐너를 실행합니다."): 
                with st.spinner("Scanning..."):
                    if run_scanner_script():
                        st.cache_data.clear()
                        st.session_state.df = load_data()
                        st.success("Complete!")
                        time.sleep(1)
                        st.rerun()
        with c2:
            if st.button("Windows", help="윈도우 환경에서 실제 스캐너를 실행합니다."): 
                with st.spinner("Scanning..."):
                    if run_scanner_script():
                        st.cache_data.clear()
                        st.session_state.df = load_data()
                        st.success("Complete!")
                        time.sleep(1)
                        st.rerun()

    st.markdown("---")
    
    # [수정] Search Helper를 Placeholder로 미리 공간만 확보
    # 이렇게 하면 Main UI에서 데이터 선택 시 바로 이 공간을 업데이트하여 딜레이 없이 표시 가능
    search_helper_ph = st.empty()

    st.markdown("---")
    st.subheader("Filters", help="위험도 기준으로 데이터를 필터링합니다.")
    current_df = st.session_state.df
    selected_severity = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    
    if not current_df.empty:
        filtered_df = current_df[
            (current_df['SEVERITY'].isin(selected_severity)) &
            (current_df['DETECT_DATE'].dt.date >= start_date) &
            (current_df['DETECT_DATE'].dt.date <= end_date)
        ]
    else:
        filtered_df = pd.DataFrame()

# -----------------------------------------------------------------------------
# 4. Main Dashboard UI
# -----------------------------------------------------------------------------
st.markdown("<h1 style='margin-bottom:0;'>NOT FOUND Integrated Dashboard</h1>", unsafe_allow_html=True)
st.caption("Security Insight: 현재 보안 상태에 대한 직관적인 요약입니다.")

if filtered_df.empty:
    st.warning(f"No data loaded. Please run a scan or check your filters.")
    st.stop()

# --- KPI & Keywords ---
col_kpi, col_chart = st.columns([1, 1])
with col_kpi:
    st.markdown("### Executive Summary", help="전체 취약점 현황을 요약하여 보여주는 핵심 지표(KPI)입니다.")
    c1, c2 = st.columns(2)
    
    c1.metric("Total Vulnerabilities", f"{len(filtered_df)}", help="발견된 총 취약점 수입니다.")
    c2.metric("Critical Risks", f"{filtered_df[filtered_df['SEVERITY']=='Critical'].shape[0]}", help="즉시 조치가 필요한 치명적 위험 개수입니다.")
    
    c3, c4 = st.columns(2)
    c3.metric("Exploitable", f"{filtered_df['EXPLOIT_STATUS'].sum()}", help="공격 코드가 존재하여 악용 가능한 취약점 수입니다.")
    c4.metric("Avg CVSS", f"{filtered_df['CVSS_SCORE'].mean():.1f}", help="전체 취약점의 평균 위험 점수입니다.")

with col_chart:
    st.markdown("### Vulnerability Main Themes", help="취약점 설명에서 자주 등장하는 핵심 단어를 추출하여 보여줍니다.")
    with st.expander("사용 가이드 및 분석 팁"):
        st.write("이 섹션은 스캔된 서버의 주요 취약점 키워드를 직관적으로 보여줍니다. 붉은색 태그는 가장 빈번하게 발견된 핵심 문제입니다.")

    keywords = get_top_keywords(filtered_df)
    if keywords:
        html_content = "<div>"
        max_count = keywords[0][1] if keywords else 1
        for word, count in keywords:
            if count > max_count * 0.5:
                html_content += f"<span class='keyword-tag-critical'>{word} ({count})</span>"
            else:
                html_content += f"<span class='keyword-tag-high'>{word} ({count})</span>"
        html_content += "</div>"
        st.markdown(html_content, unsafe_allow_html=True)

st.markdown("---")

# --- Tabs ---
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "Dashboard", "Calendar", "Statistics", "Comparison", "Deep Analysis", "Remediation", "FAQ"
])

# TAB 1: Dashboard
with tab1:
    st.subheader("Interactive Analysis", help="데이터를 다각도로 분석하고 시각화하는 메인 대시보드입니다.")
    
    # 1. Table
    selection = st.dataframe(
        filtered_df[['CVE_NAME', 'PRODUCT_NAME', 'SEVERITY', 'CVSS_SCORE', 'EPSS_SCORE', 'DETECT_DATE_STR']],
        use_container_width=True, hide_index=True, on_select="rerun", selection_mode="multi-row"
    )
    
    # Data Selection Logic
    selected_cves = []
    if selection.selection.rows:
        for idx in selection.selection.rows:
            selected_cves.append(filtered_df.iloc[idx]['CVE_NAME'])
        st.session_state.selected_cves = selected_cves
    else:
        st.session_state.selected_cves = []
        
    # [수정] Immediate Sidebar Update
    # 표에서 선택이 발생하자마자 사이드바의 Placeholder를 업데이트합니다.
    with search_helper_ph.container():
        st.subheader("Search Helper", help="선택한 CVE를 구글에서 바로 검색합니다.")
        if st.session_state.selected_cves:
            last = st.session_state.selected_cves[-1]
            st.link_button(f"Search: {last}", f"https://www.google.com/search?q={last} vulnerability exploit")
        else:
            st.caption("목록에서 항목을 선택하세요.")
    
    # 2. Line Chart
    st.markdown("#### Overall Trend", help="연도별 취약점 발생 추이를 보여줍니다. 과거 레거시 문제인지 최신 위협인지 파악할 수 있습니다.")
    yearly = filtered_df.groupby(['PUBLISH_YEAR', 'SEVERITY']).size().reset_index(name='COUNT')
    fig_line = px.line(
        yearly, x="PUBLISH_YEAR", y="COUNT", color="SEVERITY",
        color_discrete_map=SEVERITY_COLORS, markers=True
    )
    if selected_cves:
        selected_years = filtered_df[filtered_df['CVE_NAME'].isin(selected_cves)]['PUBLISH_YEAR'].unique()
        for yr in selected_years:
            fig_line.add_vline(x=yr, line_dash="dot", line_color="#333333", opacity=0.5)
    fig_line.update_traces(line=dict(width=3))
    fig_line.update_layout(height=300, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    st.plotly_chart(fig_line, use_container_width=True)

    # 3. Main Charts (Risk Matrix & New Upward Graph)
    c_left, c_right = st.columns(2)
    with c_left:
        st.markdown("#### Risk Matrix", help="위험도(CVSS)와 공격확률(EPSS)의 상관관계를 보여줍니다. 우상단에 위치할수록 위험합니다.")
        fig_sc = px.scatter(
            filtered_df, x="CVSS_SCORE", y="EPSS_SCORE", color="SEVERITY",
            color_discrete_map=SEVERITY_COLORS,
            hover_data=['CVE_NAME'], opacity=0.7
        )
        fig_sc.update_traces(marker=dict(size=8, line=dict(width=0)))
        if selected_cves:
            h_df = filtered_df[filtered_df['CVE_NAME'].isin(selected_cves)]
            if not h_df.empty:
                fig_sc.add_trace(go.Scatter(
                    x=h_df['CVSS_SCORE'], y=h_df['EPSS_SCORE'],
                    mode='markers', 
                    marker=dict(size=15, color='rgba(0,0,0,0)', line=dict(color='#333333', width=3)),
                    showlegend=False, hoverinfo='skip'
                ))
        fig_sc.add_vline(x=7.0, line_dash="dash", line_color="#E0E0E0")
        fig_sc.update_layout(height=400)
        st.plotly_chart(fig_sc, use_container_width=True)
        
    with c_right:
        st.markdown("#### Real Risk Assessment", help="CVSS 점수와 EPSS(공격 확률)를 결합한 실질적 위험도를 보여줍니다. (CVSS * EPSS * 100)")
        
        filtered_df['RISK_SCORE'] = filtered_df['CVSS_SCORE'] * filtered_df['EPSS_SCORE'] * 100
        
        # [수정] 점 크기(size)를 8 -> 5로 축소, Opacity 0.6으로 설정하여 겹침 방지
        fig_up = px.scatter(
            filtered_df, x="CVSS_SCORE", y="RISK_SCORE", color="SEVERITY",
            color_discrete_map=SEVERITY_COLORS,
            hover_data=['CVE_NAME'], opacity=0.6,
            labels={"RISK_SCORE": "Real Risk Score (CVSS x EPSS x 100)"}
        )
        fig_up.update_traces(marker=dict(size=5, line=dict(width=0)))
        
        # Highlight logic
        if selected_cves:
            h_df = filtered_df[filtered_df['CVE_NAME'].isin(selected_cves)]
            if not h_df.empty:
                fig_up.add_trace(go.Scatter(
                    x=h_df['CVSS_SCORE'], y=h_df['RISK_SCORE'],
                    mode='markers', 
                    marker=dict(size=15, color='rgba(0,0,0,0)', line=dict(color='#333333', width=3)),
                    showlegend=False, hoverinfo='skip'
                ))
        fig_up.update_layout(height=400)
        st.plotly_chart(fig_up, use_container_width=True)

    st.markdown("---")
    st.markdown("#### Severity Breakdown", help="발견된 취약점들의 위험도별 비율을 도넛 차트로 보여줍니다.")
    sev_counts = filtered_df['SEVERITY'].value_counts().reset_index()
    sev_counts.columns = ['Severity', 'Count']
    
    fig_donut = px.pie(
        sev_counts, values='Count', names='Severity', hole=0.6,
        color='Severity', color_discrete_map=SEVERITY_COLORS
    )
    fig_donut.update_traces(textinfo='percent+label', textfont_size=14)
    fig_donut.update_layout(height=400, showlegend=True)
    st.plotly_chart(fig_donut, use_container_width=True)
    
    # 4. Service Trend
    st.markdown("#### Service Trends", help="어떤 서비스에서 취약점이 많이 발생하는지 보여줍니다. 시간 흐름에 따른 변화를 파악할 수 있습니다.")
    service_trend = filtered_df.groupby(['SERVICE_TYPE', 'PUBLISH_YEAR']).size().reset_index(name='COUNT')
    fig_small = px.area(
        service_trend, x="PUBLISH_YEAR", y="COUNT", 
        facet_col="SERVICE_TYPE", facet_col_wrap=6,
        color_discrete_sequence=['#757575'], 
        height=300
    )
    fig_small.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        showlegend=False, margin=dict(t=30, l=0, r=0, b=0)
    )
    fig_small.for_each_annotation(lambda a: a.update(text=a.text.split("=")[-1]))
    st.plotly_chart(fig_small, use_container_width=True)

# TAB 2: Calendar
with tab2:
    st.header(f"Monthly Vulnerability Calendar ({start_date} ~ {end_date})", help="월별로 취약점 발견 현황을 달력 형태의 히트맵과 목록으로 확인합니다.")
    st.caption("ℹ️ 목록을 클릭하면 달력에 테두리가 생깁니다.")

    cal_base_df = filtered_df.copy()
    cal_base_df['Month_No'] = cal_base_df['DETECT_DATE'].dt.month
    cal_base_df['Day'] = cal_base_df['DETECT_DATE'].dt.day

    months_list = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    
    for m_idx, m_name in enumerate(months_list):
        current_month_no = m_idx + 1
        m_df = cal_base_df[cal_base_df['Month_No'] == current_month_no].sort_values('Day').reset_index(drop=True)
        count_in_month = len(m_df)
        
        with st.expander(f"{m_name} ({count_in_month} Items)", expanded=(m_idx == 0)):
            if count_in_month == 0:
                st.info("No vulnerabilities detected this month.")
            else:
                c_cal, c_list = st.columns([1, 1])
                
                target_year = start_date.year
                _, num_days = calendar.monthrange(target_year, current_month_no)
                days_grid = []
                day_counts = m_df['Day'].value_counts().to_dict()
                
                week_num = 0
                for d in range(1, num_days + 1):
                    wd = calendar.weekday(target_year, current_month_no, d)
                    val = day_counts.get(d, 0)
                    days_grid.append({'Day': d, 'Week': week_num, 'Weekday': wd, 'Count': val})
                    if wd == 6: week_num += 1
                grid_df = pd.DataFrame(days_grid)

                list_key = f"list_{m_name}"
                cal_key = f"cal_{m_name}"

                clicked_day_from_cal = None
                if cal_key in st.session_state and st.session_state[cal_key].selection['points']:
                    p = st.session_state[cal_key].selection['points'][0]
                    try:
                        sel_wd, sel_w = p['x'], p['y']
                        row_match = grid_df[(grid_df['Weekday'] == sel_wd) & (grid_df['Week'] == sel_w)]
                        if not row_match.empty:
                            clicked_day_from_cal = row_match.iloc[0]['Day']
                    except: pass
                
                with c_list:
                    st.markdown("###### Vulnerability List")
                    
                    def highlight_matched_day(row):
                        if clicked_day_from_cal is not None and row['Day'] == clicked_day_from_cal:
                            return ['background-color: #FFF9C4; color: black; border: 2px solid #FBC02D'] * len(row)
                        return [''] * len(row)

                    st.dataframe(
                        m_df[['Day', 'DETECT_DATE_STR', 'CVE_NAME', 'SEVERITY']].style.apply(highlight_matched_day, axis=1),
                        use_container_width=True, hide_index=True,
                        on_select="rerun", selection_mode="multi-row",
                        key=list_key,
                        height=300
                    )
                
                selected_days_from_list = []
                if list_key in st.session_state and st.session_state[list_key].selection.rows:
                    sel_indices = st.session_state[list_key].selection.rows
                    valid_idx = [i for i in sel_indices if i < len(m_df)]
                    selected_days_from_list = m_df.iloc[valid_idx]['Day'].unique().tolist()

                with c_cal:
                    st.markdown(f"###### {m_name} Overview (Clickable)")
                    
                    text_labels = grid_df.apply(lambda r: str(r['Day']), axis=1)
                    
                    shapes = []
                    for d_hl in selected_days_from_list:
                        d_info = grid_df[grid_df['Day'] == d_hl]
                        if not d_info.empty:
                            w, wd = d_info.iloc[0]['Week'], d_info.iloc[0]['Weekday']
                            shapes.append(dict(type="rect", x0=wd-0.5, x1=wd+0.5, y0=w-0.5, y1=w+0.5, line=dict(color="#FBC02D", width=4), fillcolor="rgba(0,0,0,0)"))

                    fig_mosaic = go.Figure(data=go.Heatmap(
                        x=grid_df['Weekday'], y=grid_df['Week'], z=grid_df['Count'],
                        text=text_labels, texttemplate="%{text}", textfont={"size": 12},
                        colorscale="Greys", showscale=False, xgap=3, ygap=3,
                        hoverinfo='z+text'
                    ))
                    
                    fig_mosaic.update_layout(
                        height=300, margin=dict(l=10,r=10,t=10,b=10),
                        xaxis=dict(tickmode='array', tickvals=[0,1,2,3,4,5,6], ticktext=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], side='top', fixedrange=True),
                        yaxis=dict(autorange='reversed', showticklabels=False, fixedrange=True),
                        shapes=shapes, clickmode='event+select', dragmode=False
                    )
                    
                    st.plotly_chart(fig_mosaic, use_container_width=True, on_select="rerun", key=cal_key)
                    
                    if clicked_day_from_cal:
                        st.caption(f"📅 Filtered Day: {clicked_day_from_cal}")

# TAB 3: Statistics
with tab3:
    st.header("Top Vulnerabilities & Matching", help="내부 최다 취약점과 외부 중요 취약점을 비교 분석합니다.")
    
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Internal Top Detected", help="우리 서버에서 가장 많이 발견된 상위 10개 취약점입니다.")
        internal_top = filtered_df['CVE_NAME'].value_counts().head(10).reset_index()
        internal_top.columns = ['CVE', 'Count']
        st.dataframe(internal_top, use_container_width=True, hide_index=True)
        
    with c2:
        st.subheader("Global NVD Top 10 Matching", help="전 세계적으로 위험한 취약점이 내 서버에도 있는지 확인합니다.")
        internal_cves = set(filtered_df['CVE_NAME'].unique())
        nvd_rows = []
        for item in GLOBAL_TOP_10:
            cve = item['id']
            status = "Detected" if cve in internal_cves else "Safe"
            nvd_rows.append({"CVE": cve, "Description": item['desc'], "Status": status})
        
        nvd_df = pd.DataFrame(nvd_rows)
        st.dataframe(
            nvd_df, 
            column_config={
                "Status": st.column_config.TextColumn("Status", help="Detected = Action Required")
            },
            use_container_width=True, hide_index=True
        )

# TAB 4: Comparison
with tab4:
    st.header("Vulnerability Comparison", help="두 개의 취약점을 선택하여 상세 스펙을 비교합니다.")
    col_sel, col_viz = st.columns([1, 2])
    cves = filtered_df['CVE_NAME'].unique()
    idx_a, idx_b = 0, min(1, len(cves)-1)
    
    if len(st.session_state.selected_cves) >= 1: 
        try: idx_a = list(cves).index(st.session_state.selected_cves[-1])
        except: idx_a = 0
    
    with col_sel:
        v_a = st.selectbox("Select A", cves, index=idx_a, key='va')
        v_b = st.selectbox("Select B", cves, index=idx_b, key='vb')
    
    with col_viz:
        if v_a and v_b:
            d_a = filtered_df[filtered_df['CVE_NAME'] == v_a].iloc[0]
            d_b = filtered_df[filtered_df['CVE_NAME'] == v_b].iloc[0]
            comp_data = pd.DataFrame({
                'Metric': ['CVSS', 'EPSS (x10)'],
                f'{v_a}': [d_a['CVSS_SCORE'], d_a['EPSS_SCORE']*10],
                f'{v_b}': [d_b['CVSS_SCORE'], d_b['EPSS_SCORE']*10]
            }).melt(id_vars='Metric', var_name='CVE', value_name='Value')
            
            fig_comp = px.bar(
                comp_data, x='Metric', y='Value', color='CVE', barmode='group',
                color_discrete_sequence=['#D32F2F', '#757575'], height=300,
                text_auto='.1f'
            )
            fig_comp.update_traces(textposition='outside')
            st.plotly_chart(fig_comp, use_container_width=True)
            
            st.table(pd.DataFrame({
                "Item": ["Product", "Severity", "NVD Searches"], 
                f"{v_a}": [d_a['PRODUCT_NAME'], d_a['SEVERITY'], d_a['NVD_SEARCHES']], 
                f"{v_b}": [d_b['PRODUCT_NAME'], d_b['SEVERITY'], d_b['NVD_SEARCHES']]
            }))
            st.caption("ℹ️ NVD Searches: 해당 취약점에 대한 대중의 관심도(검색량)를 나타내는 지표입니다.")

# TAB 5: Deep Analysis
with tab5:
    st.header("Deep Vulnerability Analysis", help="단일 취약점에 대한 심층 분석 및 보고서 다운로드 기능입니다.")
    
    if len(st.session_state.selected_cves) >= 1: 
        try:
            target_index = list(cves).index(st.session_state.selected_cves[-1])
        except ValueError:
            target_index = 0
    else:
        target_index = 0

    target_cve = st.selectbox("Select Vulnerability", cves, index=target_index)
    
    if target_cve:
        info = filtered_df[filtered_df['CVE_NAME'] == target_cve].iloc[0]
        col_main, col_gauge = st.columns([2, 1])

        with col_main:
            st.markdown(f"## {target_cve}")
            st.markdown(f"Product: {info['PRODUCT_NAME']} | Port: {info['PORT']}")
            st.info(info['DESCRIPTION'])
            
            with st.expander("사용 가이드 및 DB 설명"):
                st.write("1) 아래 Exploit-DB 조회 버튼으로 공개 PoC 정보를 확인합니다.")
                st.write("2) 필요하면 NVD 공식 페이지와 AI 분석 버튼으로 추가 정보를 확인합니다.")
                st.write("※ 실제 익스플로잇 코드는 Exploit-DB 사이트에서 직접 확인하도록 구성했습니다.")

            # ---- Exploit-DB 조회 섹션 ----
            st.markdown("### 🔍 Exploit-DB Online Lookup")
            if st.button("Search Exploit-DB", key="btn_exploitdb",
                         help="Exploit-DB에서 이 CVE에 대한 PoC/익스플로잇을 검색합니다."):
                with st.spinner(f"Searching Exploit-DB for {target_cve} ..."):
                    exploits = fetch_exploitdb_for_cve(target_cve)

                if not exploits:
                    st.warning("Exploit-DB 검색 결과가 없습니다. (네트워크 문제 또는 해당 CVE 미등록 가능성)")
                else:
                    df_edb = pd.DataFrame(exploits)
                    st.dataframe(
                        df_edb[["edb_id", "title", "date", "verified"]],
                        hide_index=True,
                        width="stretch"
                    )

                    # 상위 몇 개는 바로 열 수 있는 링크 버튼 제공
                    st.caption("상위 Exploit-DB 항목 바로가기:")
                    for row in exploits[:3]:
                        label = f"Open EDB-{row['edb_id']}: {row['title']}"
                        st.link_button(label, row["url"])

            st.markdown("---")

            # NVD 공식 페이지 링크
            st.link_button(
                "View on NVD Official",
                f"https://nvd.nist.gov/vuln/detail/{target_cve}",
                help="NVD 공식 사이트의 해당 취약점 페이지로 이동합니다."
            )
            
            # OpenAI 기반 AI 분석 (선택)
            if openai_api_key:
                if st.button("Ask AI Analyst", help="OpenAI를 통해 해당 취약점에 대한 AI 분석을 요청합니다."):
                    try:
                        client = OpenAI(api_key=openai_api_key)
                        resp = client.chat.completions.create(
                            model="gpt-3.5-turbo",
                            messages=[{"role": "user", "content": f"Explain exploit paths and mitigation for {target_cve}."}]
                        )
                        st.success(resp.choices[0].message.content)
                    except Exception as e:
                        st.error(str(e))

            # 현재 CVE 정보 엑셀 다운로드
            single_df = pd.DataFrame([info])
            excel_data = to_excel(single_df)
            if excel_data:
                st.download_button(
                    "Report Download (Excel)",
                    data=excel_data,
                    file_name=f"{target_cve}.xlsx",
                    help="현재 보고 있는 취약점 정보를 엑셀 파일로 다운로드합니다."
                )
        
        with col_gauge:
            color_g = "#D32F2F" if info['SEVERITY'] == 'Critical' else ("#FBC02D" if info['SEVERITY'] == 'High' else "#757575")
            fig_donut = go.Figure(
                data=[
                    go.Pie(
                        labels=['Score', 'Safe Margin'],
                        values=[info['CVSS_SCORE'], 10 - info['CVSS_SCORE']],
                        hole=.7,
                        marker_colors=[color_g, '#E0E0E0']
                    )
                ]
            )
            fig_donut.update_layout(
                height=250,
                showlegend=False,
                annotations=[dict(text=str(info['CVSS_SCORE']), x=0.5, y=0.5, font_size=20, showarrow=False)]
            )
            st.plotly_chart(fig_donut, use_container_width=True)

# TAB 6: Remediation
with tab6:
    st.header("Action Plan & Status Matrix", help="조치 계획을 수립하고 진행 상황을 관리합니다.")
    with st.expander("사용 가이드 및 활용법"):
        st.write("""
        이 탭은 발견된 취약점의 조치 상태를 추적하고 관리하는 공간입니다.
        
        활용 방법:
        1. 상태 변경: 아래 표에서 Status(진행 상태)와 Priority(우선순위)를 클릭하여 변경합니다.
        2. 담당자 지정: Owner 컬럼에 담당자 이름을 입력합니다.
        3. 진척도 확인: 표 아래의 매트릭스 차트에서 색상 변화를 통해 전체적인 조치 현황을 시각적으로 확인합니다. (빨강: 시작 전, 노랑: 진행 중, 회색: 완료)
        4. 보고서 다운로드: Download Plan 버튼을 눌러 현재 계획을 엑셀 파일로 저장하여 보고용으로 사용합니다.
        """)

    current_plan = st.session_state.plan_data
    edited_plan = st.data_editor(
        current_plan,
        column_config={
            "Status": st.column_config.SelectboxColumn("Status", options=["Open", "In Progress", "Resolved", "Risk Accepted"], required=True),
            "Priority": st.column_config.SelectboxColumn("Priority", options=["Critical", "High", "Medium", "Low"], required=True),
            "Owner": st.column_config.TextColumn("Owner"),
            "Note": st.column_config.TextColumn("Note")
        },
        use_container_width=True, num_rows="fixed", key="plan_editor"
    )
    st.session_state.plan_data = edited_plan
    
    st.divider()
    st.subheader("Status Matrix (Product vs CVE)", help="조치 진행 상황을 매트릭스 형태로 한눈에 보여줍니다.")
    
    fig_mat = px.scatter(
        edited_plan, x="PRODUCT_NAME", y="CVE_NAME",
        color="Status", color_discrete_map=STATUS_COLORS,
        title="Remediation Status Overview",
        size='CVSS_SCORE', size_max=15
    )
    fig_mat.update_traces(marker=dict(line=dict(width=1, color='white'), opacity=0.9))
    fig_mat.update_layout(
        height=600,
        xaxis=dict(showgrid=True, gridcolor='#F5F5F5'),
        yaxis=dict(showgrid=True, gridcolor='#F5F5F5', type='category'),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(fig_mat, use_container_width=True)
    
    excel_plan = to_excel(edited_plan)
    if excel_plan:
        st.download_button("Download Plan", data=excel_plan, file_name="plan.xlsx", help="현재 작성된 조치 계획을 엑셀 파일로 다운로드합니다.")

# TAB 7: FAQ
with tab7:
    st.header("FAQ")
    st.markdown("자주 묻는 질문에 대한 답변입니다.")
    
    # [수정] About Project 이동
    with st.expander("개발 목적 및 사용 대상"):
        st.markdown("""
        **개발 목적**
        - 서버 보안 취약점의 시각적 식별 및 분석
        - 데이터 기반의 보안 조치 우선순위 결정
        
        **사용 대상**
        - 보안 담당자, 시스템 관리자, 모의해킹 전문가
        """)
        
    with st.expander("Q. 취약점 스캔은 어떻게 실행하나요?"):
        st.write("A. 사이드바의 Scanner Settings에서 데모 모드 또는 실제 OS 환경에 맞는 버튼을 클릭하여 실행할 수 있습니다.")
    with st.expander("Q. 조치 상태를 변경하면 어떻게 되나요?"):
        st.write("A. Remediation 탭의 표에서 상태를 변경하면, 아래 매트릭스 그래프의 점 색상이 실시간으로 변경되어 진척도를 파악할 수 있습니다.")
    with st.expander("Q. 색상은 무엇을 의미하나요?"):
        st.write("A. 빨강은 Critical, 노랑은 High, 회색은 그 외의 위험도를 나타냅니다.")
    with st.expander("Q. 다중 선택 기능은 무엇인가요?"):
        st.write("A. 대시보드 목록에서 Ctrl 키를 누르고 여러 항목을 선택하면, 모든 그래프에서 해당 항목들이 동시에 강조 표시됩니다.")
    with st.expander("Q. NVD 검색은 무엇인가요?"):
        st.write("A. Deep Analysis 탭에서 NVD 버튼을 누르면 미국 국립취약점데이터베이스(NVD)의 해당 CVE 페이지로 이동합니다.")
