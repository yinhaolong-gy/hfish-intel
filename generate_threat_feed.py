#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 濞佽儊鎯呮姤鑷姩鍖栫敓鎴愯剼鏈?v5.0
鍔熻兘锛氬叏铚滅綈鏁版嵁 + 寮卞彛浠ゅ瓧鍏?+ 瓒嬪娍鍥?+ 涓栫晫鍦板浘 + CSV瀵煎嚭 + 鍒嗚湝缃愮粺璁?"""

import requests
import pandas as pd
from datetime import datetime, timedelta
from jinja2 import Template
import os
import json
import urllib3
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 閰嶇疆鍖哄煙 ====================
HFISH_BASE_URL = "https://127.0.0.1:4433"
API_KEY = "SiFtBHLWzBmcRjndOoQEwPAjvBSBefxSDfvxMoxXwjetfnELGjXIbTZvhFZceacI"

END_TIME = datetime.now()
START_TIME = END_TIME - timedelta(days=90)

OUTPUT_DIR = "./docs"
OUTPUT_FILE = "index.html"

# ==================== 1. 鏀诲嚮API ====================
def fetch_attack_logs():
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    headers = {"Content-Type": "application/json"}
    params = {"api_key": API_KEY}
    payload = {
        "start_time": int(START_TIME.timestamp()),
        "end_time": int(END_TIME.timestamp()),
        "page": 1, "page_size": 5000
    }
    try:
        r = requests.post(url, headers=headers, params=params, json=payload, verify=False, timeout=30)
        data = r.json()
        if data.get("response_code") == 0:
            return data.get("data", [])
    except Exception as e:
        print(f"鏀诲嚮API澶辫触: {e}")
    return []

# ==================== 2. 璐﹀彿API ====================
def fetch_accounts():
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    headers = {"Content-Type": "application/json"}
    params = {"api_key": API_KEY}
    payload = {"page": 1, "page_size": 5000}
    try:
        r = requests.post(url, headers=headers, params=params, json=payload, verify=False, timeout=30)
        data = r.json()
        if data.get("response_code") == 0:
            return data.get("data", [])
    except Exception as e:
        print(f"璐﹀彿API澶辫触: {e}")
    return []

# ==================== 3. 寮卞彛浠ょ粺璁?====================
def get_top_passwords(accounts):
    pws = [a.get("password", "") for a in accounts if a.get("password")]
    return Counter(pws).most_common(10)

def get_top_usernames(accounts):
    uns = [a.get("username", "") for a in accounts if a.get("username")]
    return Counter(uns).most_common(5)

# ==================== 4. 鏁版嵁娓呮礂 ====================
def process_data(raw_logs):
    if not raw_logs:
        return pd.DataFrame(), {}
    df = pd.DataFrame(raw_logs)

    column_mapping = {
        "attack_ip": "鏀诲嚮婧怚P",
        "ip_location": "鍦扮悊浣嶇疆",
        "client_name": "铚滅綈鑺傜偣",
        "service_name": "鏈嶅姟绫诲瀷",
        "service_port": "绔彛",
        "create_time": "鏀诲嚮鏃堕棿"
    }
    cols = [c for c in column_mapping if c in df.columns]
    df = df[cols].copy()
    df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns}, inplace=True)

    if "鏀诲嚮鏃堕棿" in df.columns:
        df["鏀诲嚮鏃堕棿"] = pd.to_datetime(df["鏀诲嚮鏃堕棿"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
    if "鍦扮悊浣嶇疆" in df.columns:
        df["鍥藉"] = df["鍦扮悊浣嶇疆"].apply(lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x)

    all_honeypots = ["SSH铚滅綈", "TCP绔彛鐩戝惉", "Elasticsearch铚滅綈", "Telnet铚滅綈",
                     "FTP铚滅綈", "HTTP浠ｇ悊铚滅綈", "MYSQL铚滅綈", "REDIS铚滅綈",
                     "Tomcat铚滅綈", "Weblogic铚滅綈"]
    honeypot_counts = df["鏈嶅姟绫诲瀷"].value_counts().to_dict() if "鏈嶅姟绫诲瀷" in df.columns else {}
    honeypot_data = {hp: honeypot_counts.get(hp, 0) for hp in all_honeypots}

    stats = {
        "total_attacks": len(df),
        "unique_ips": df["鏀诲嚮婧怚P"].nunique() if "鏀诲嚮婧怚P" in df.columns else 0,
        "top_ips": df["鏀诲嚮婧怚P"].value_counts().head(10).to_dict() if "鏀诲嚮婧怚P" in df.columns else {},
        "top_services": df["鏈嶅姟绫诲瀷"].value_counts().head(10).to_dict() if "鏈嶅姟绫诲瀷" in df.columns else {},
        "top_countries": df["鍥藉"].value_counts().head(10).to_dict() if "鍥藉" in df.columns else {},
        "honeypot_data": honeypot_data,
        "active_honeypots": sum(1 for v in honeypot_data.values() if v > 0),
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }
    return df, stats

# ==================== 5. 涓栫晫鍦板浘鏁版嵁 ====================
def generate_map_data(df):
    country_name_map = {
        "涓浗": "China", "缇庡浗": "United States", "淇勭綏鏂?: "Russia",
        "鍔犳嬁澶?: "Canada", "鏂板姞鍧?: "Singapore", "鏃ユ湰": "Japan",
        "闊╁浗": "South Korea", "寰峰浗": "Germany", "鑻卞浗": "United Kingdom",
        "娉曞浗": "France", "鍗板害": "India", "宸磋タ": "Brazil",
        "婢冲ぇ鍒╀簹": "Australia", "鑽峰叞": "Netherlands", "瓒婂崡": "Vietnam",
        "涔屽厠鍏?: "Ukraine", "娉㈠叞": "Poland", "鎰忓ぇ鍒?: "Italy",
        "瑗跨彮鐗?: "Spain", "鐟炲吀": "Sweden", "鐟炲＋": "Switzerland",
        "鍦熻€冲叾": "Turkey", "浼婃湕": "Iran", "娉板浗": "Thailand",
        "椹潵瑗夸簹": "Malaysia", "鍗板害灏艰タ浜?: "Indonesia"
    }
    if "鍥藉" in df.columns and not df.empty:
        country_counts = df["鍥藉"].value_counts().to_dict()
        countries = []
        for cn_name, count in country_counts.items():
            en_name = country_name_map.get(cn_name, cn_name)
            countries.append({"name": en_name, "value": count})
        max_count = max(country_counts.values()) if country_counts else 1
        data = {"countries": countries, "maxCount": max_count}
        with open(os.path.join(OUTPUT_DIR, "country_data.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

# ==================== 6. 鍥捐〃鏁版嵁 ====================
def generate_chart_data(df):
    if "鏀诲嚮鏃堕棿" in df.columns and not df.empty:
        df["鏃ユ湡"] = pd.to_datetime(df["鏀诲嚮鏃堕棿"]).dt.strftime("%m-%d")
        daily = df["鏃ユ湡"].value_counts().sort_index()
        return json.dumps({"dates": daily.index.tolist()[-7:], "counts": daily.values.tolist()[-7:]})
    return json.dumps({"dates": [], "counts": []})

# ==================== 7. HTML 妯℃澘 ====================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HFish 濞佽儊鎯呮姤鐩戞帶涓績</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary-color: #00d4ff;
            --secondary-color: #7c3aed;
            --accent-color: #06b6d4;
            --bg-dark: #0a0a14;
            --bg-card: rgba(255,255,255,0.04);
            --border-color: rgba(0,212,255,0.15);
        }
        body {
            font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', -apple-system, sans-serif;
            background: linear-gradient(135deg, #0a0a14 0%, #0f172a 30%, #1e1b4b 60%, #0a0a14 100%);
            min-height: 100vh;
            padding: 25px 20px;
            color: #e2e8f0;
            position: relative;
            overflow-x: hidden;
        }
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0,212,255,0.08) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(124,58,237,0.06) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(6,182,212,0.05) 0%, transparent 40%);
            pointer-events: none;
            z-index: 0;
        }
        .container { 
            max-width: 1440px; 
            margin: 0 auto; 
            position: relative;
            z-index: 1;
        }
        .header { 
            text-align: center; 
            margin-bottom: 40px; 
            padding: 35px;
            background: linear-gradient(135deg, rgba(0,212,255,0.08) 0%, rgba(124,58,237,0.06) 50%, rgba(6,182,212,0.05) 100%);
            border-radius: 24px;
            border: 1px solid rgba(0,212,255,0.15);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            backdrop-filter: blur(20px);
        }
        .header h1 { 
            font-size: 3.2em; 
            background: linear-gradient(135deg, #00d4ff, #7c3aed, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: none;
            margin-bottom: 12px;
            letter-spacing: 3px;
            font-weight: 700;
        }
        .header .update-time { 
            font-size: 1em; 
            color: #94a3b8;
            opacity: 0.9;
            font-weight: 500;
        }
        .header .update-time span {
            color: var(--primary-color);
            font-weight: 600;
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 18px; 
            margin-bottom: 35px; 
        }
        .stat-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(0,212,255,0.18); 
            border-radius: 20px; 
            padding: 25px;
            text-align: center; 
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(from 0deg, transparent, rgba(0,212,255,0.1), transparent, rgba(124,58,237,0.1), transparent);
            animation: rotate 8s linear infinite;
        }
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .stat-card::after {
            content: '';
            position: absolute;
            inset: 1px;
            background: linear-gradient(135deg, rgba(10,10,20,0.9) 0%, rgba(30,27,75,0.8) 100%);
            border-radius: 19px;
            z-index: 0;
        }
        .stat-card:hover { 
            transform: translateY(-8px) scale(1.02); 
            border-color: var(--primary-color);
            box-shadow: 0 20px 60px rgba(0,212,255,0.25), 0 0 40px rgba(124,58,237,0.1);
        }
        .stat-card:hover::before {
            animation-duration: 3s;
        }
        .stat-card-inner {
            position: relative;
            z-index: 1;
        }
        .stat-icon {
            font-size: 1.8em;
            margin-bottom: 12px;
            display: block;
        }
        .stat-number { 
            font-size: 2.8em; 
            font-weight: 700; 
            background: linear-gradient(135deg, #00d4ff, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: none;
            margin-bottom: 8px;
        }
        .stat-label { 
            color: #94a3b8; 
            font-size: 0.92em; 
            letter-spacing: 1.5px;
            font-weight: 500;
        }
        .section {
            background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(0,212,255,0.12); 
            border-radius: 24px; 
            padding: 35px; 
            margin-bottom: 35px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.2);
            position: relative;
            overflow: hidden;
        }
        .section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, rgba(0,212,255,0.4), rgba(124,58,237,0.4), transparent);
        }
        .section-title { 
            font-size: 1.5em; 
            background: linear-gradient(135deg, #00d4ff, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 25px; 
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(0,212,255,0.12);
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
        }
        .section-title::before {
            content: '';
            width: 4px;
            height: 28px;
            background: linear-gradient(180deg, #00d4ff, #7c3aed);
            border-radius: 2px;
            box-shadow: 0 0 15px rgba(0,212,255,0.5);
        }
        .chart-container { 
            width: 100%; 
            height: 400px; 
            border-radius: 16px;
            background: rgba(0,0,0,0.3);
            padding: 20px;
        }
        .map-container { 
            width: 100%; 
            height: 550px; 
            border-radius: 16px;
            background: rgba(0,0,0,0.3);
            padding: 15px;
            position: relative;
        }
        .map-container::before {
            content: '馃實';
            position: absolute;
            top: 15px;
            right: 20px;
            font-size: 1.5em;
            opacity: 0.3;
        }
        .honeypot-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
            gap: 18px; 
        }
        .hp-item {
            background: linear-gradient(135deg, rgba(0,212,255,0.08) 0%, rgba(124,58,237,0.05) 100%);
            border: 1px solid rgba(0,212,255,0.15);
            border-radius: 16px; 
            padding: 22px; 
            text-align: center;
            transition: all 0.35s ease;
            position: relative;
            overflow: hidden;
        }
        .hp-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            transform: scaleX(0);
            transition: transform 0.35s ease;
        }
        .hp-item:hover {
            border-color: rgba(0,212,255,0.4);
            transform: translateY(-5px) scale(1.03);
            box-shadow: 0 12px 30px rgba(0,212,255,0.15);
        }
        .hp-item:hover::before {
            transform: scaleX(1);
        }
        .hp-name { 
            color: #94a3b8; 
            font-size: 0.82em; 
            margin-bottom: 10px;
            font-weight: 500;
        }
        .hp-count { 
            font-size: 2em; 
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .hp-zero { 
            color: #475569; 
            background: none;
            -webkit-background-clip: text;
            -webkit-text-fill-color: #475569;
        }
        .top-list { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
        }
        .list-item { 
            background: rgba(0,0,0,0.4); 
            border-radius: 16px; 
            padding: 22px;
            border: 1px solid rgba(0,212,255,0.1);
            transition: all 0.3s ease;
        }
        .list-item:hover {
            border-color: rgba(0,212,255,0.25);
            transform: translateY(-3px);
        }
        .list-item h3 { 
            color: var(--primary-color); 
            margin-bottom: 15px; 
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 600;
        }
        .rank-item { 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            padding: 10px 12px; 
            margin-bottom: 6px;
            border-radius: 8px;
            color: #cbd5e1; 
            font-size: 0.9em;
            transition: all 0.25s ease;
            cursor: pointer;
        }
        .rank-item:hover {
            background: rgba(0,212,255,0.1);
            transform: translateX(5px);
        }
        .rank-item:last-child {
            margin-bottom: 0;
        }
        .rank-index {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background: rgba(0,212,255,0.2);
            color: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8em;
            font-weight: 600;
            margin-right: 10px;
        }
        .rank-index.top {
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            color: #1f2937;
        }
        .rank-value { 
            font-weight: 700; 
            color: var(--primary-color);
            font-size: 1.1em;
        }
        .data-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
            font-size: 0.9em; 
            color: #cbd5e1;
        }
        .data-table th { 
            background: linear-gradient(135deg, rgba(0,212,255,0.15) 0%, rgba(124,58,237,0.1) 100%);
            color: var(--primary-color); 
            padding: 14px 16px; 
            text-align: left;
            font-weight: 600;
            border-radius: 10px 10px 0 0;
            font-size: 0.95em;
        }
        .data-table th:first-child { border-radius: 10px 0 0 0; }
        .data-table th:last-child { border-radius: 0 10px 0 0; }
        .data-table td { 
            padding: 12px 16px; 
            border-bottom: 1px solid rgba(255,255,255,0.05);
            transition: background 0.2s ease;
        }
        .data-table tr:hover { 
            background: rgba(0,212,255,0.05);
        }
        .data-table tr:hover td {
            color: #fff;
        }
        .badge { 
            background: linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(124,58,237,0.15) 100%);
            color: var(--primary-color); 
            padding: 6px 14px; 
            border-radius: 20px; 
            font-size: 0.85em;
            font-weight: 500;
            border: 1px solid rgba(0,212,255,0.2);
        }
        .footer { 
            text-align: center; 
            color: #64748b; 
            margin-top: 50px; 
            padding: 25px;
            font-size: 0.95em;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .footer p:first-child {
            margin-bottom: 8px;
        }
        .warning { 
            color: #f87171;
            font-weight: 500;
        }
        .highlight {
            background: linear-gradient(135deg, rgba(0,212,255,0.1), rgba(124,58,237,0.08));
            border-left: 3px solid var(--primary-color);
            padding: 18px;
            border-radius: 0 10px 10px 0;
            margin-bottom: 18px;
        }
        .visual-map-legend {
            position: absolute;
            bottom: 25px;
            right: 25px;
            background: rgba(0,0,0,0.7);
            border: 1px solid rgba(0,212,255,0.2);
            border-radius: 12px;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            z-index: 10;
        }
        .visual-map-legend .legend-title {
            color: #94a3b8;
            font-size: 0.85em;
            font-weight: 500;
        }
        .visual-map-legend .legend-gradient {
            width: 120px;
            height: 16px;
            border-radius: 8px;
            background: linear-gradient(90deg, #1a1a3e, #0d47a1, #1565c0, #00d4ff, #06b6d4);
        }
        .visual-map-legend .legend-labels {
            display: flex;
            justify-content: space-between;
            width: 120px;
            margin-top: 5px;
            font-size: 0.75em;
            color: #94a3b8;
        }
        @media (max-width: 768px) {
            .header h1 { font-size: 2em; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .stat-number { font-size: 2em; }
            .section { padding: 22px; }
            .chart-container { height: 300px; }
            .map-container { height: 420px; }
            .top-list { grid-template-columns: 1fr; }
        }
        @media (max-width: 480px) {
            .stats-grid { grid-template-columns: 1fr; }
            .header h1 { font-size: 1.6em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>馃洝锔?HFish 濞佽儊鎯呮姤鐩戞帶涓績</h1>
            <p class="update-time">馃搳 鐩戞帶鍛ㄦ湡: <span>{{ stats.time_range }}</span> | 鏈€鍚庢洿鏂? <span>{{ last_update }}</span></p>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-card-inner"><div class="stat-icon">鈿旓笍</div><div class="stat-number">{{ stats.total_attacks }}</div><div class="stat-label">鎬绘敾鍑绘鏁?/div></div></div>
            <div class="stat-card"><div class="stat-card-inner"><div class="stat-icon">馃寪</div><div class="stat-number">{{ stats.unique_ips }}</div><div class="stat-label">鐙珛鏀诲嚮IP</div></div></div>
            <div class="stat-card"><div class="stat-card-inner"><div class="stat-icon">馃敡</div><div class="stat-number">{{ services_count }}</div><div class="stat-label">鏈嶅姟绫诲瀷鏁?/div></div></div>
            <div class="stat-card"><div class="stat-card-inner"><div class="stat-icon">馃實</div><div class="stat-number">{{ countries_count }}</div><div class="stat-label">娑夊強鍥藉/鍦板尯</div></div></div>
            <div class="stat-card"><div class="stat-card-inner"><div class="stat-icon">馃懁</div><div class="stat-number">{{ account_count }}</div><div class="stat-label">璐﹀彿璧勪骇鏁版嵁</div></div></div>
            <div class="stat-card"><div class="stat-card-inner"><div class="stat-icon">馃幆</div><div class="stat-number">{{ stats.active_honeypots }}</div><div class="stat-label">娲昏穬铚滅綈鏁?/div></div></div>
        </div>

        <div class="section">
            <h2 class="section-title">馃搱 鏀诲嚮瓒嬪娍鍒嗘瀽锛堣繎7澶╋級</h2>
            <div class="chart-container"><canvas id="attackChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">馃椇锔?鏀诲嚮鏉ユ簮鍏ㄧ悆鍒嗗竷</h2>
            <div class="map-container" id="worldMap">
                <div class="visual-map-legend">
                    <div class="legend-title">鏀诲嚮瀵嗗害</div>
                    <div><div class="legend-gradient"></div><div class="legend-labels"><span>浣?/span><span>楂?/span></div></div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">馃幆 鍚勮湝缃愬彈鏀诲嚮缁熻</h2>
            <div class="honeypot-grid">
                {% for name, count in stats.honeypot_data.items() %}
                <div class="hp-item">
                    <div class="hp-name">{{ name }}</div>
                    <div class="hp-count {% if count == 0 %}hp-zero{% endif %}">{{ count }}</div>
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">馃搳 鏀诲嚮缁熻鍒嗘瀽</h2>
            <div class="top-list">
                <div class="list-item">
                    <h3>馃敐 Top 10 鏀诲嚮婧怚P</h3>
                    {% set ip_index = 1 %}
                    {% for ip, count in stats.top_ips.items() %}
                    <div class="rank-item"><span class="rank-index {% if ip_index <= 3 %}top{% endif %}">{{ ip_index }}</span><span>{{ ip }}</span><span class="rank-value">{{ count }}</span></div>
                    {% set ip_index = ip_index + 1 %}
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>馃實 鏀诲嚮鏉ユ簮鍥藉</h3>
                    {% set country_index = 1 %}
                    {% for country, count in stats.top_countries.items() %}
                    <div class="rank-item"><span class="rank-index {% if country_index <= 3 %}top{% endif %}">{{ country_index }}</span><span>{{ country }}</span><span class="rank-value">{{ count }}</span></div>
                    {% set country_index = country_index + 1 %}
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>馃攽 寮卞彛浠ゅ瓧鍏?TOP 10</h3>
                    {% set pwd_index = 1 %}
                    {% for pwd, count in top_passwords %}
                    <div class="rank-item"><span class="rank-index {% if pwd_index <= 3 %}top{% endif %}">{{ pwd_index }}</span><span class="warning">{{ pwd }}</span><span class="rank-value">{{ count }}</span></div>
                    {% set pwd_index = pwd_index + 1 %}
                    {% endfor %}
                    {% if not top_passwords %}<div class="rank-item" style="justify-content: center;"><span>鏆傛棤寮卞彛浠ゆ暟鎹?/span></div>{% endif %}
                </div>
                <div class="list-item">
                    <h3>馃懁 楂橀鐢ㄦ埛鍚?TOP 5</h3>
                    {% set user_index = 1 %}
                    {% for user, count in top_usernames %}
                    <div class="rank-item"><span class="rank-index {% if user_index <= 3 %}top{% endif %}">{{ user_index }}</span><span>{{ user }}</span><span class="rank-value">{{ count }}</span></div>
                    {% set user_index = user_index + 1 %}
                    {% endfor %}
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">馃搵 鏈€鏂版敾鍑昏鎯呰褰?/h2>
            <div style="overflow-x:auto; max-height:450px; overflow-y:auto; border-radius: 12px; background: rgba(0,0,0,0.3);">
                <table class="data-table"><thead><tr><th>鏀诲嚮婧怚P</th><th>鍦扮悊浣嶇疆</th><th>鏈嶅姟绫诲瀷</th><th>绔彛</th><th>鏀诲嚮鏃堕棿</th></tr></thead><tbody>
                    {% for _, row in df.head(100).iterrows() %}
                    <tr><td><span class="badge">{{ row.get('鏀诲嚮婧怚P', '-') }}</span></td><td>{{ row.get('鍦扮悊浣嶇疆', '-') }}</td><td>{{ row.get('鏈嶅姟绫诲瀷', '-') }}</td><td>{{ row.get('绔彛', '-') }}</td><td>{{ row.get('鏀诲嚮鏃堕棿', '-') }}</td></tr>{% endfor %}</tbody></table>
            </div>
        </div>

        <div class="footer">
            <p>馃 HFish 铚滅綈绯荤粺鑷姩閲囬泦 路 姣?灏忔椂鏇存柊 路 姣曚笟璁捐浣滃搧</p>
            <p style="font-size: 0.85em; color: #475569;">漏 2024 Security Monitoring System 路 All Rights Reserved</p>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('attackChart').getContext('2d');
        const data = {{ chart_data | safe }};
        const gradient = ctx.createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, 'rgba(0,212,255,0.3)');
        gradient.addColorStop(0.5, 'rgba(0,212,255,0.1)');
        gradient.addColorStop(1, 'rgba(0,212,255,0)');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.dates,
                datasets: [{
                    label: '鏀诲嚮娆℃暟',
                    data: data.counts,
                    borderColor: '#00d4ff',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#00d4ff',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 6,
                    pointHoverRadius: 10,
                    pointHoverBackgroundColor: '#7c3aed',
                    pointHoverBorderColor: '#fff',
                    pointHoverBorderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#94a3b8',
                            font: { size: 13, weight: '500' },
                            padding: 20
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0,0,0,0.9)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(0,212,255,0.3)',
                        borderWidth: 1,
                        padding: 15,
                        cornerRadius: 10,
                        displayColors: false,
                        callbacks: {
                            label: function(context) {
                                return '鏀诲嚮娆℃暟: ' + context.parsed.y + ' 娆?;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(255,255,255,0.04)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#94a3b8',
                            font: { size: 12 }
                        }
                    },
                    y: {
                        grid: {
                            color: 'rgba(255,255,255,0.04)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#94a3b8',
                            font: { size: 12 }
                        },
                        beginAtZero: true
                    }
                },
                animation: {
                    duration: 1500,
                    easing: 'easeOutQuart'
                }
            }
        });
    </script>

    <script src="https://cdn.jsdelivr.net/npm/echarts/map/js/world.js"></script>
    <script>
        fetch('country_data.json')
          .then(res => res.json())
          .then(data => {
              var myChart = echarts.init(document.getElementById('worldMap'));
              var option = {
                  backgroundColor: 'transparent',
                  tooltip: { 
                      trigger: 'item', 
                      formatter: function(p) { 
                          return '<div style="padding: 8px 12px;">' +
                                 '<div style="font-weight: 600; color: #00d4ff; margin-bottom: 4px;">' + p.name + '</div>' +
                                 '<div style="color: #94a3b8;">鏀诲嚮娆℃暟: <span style="color: #06b6d4; font-weight: 600; font-size: 1.2em;">' + (p.value || 0) + '</span> 娆?/div>' +
                                 '</div>';
                      }, 
                      backgroundColor: 'rgba(0,0,0,0.9)', 
                      textStyle: { color: '#e2e8f0' },
                      borderColor: 'rgba(0,212,255,0.4)',
                      borderWidth: 1,
                      padding: 12,
                      borderRadius: 10,
                      boxShadow: '0 4px 20px rgba(0,0,0,0.4)'
                  },
                  visualMap: { 
                      show: false,
                      min: 0, 
                      max: data.maxCount || 100, 
                      inRange: { 
                          color: ['#1a1a3e', '#0d47a1', '#1565c0', '#0284c7', '#00d4ff', '#06b6d4'] 
                      }
                  },
                  series: [{ 
                      type: 'map', 
                      map: 'world', 
                      roam: true, 
                      zoom: 1.3,
                      center: [100, 30],
                      aspectScale: 0.75,
                      label: {
                          show: false
                      },
                      emphasis: { 
                          label: { 
                              show: true, 
                              color: '#fff', 
                              fontSize: 12,
                              fontWeight: 'bold',
                              textBorderColor: 'rgba(0,0,0,0.8)',
                              textBorderWidth: 2
                          }, 
                          itemStyle: { 
                              areaColor: '#00d4ff', 
                              shadowBlur: 25, 
                              shadowColor: 'rgba(0,212,255,0.7)',
                              borderColor: '#fff',
                              borderWidth: 2
                          } 
                      }, 
                      itemStyle: { 
                          borderColor: 'rgba(255,255,255,0.12)', 
                          areaColor: function(params) {
                              if (params.value && params.value > 0) {
                                  var maxCount = data.maxCount || 100;
                                  var ratio = params.value / maxCount;
                                  if (ratio > 0.8) return '#06b6d4';
                                  if (ratio > 0.6) return '#00d4ff';
                                  if (ratio > 0.4) return '#0284c7';
                                  if (ratio > 0.2) return '#1565c0';
                                  return '#0d47a1';
                              }
                              return 'rgba(30, 30, 60, 0.6)';
                          },
                          borderWidth: 1,
                          shadowBlur: function(params) {
                              return params.value && params.value > 0 ? 10 : 0;
                          },
                          shadowColor: function(params) {
                              return params.value && params.value > 0 ? 'rgba(0,212,255,0.3)' : 'transparent';
                          }
                      }, 
                      data: data.countries || [],
                      selectedMode: false
                  }]
              };
              myChart.setOption(option);
              window.addEventListener('resize', function() { myChart.resize(); });
          })
          .catch(err => {
              var myChart = echarts.init(document.getElementById('worldMap'));
              var option = {
                  backgroundColor: 'transparent',
                  tooltip: { 
                      trigger: 'item', 
                      formatter: function(p) { 
                          return '<div style="padding: 8px 12px;">' +
                                 '<div style="font-weight: 600; color: #00d4ff; margin-bottom: 4px;">' + p.name + '</div>' +
                                 '<div style="color: #94a3b8;">鏀诲嚮娆℃暟: <span style="color: #06b6d4; font-weight: 600; font-size: 1.2em;">0</span> 娆?/div>' +
                                 '</div>';
                      }, 
                      backgroundColor: 'rgba(0,0,0,0.9)', 
                      textStyle: { color: '#e2e8f0' },
                      borderColor: 'rgba(0,212,255,0.4)',
                      borderWidth: 1,
                      padding: 12,
                      borderRadius: 10
                  },
                  visualMap: { 
                      show: false,
                      min: 0, 
                      max: 100, 
                      inRange: { 
                          color: ['#1a1a3e', '#0d47a1', '#1565c0', '#0284c7', '#00d4ff', '#06b6d4'] 
                      }
                  },
                  series: [{ 
                      type: 'map', 
                      map: 'world', 
                      roam: true, 
                      zoom: 1.3,
                      center: [100, 30],
                      aspectScale: 0.75,
                      label: {
                          show: false
                      },
                      emphasis: { 
                          label: { 
                              show: true, 
                              color: '#fff', 
                              fontSize: 12,
                              fontWeight: 'bold'
                          }, 
                          itemStyle: { 
                              areaColor: '#00d4ff', 
                              shadowBlur: 25, 
                              shadowColor: 'rgba(0,212,255,0.7)'
                          } 
                      }, 
                      itemStyle: { 
                          borderColor: 'rgba(255,255,255,0.12)', 
                          areaColor: 'rgba(30, 30, 60, 0.6)', 
                          borderWidth: 1 
                      }, 
                      data: [] 
                  }]
              };
              myChart.setOption(option);
              window.addEventListener('resize', function() { myChart.resize(); });
          });
    </script>
</body>
</html>
"""
            text-align: center;
