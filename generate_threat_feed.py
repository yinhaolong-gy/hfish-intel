#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v6.1 (优化版)
功能：全蜜罐数据采集 + 弱口令字典 + 攻击趋势图 + 世界地图 +
      攻击时段热力图 + 数据对比 + CSV导出 + 分蜜罐统计
"""

import requests
import pandas as pd
import os
import json
import urllib3
from datetime import datetime, timedelta
from jinja2 import Template
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 配置区域 ====================
HFISH_BASE_URL = "https://127.0.0.1:4433"
API_KEY = "SiFtBHLWzBmcRjndOoQEwPAjvBSBefxSDfvxMoxXwjetfnELGjXIbTZvhFZceacI"

# 时间范围：最近90天
END_TIME = datetime.now()
START_TIME = END_TIME - timedelta(days=90)

# 上周时间范围（用于数据对比）
LAST_WEEK_END = START_TIME
LAST_WEEK_START = LAST_WEEK_END - timedelta(days=7)

OUTPUT_DIR = "./docs"
OUTPUT_FILE = "index.html"
CSV_FILE = "threat_data.csv"

# ==================== 1. 攻击数据采集 ====================
def fetch_attack_logs(start_ts, end_ts):
    """从 HFish API 拉取攻击日志"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    headers = {"Content-Type": "application/json"}
    params = {"api_key": API_KEY}
    payload = {
        "start_time": int(start_ts.timestamp()),
        "end_time": int(end_ts.timestamp()),
        "page": 1, "page_size": 5000
    }
    try:
        r = requests.post(url, headers=headers, params=params, json=payload, verify=False, timeout=30)
        data = r.json()
        if data.get("response_code") == 0:
            return data.get("data", [])
    except Exception as e:
        print(f"攻击API请求失败: {e}")
    return []

# ==================== 2. 账号资产数据采集 ====================
def fetch_accounts():
    """从 HFish API 拉取账号资产数据"""
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
        print(f"账号API请求失败: {e}")
    return []

# ==================== 3. 弱口令统计 ====================
def get_top_passwords(accounts):
    """统计攻击者最常用的10个密码"""
    pws = [a.get("password", "") for a in accounts if a.get("password")]
    return Counter(pws).most_common(10)

def get_top_usernames(accounts):
    """统计攻击者最常用的5个用户名"""
    uns = [a.get("username", "") for a in accounts if a.get("username")]
    return Counter(uns).most_common(5)

# ==================== 4. 数据清洗与聚合 ====================
def process_data(raw_logs):
    """清洗原始攻击日志，提取关键字段并统计"""
    if not raw_logs:
        return pd.DataFrame(), {}

    df = pd.DataFrame(raw_logs)

    # 保留需要的字段
    keep_cols = ["attack_ip", "ip_location", "client_name", "service_name", "service_port", "create_time"]
    cols = [c for c in keep_cols if c in df.columns]
    df = df[cols].copy()

    # 时间戳转换为可读格式
    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
        # 提取小时用于热力图
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour

    # 从地理位置提取国家
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(
            lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x
        )

    # 所有蜜罐类型列表
    all_hp = [
        "SSH蜜罐", "TCP端口监听", "Elasticsearch蜜罐", "Telnet蜜罐",
        "FTP蜜罐", "HTTP代理蜜罐", "MYSQL蜜罐", "REDIS蜜罐",
        "Tomcat蜜罐", "Weblogic蜜罐"
    ]
    hp_counts = df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}
    hp_data = {hp: hp_counts.get(hp, 0) for hp in all_hp}

    # 攻击时段热力图数据（24小时分布）
    heatmap_data = [0] * 24
    if "hour" in df.columns:
        hour_counts = df["hour"].value_counts().to_dict()
        for h, c in hour_counts.items():
            heatmap_data[int(h)] = c

    stats = {
        "total_attacks": len(df),
        "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
        "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
        "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
        "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
        "honeypot_data": hp_data,
        "active_honeypots": sum(1 for v in hp_data.values() if v > 0),
        "heatmap_data": heatmap_data,
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }
    return df, stats

# ==================== 5. 世界地图数据生成 ====================
def generate_map_data(df):
    """将国家统计数据转换为世界地图所需格式"""
    name_map = {
        "中国": "China", "美国": "United States", "俄罗斯": "Russia",
        "加拿大": "Canada", "新加坡": "Singapore", "日本": "Japan",
        "韩国": "South Korea", "德国": "Germany", "英国": "United Kingdom",
        "法国": "France", "印度": "India", "巴西": "Brazil",
        "澳大利亚": "Australia", "荷兰": "Netherlands", "越南": "Vietnam",
        "乌克兰": "Ukraine", "波兰": "Poland", "意大利": "Italy",
        "西班牙": "Spain", "瑞典": "Sweden", "瑞士": "Switzerland",
        "土耳其": "Turkey", "伊朗": "Iran", "泰国": "Thailand",
        "马来西亚": "Malaysia", "印度尼西亚": "Indonesia"
    }
    if "country" in df.columns and not df.empty:
        cc = df["country"].value_counts().to_dict()
        countries = [{"name": name_map.get(k, k), "value": v} for k, v in cc.items()]
        mx = max(cc.values()) if cc else 1
        with open(os.path.join(OUTPUT_DIR, "country_data.json"), "w", encoding="utf-8") as f:
            json.dump({"countries": countries, "maxCount": mx}, f, ensure_ascii=False)

# ==================== 6. CSV数据导出 ====================
def export_csv(df):
    """导出攻击数据为CSV文件"""
    if not df.empty:
        edf = df[["attack_ip", "ip_location", "service_name", "service_port", "create_time"]].head(500).copy()
        edf.columns = ["攻击源IP", "地理位置", "服务类型", "端口", "攻击时间"]
        edf.to_csv(os.path.join(OUTPUT_DIR, CSV_FILE), index=False, encoding="utf-8-sig")

# ==================== 7. 趋势图数据生成 ====================
def generate_chart_data(df):
    """生成近7天攻击趋势图数据"""
    if "create_time" in df.columns and not df.empty:
        df["date"] = pd.to_datetime(df["create_time"]).dt.strftime("%m-%d")
        daily = df["date"].value_counts().sort_index()
        return json.dumps({"dates": daily.index.tolist()[-7:], "counts": daily.values.tolist()[-7:]})
    return json.dumps({"dates": [], "counts": []})

# ==================== 8. 数据对比 ====================
def compare_weeks(current_df, last_week_logs):
    """本周与上周攻击数据对比"""
    if last_week_logs:
        last_df = pd.DataFrame(last_week_logs)
        return {
            "current": len(current_df),
            "last": len(last_df),
            "change": len(current_df) - len(last_df),
            "trend": "上升" if len(current_df) > len(last_df) else "下降"
        }
    return {"current": len(current_df), "last": 0, "change": 0, "trend": "无数据"}

# ==================== 9. HTML页面生成 ====================
def generate_html(df, stats, accounts, week_compare):
    """使用Jinja2模板生成完整的威胁情报HTML页面"""
    template = Template("""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HFish 威胁情报监控中心</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/echarts/5.4.3/echarts.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #0a0a14 0%, #0f172a 40%, #1e1b4b 70%, #0a0a14 100%);
            min-height: 100vh; padding: 20px; color: #e2e8f0;
        }
        .container { max-width: 1440px; margin: 0 auto; }
        .header {
            text-align: center; padding: 30px; margin-bottom: 30px;
            background: linear-gradient(135deg, rgba(0,212,255,0.08) 0%, rgba(124,58,237,0.06) 100%);
            border-radius: 20px; border: 1px solid rgba(0,212,255,0.12);
            box-shadow: 0 8px 32px rgba(0,212,255,0.08);
        }
        .header h1 {
            font-size: 2.6em;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            letter-spacing: 2px;
        }
        .header .subtitle { color: #94a3b8; font-size: 0.9em; letter-spacing: 1px; }
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 15px; margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid rgba(0,212,255,0.15); border-radius: 16px;
            padding: 22px; text-align: center; transition: all 0.3s ease;
            position: relative; overflow: hidden;
        }
        .stat-card:hover { transform: translateY(-5px); border-color: #00d4ff; box-shadow: 0 10px 30px rgba(0,212,255,0.15); }
        .stat-number { font-size: 2.4em; font-weight: 700; color: #00d4ff; text-shadow: 0 0 20px rgba(0,212,255,0.3); }
        .stat-number.up { color: #4ade80; text-shadow: 0 0 20px rgba(74,222,128,0.3); }
        .stat-number.down { color: #f87171; text-shadow: 0 0 20px rgba(248,113,113,0.3); }
        .stat-label { color: #94a3b8; font-size: 0.85em; margin-top: 6px; letter-spacing: 1px; }
        .section {
            background: rgba(255,255,255,0.03); border: 1px solid rgba(0,212,255,0.1);
            border-radius: 20px; padding: 30px; margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            transition: all 0.3s ease;
        }
        .section:hover {
            border-color: rgba(0,212,255,0.25);
            box-shadow: 0 8px 30px rgba(0,212,255,0.1);
        }
        .section-title {
            font-size: 1.3em; color: #00d4ff; margin-bottom: 20px;
            border-bottom: 1px solid rgba(0,212,255,0.1); padding-bottom: 12px;
            display: flex; align-items: center; gap: 10px;
            text-shadow: 0 0 15px rgba(0,212,255,0.3);
        }
        .chart-container { width: 100%; height: 380px; }
        .map-container { width: 100%; height: 500px; border-radius: 12px; position: relative; overflow: hidden; background: #0f172a; }
        .heatmap-container { width: 100%; height: 300px; }
        .honeypot-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px;
        }
        .hp-item {
            background: linear-gradient(135deg, rgba(0,212,255,0.06), rgba(124,58,237,0.04));
            border: 1px solid rgba(0,212,255,0.12); border-radius: 14px;
            padding: 20px; text-align: center; transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .hp-item:hover { transform: translateY(-3px); border-color: #00d4ff; box-shadow: 0 8px 25px rgba(0,212,255,0.15); }
        .hp-name { color: #94a3b8; font-size: 0.8em; margin-bottom: 8px; }
        .hp-count { font-size: 1.8em; font-weight: 700; color: #00d4ff; text-shadow: 0 0 10px rgba(0,212,255,0.3); }
        .hp-zero { color: #475569; }
        .top-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
        .list-item {
            background: rgba(0,0,0,0.35); border: 1px solid rgba(0,212,255,0.08);
            border-radius: 14px; padding: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: all 0.3s ease;
        }
        .list-item:hover {
            border-color: rgba(0,212,255,0.2);
            box-shadow: 0 6px 20px rgba(0,212,255,0.1);
        }
        .list-item h3 { color: #00d4ff; margin-bottom: 12px; font-size: 1em; text-shadow: 0 0 10px rgba(0,212,255,0.2); }
        .rank-item {
            display: flex; justify-content: space-between; padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06); color: #cbd5e1; font-size: 0.88em;
            transition: all 0.2s ease;
        }
        .rank-item:hover { background: rgba(0,212,255,0.05); padding-left: 8px; }
        .rank-value { font-weight: 700; color: #00d4ff; }
        .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.88em; color: #cbd5e1; }
        .data-table th { background: rgba(0,212,255,0.12); color: #00d4ff; padding: 12px; text-align: left; }
        .data-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .data-table tr:hover { background: rgba(0,212,255,0.04); }
        .badge {
            background: rgba(0,212,255,0.15); color: #00d4ff;
            padding: 4px 10px; border-radius: 16px; font-size: 0.82em;
            border: 1px solid rgba(0,212,255,0.2);
            transition: all 0.2s ease;
        }
        .badge:hover {
            background: rgba(0,212,255,0.25);
            box-shadow: 0 0 10px rgba(0,212,255,0.3);
        }
        .footer { text-align: center; color: #64748b; margin-top: 40px; font-size: 0.85em; }
        .warning { color: #f87171; font-weight: 500; }
        .compare-box {
            display: flex; gap: 15px; align-items: center; justify-content: center;
            flex-wrap: wrap;
        }
        .compare-item {
            background: rgba(0,0,0,0.3); border-radius: 12px; padding: 15px 25px;
            text-align: center;
        }
        .compare-num { font-size: 2em; font-weight: 700; }
        .compare-label { color: #94a3b8; font-size: 0.8em; }
        .trend-up { color: #f87171; }
        .trend-down { color: #4ade80; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ HFish 威胁情报监控中心</h1>
            <p class="subtitle">📊 监控周期: {{ stats.time_range }} | 最后更新: {{ last_update }}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ stats.total_attacks }}</div>
                <div class="stat-label">总攻击次数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.unique_ips }}</div>
                <div class="stat-label">独立攻击IP</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ account_count }}</div>
                <div class="stat-label">账号资产数据</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.active_honeypots }}</div>
                <div class="stat-label">活跃蜜罐数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number {{ 'up' if week_compare.trend == '上升' else 'down' }}">
                    {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
                </div>
                <div class="stat-label">较上周{{ week_compare.trend }}</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📈 攻击趋势（近7天）</h2>
            <div class="chart-container"><canvas id="attackChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">🔥 攻击时段分布（24小时）</h2>
            <div class="heatmap-container"><canvas id="heatmapChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">📊 本周 vs 上周攻击对比</h2>
            <div class="compare-box">
                <div class="compare-item">
                    <div class="compare-num" style="color:#00d4ff;">{{ week_compare.current }}</div>
                    <div class="compare-label">本周攻击</div>
                </div>
                <div style="font-size:2em;color:#94a3b8;">VS</div>
                <div class="compare-item">
                    <div class="compare-num" style="color:#94a3b8;">{{ week_compare.last }}</div>
                    <div class="compare-label">上周攻击</div>
                </div>
                <div class="compare-item">
                    <div class="compare-num {{ 'trend-up' if week_compare.trend == '上升' else 'trend-down' }}">
                        {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
                    </div>
                    <div class="compare-label">变化趋势: {{ week_compare.trend }}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">🗺️ 攻击来源全球分布</h2>
            <div class="map-container" id="worldMap"></div>
        </div>

        <div class="section">
            <h2 class="section-title">🎯 各蜜罐受攻击次数</h2>
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
            <h2 class="section-title">📊 攻击统计分析</h2>
            <div class="top-list">
                <div class="list-item">
                    <h3>🔝 Top 10 攻击源IP</h3>
                    {% for ip, count in stats.top_ips.items() %}
                    <div class="rank-item"><span>{{ ip }}</span><span class="rank-value">{{ count }}次</span></div>{% endfor %}
                </div>
                <div class="list-item">
                    <h3>🌍 攻击来源国家</h3>
                    {% for country, count in stats.top_countries.items() %}
                    <div class="rank-item"><span>{{ country }}</span><span class="rank-value">{{ count }}次</span></div>{% endfor %}
                </div>
                <div class="list-item">
                    <h3>🔑 弱口令字典 TOP 10</h3>
                    {% for pwd, count in top_passwords %}
                    <div class="rank-item"><span class="warning">{{ pwd }}</span><span class="rank-value">{{ count }}次</span></div>{% endfor %}
                    {% if not top_passwords %}<div class="rank-item"><span>暂无弱口令数据</span></div>{% endif %}
                </div>
                <div class="list-item">
                    <h3>👤 高频用户名 TOP 5</h3>
                    {% for user, count in top_usernames %}
                    <div class="rank-item"><span>{{ user }}</span><span class="rank-value">{{ count }}次</span></div>{% endfor %}
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📋 最新攻击详情记录（前100条）</h2>
            <div style="overflow-x:auto; max-height:400px; overflow-y:auto;">
                <table class="data-table">
                    <thead><tr><th>攻击源IP</th><th>地理位置</th><th>服务类型</th><th>端口</th><th>攻击时间</th></tr></thead>
                    <tbody>
                    {% for _, row in df.head(100).iterrows() %}
                    <tr>
                        <td><span class="badge">{{ row.get('attack_ip', '-') }}</span></td>
                        <td>{{ row.get('ip_location', '-') }}</td>
                        <td>{{ row.get('service_name', '-') }}</td>
                        <td>{{ row.get('service_port', '-') }}</td>
                        <td>{{ row.get('create_time', '-') }}</td>
                    </tr>{% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>🤖 HFish 蜜罐系统自动采集 | 每6小时更新 | 毕业设计作品 | {{ last_update }}</p>
        </div>
    </div>

    <script>
        // --- 1. 攻击趋势折线图 ---
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        // 直接在 JS 中接收 JSON 对象
        const trendData = {{ chart_data | safe }};
        
        new Chart(attackCtx, {
            type: 'line',
            data: {
                labels: trendData.dates || [],
                datasets: [{
                    label: '攻击次数',
                    data: trendData.counts || [],
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0,212,255,0.1)',
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#00d4ff',
                    pointRadius: 5
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#94a3b8' } } },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
                }
            }
        });

        // --- 2. 攻击时段热力图 ---
        const heatCtx = document.getElementById('heatmapChart').getContext('2d');
        const heatData = {{ heatmap_data | safe }};
        
        new Chart(heatCtx, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => i + '时'),
                datasets: [{
                    label: '攻击次数',
                    data: heatData,
                    backgroundColor: function(context) {
                        const val = context.raw;
                        if(val > 200) return '#7c3aed';
                        if(val > 100) return '#00d4ff';
                        if(val > 50) return '#0284c7';
                        return '#0d47a1';
                    },
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#94a3b8' } } },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
                }
            }
        });

        // --- 3. 世界地图 (ECharts) ---
        const mapDom = document.getElementById('worldMap');
        const mapChart = echarts.init(mapDom);

        const countryNameMap = {
            "China": "中国", "United States": "美国", "Russia": "俄罗斯", "Canada": "加拿大",
            "Brazil": "巴西", "Australia": "澳大利亚", "India": "印度", "Japan": "日本",
            "Germany": "德国", "United Kingdom": "英国", "France": "法国", "Italy": "意大利",
            "South Korea": "韩国", "Singapore": "新加坡", "Malaysia": "马来西亚", "Indonesia": "印度尼西亚",
            "Thailand": "泰国", "Vietnam": "越南", "Turkey": "土耳其", "Iran": "伊朗",
            "Netherlands": "荷兰", "Sweden": "瑞典", "Switzerland": "瑞士", "Spain": "西班牙",
            "Ukraine": "乌克兰", "Poland": "波兰", "Mexico": "墨西哥", "Nigeria": "尼日利亚",
            "Egypt": "埃及", "South Africa": "南非", "Argentina": "阿根廷", "Chile": "智利",
            "Saudi Arabia": "沙特阿拉伯", "United Arab Emirates": "阿联酋", "Israel": "以色列",
            "Pakistan": "巴基斯坦", "Bangladesh": "孟加拉", "Philippines": "菲律宾", "New Zealand": "新西兰",
            "Norway": "挪威", "Denmark": "丹麦", "Finland": "芬兰", "Ireland": "爱尔兰",
            "Portugal": "葡萄牙", "Greece": "希腊", "Austria": "奥地利", "Hungary": "匈牙利"
        };

        fetch('country_data.json').then(res => res.json()).then(data => {
            const mapOptions = {
                backgroundColor: 'transparent',
                tooltip: {
                    trigger: 'item',
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    textStyle: { color: '#e2e8f0' },
                    formatter: p => `${countryNameMap[p.name] || p.name}<br/>攻击次数: ${p.value || 0}`
                },
                visualMap: {
                    show: true, left: 'left', bottom: '5%',
                    min: 0, max: data.maxCount || 100,
                    text: ['高', '低'],
                    textStyle: { color: '#94a3b8' },
                    inRange: { color: ['#1e293b', '#0d47a1', '#1565c0', '#00d4ff'] }
                },
                series: [{
                    type: 'map',
                    map: 'world',
                    roam: true,
                    zoom: 1.2,
                    center: [10, 10],
                    itemStyle: {
                        borderColor: '#334155', borderWidth: 1,
                        areaColor: '#1e293b'
                    },
                    emphasis: {
                        itemStyle: {
                            areaColor: '#00d4ff',
                            borderColor: '#00d4ff',
                            borderWidth: 2
                        },
                        label: { show: true, color: '#fff' }
                    },
                    data: data.countries
                }]
            };

            // 使用内置世界地图
            mapChart.setOption(mapOptions);
        }).catch(() => {
            mapDom.innerHTML = '<div style="color:#94a3b8;text-align:center;padding-top:150px;font-size:14px;">暂无攻击源地理数据</div>';
        });

        // 使用 ECharts 内置世界地图
        (function() {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/echarts@5.4.3/map/js/world.js';
            script.onload = function() {
                if (mapChart.getOption() && mapChart.getOption().series) {
                    mapChart.setOption({
                        series: [{
                            type: 'map',
                            map: 'world'
                        }]
                    });
                }
            };
            document.head.appendChild(script);
        })();

        window.addEventListener('resize', () => mapChart.resize());
    </script>
</body>
</html>
""")

    # --- 变量准备 ---
    chart_data = generate_chart_data(df)
    heatmap_data = json.dumps(stats.get("heatmap_data", [0]*24))
    top_passwords = get_top_passwords(accounts)
    top_usernames = get_top_usernames(accounts)

    # --- 渲染 ---
    html_content = template.render(
        df=df, 
        stats=stats, 
        chart_data=chart_data,
        heatmap_data=heatmap_data,
        top_passwords=top_passwords, 
        top_usernames=top_usernames,
        week_compare=week_compare,
        account_count=len(accounts),
        last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, OUTPUT_FILE), "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ HTML 已生成: {OUTPUT_DIR}/{OUTPUT_FILE}")

# ==================== 主函数 ====================
def main():
    print("🔄 正在拉取攻击日志（近90天）...")
    logs = fetch_attack_logs(START_TIME, END_TIME)

    print("🔄 正在拉取上周攻击日志...")
    last_week_logs = fetch_attack_logs(LAST_WEEK_START, LAST_WEEK_END)

    print("🔄 正在拉取账号资产数据...")
    accounts = fetch_accounts()

    if logs:
        print(f"📥 攻击数据: {len(logs)} 条 | 账号数据: {len(accounts)} 条 | 上周: {len(last_week_logs)} 条")
        df, stats = process_data(logs)
        week_compare = compare_weeks(df, last_week_logs)
        
        # 执行导出与生成
        generate_map_data(df)
        export_csv(df)
        generate_html(df, stats, accounts, week_compare)
        print("✨ v6.1 (优化版) 所有任务完成！")
    else:
        print("⚠️ 未拉取到攻击数据")

if __name__ == "__main__":
    main()