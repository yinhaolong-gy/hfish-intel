#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v6.0
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
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
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
        }
        .header h1 {
            font-size: 2.6em;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }
        .header .subtitle { color: #94a3b8; font-size: 0.9em; }
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
        .stat-number { font-size: 2.4em; font-weight: 700; color: #00d4ff; }
        .stat-number.up { color: #4ade80; }
        .stat-number.down { color: #f87171; }
        .stat-label { color: #94a3b8; font-size: 0.85em; margin-top: 6px; }
        .section {
            background: rgba(255,255,255,0.03); border: 1px solid rgba(0,212,255,0.1);
            border-radius: 20px; padding: 30px; margin-bottom: 25px;
        }
        .section-title {
            font-size: 1.3em; color: #00d4ff; margin-bottom: 20px;
            border-bottom: 1px solid rgba(0,212,255,0.1); padding-bottom: 12px;
            display: flex; align-items: center; gap: 10px;
        }
        .chart-container { width: 100%; height: 380px; }
        .map-container { width: 100%; height: 500px; border-radius: 12px; }
        .heatmap-container { width: 100%; height: 300px; }
        .honeypot-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px;
        }
        .hp-item {
            background: linear-gradient(135deg, rgba(0,212,255,0.06), rgba(124,58,237,0.04));
            border: 1px solid rgba(0,212,255,0.12); border-radius: 14px;
            padding: 20px; text-align: center; transition: all 0.3s ease;
        }
        .hp-item:hover { transform: translateY(-3px); border-color: #00d4ff; }
        .hp-name { color: #94a3b8; font-size: 0.8em; margin-bottom: 8px; }
        .hp-count { font-size: 1.8em; font-weight: 700; color: #00d4ff; }
        .hp-zero { color: #475569; }
        .top-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
        .list-item {
            background: rgba(0,0,0,0.35); border: 1px solid rgba(0,212,255,0.08);
            border-radius: 14px; padding: 20px;
        }
        .list-item h3 { color: #00d4ff; margin-bottom: 12px; font-size: 1em; }
        .rank-item {
            display: flex; justify-content: space-between; padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06); color: #cbd5e1; font-size: 0.88em;
        }
        .rank-value { font-weight: 700; color: #00d4ff; }
        .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.88em; color: #cbd5e1; }
        .data-table th { background: rgba(0,212,255,0.12); color: #00d4ff; padding: 12px; text-align: left; }
        .data-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .data-table tr:hover { background: rgba(0,212,255,0.04); }
        .badge {
            background: rgba(0,212,255,0.15); color: #00d4ff;
            padding: 4px 10px; border-radius: 16px; font-size: 0.82em;
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
        <!-- 头部 -->
        <div class="header">
            <h1>🛡️ HFish 威胁情报监控中心</h1>
            <p class="subtitle">📊 监控周期: {{ stats.time_range }} | 最后更新: {{ last_update }}</p>
        </div>

        <!-- 统计卡片 -->
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

        <!-- 攻击趋势图 -->
        <div class="section">
            <h2 class="section-title">📈 攻击趋势（近7天）</h2>
            <div class="chart-container"><canvas id="attackChart"></canvas></div>
        </div>

        <!-- 攻击时段热力图 -->
        <div class="section">
            <h2 class="section-title">🔥 攻击时段分布（24小时）</h2>
            <div class="heatmap-container"><canvas id="heatmapChart"></canvas></div>
        </div>

        <!-- 周对比 -->
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

        <!-- 世界地图 -->
        <div class="section">
            <h2 class="section-title">🗺️ 攻击来源全球分布</h2>
            <div class="map-container" id="worldMap"></div>
        </div>

        <!-- 分蜜罐统计 -->
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

        <!-- 攻击统计分析 -->
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

        <!-- 最新攻击详情 -->
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

    <!-- 图表脚本 -->
    <script>
        // 攻击趋势折线图
        const ctx = document.getElementById('attackChart').getContext('2d');
        const trendData = {{ chart_data | safe }};
        new Chart(ctx, {
            type:'line',
            data:{
                labels:trendData.dates,
                datasets:[{
                    label:'攻击次数',data:trendData.counts,
                    borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.1)',
                    fill:true,tension:0.4,
                    pointBackgroundColor:'#00d4ff',pointRadius:5
                }]
            },
            options:{
                responsive:true,maintainAspectRatio:false,
                plugins:{legend:{labels:{color:'#94a3b8'}}},
                scales:{
                    x:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)'}},
                    y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)'},beginAtZero:true}
                }
            }
        });

        // 攻击时段热力图
        const heatCtx = document.getElementById('heatmapChart').getContext('2d');
        const heatData = {{ heatmap_data | safe }};
        new Chart(heatCtx, {
            type:'bar',
            data:{
                labels:['0时','1时','2时','3时','4时','5时','6时','7时','8时','9时','10时','11时',
                        '12时','13时','14时','15时','16时','17时','18时','19时','20时','21时','22时','23时'],
                datasets:[{
                    label:'攻击次数',
                    data:heatData,
                    backgroundColor:function(context){
                        var value = context.raw;
                        if(value > 200) return '#7c3aed';
                        if(value > 100) return '#00d4ff';
                        if(value > 50) return '#0284c7';
                        return '#0d47a1';
                    },
                    borderRadius:6
                }]
            },
            options:{
                responsive:true,maintainAspectRatio:false,
                plugins:{legend:{labels:{color:'#94a3b8'}}},
                scales:{
                    x:{ticks:{color:'#94a3b8'},grid:{display:false}},
                    y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)'},beginAtZero:true}
                }
            }
        });
    </script>

    <!-- 世界地图 -->
    <script>
        fetch('country_data.json').then(res => res.json()).then(data => {
            var map = L.map('worldMap', {
                center: [30, 0],
                zoom: 2,
                zoomControl: true
            });
            
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(map);
            
            var countryCoords = {
                "China": [35.8617, 104.1954],
                "United States": [37.0902, -95.7129],
                "Russia": [61.5240, 105.3188],
                "Canada": [56.1304, -106.3468],
                "Brazil": [-14.2350, -51.9253],
                "Australia": [-25.2744, 133.7751],
                "India": [20.5937, 78.9629],
                "Japan": [36.2048, 138.2529],
                "Germany": [51.1657, 10.4515],
                "United Kingdom": [55.3781, -3.4360],
                "France": [46.2276, 2.2137],
                "Italy": [41.8719, 12.5674],
                "South Korea": [35.9078, 127.7669],
                "Singapore": [1.3521, 103.8198],
                "Malaysia": [2.5276, 112.9388],
                "Indonesia": [-0.7893, 113.9213],
                "Thailand": [15.8700, 100.9925],
                "Vietnam": [14.0583, 108.2772],
                "Turkey": [38.9637, 35.2433],
                "Iran": [32.4279, 53.6880],
                "Netherlands": [52.1326, 5.2913],
                "Sweden": [60.1282, 18.6435],
                "Switzerland": [46.8182, 8.2275],
                "Spain": [40.4637, -3.7492],
                "Ukraine": [48.3794, 31.1656],
                "Poland": [51.9194, 19.1451],
                "France": [46.2276, 2.2137],
                "Mexico": [23.6345, -102.5528],
                "Nigeria": [9.0820, 8.6753],
                "Egypt": [26.8206, 30.8025],
                "South Africa": [-30.5595, 22.9375],
                "Argentina": [-38.4161, -63.6167],
                "Chile": [-35.6751, -71.5430],
                "Saudi Arabia": [23.8859, 45.0792],
                "United Arab Emirates": [23.4241, 53.8478],
                "Israel": [31.0461, 34.8516],
                "Pakistan": [30.3753, 69.3451],
                "Bangladesh": [23.6850, 90.3563],
                "Philippines": [12.8797, 121.7740],
                "New Zealand": [-40.9006, 174.8860],
                "Norway": [60.4720, 8.4689],
                "Denmark": [56.2639, 9.5018],
                "Finland": [61.9241, 25.7482],
                "Ireland": [53.4129, -8.2439],
                "Portugal": [39.3999, -8.2245],
                "Greece": [39.0742, 21.8243],
                "Austria": [47.5162, 14.5501],
                "Hungary": [47.1625, 19.5033],
                "Czech Republic": [49.8175, 15.4729],
                "Belgium": [50.5039, 4.4699],
                "Luxembourg": [49.8153, 6.1296],
                "Croatia": [45.1, 15.2],
                "Serbia": [44.0165, 21.0059],
                "Romania": [45.9432, 24.9668],
                "Bulgaria": [42.7339, 25.4858],
                "Hungary": [47.1625, 19.5033],
                "Slovakia": [48.6690, 19.6990],
                "Slovenia": [46.1512, 14.9955],
                "Bosnia and Herzegovina": [43.8666, 18.4131],
                "Montenegro": [42.7087, 19.3744],
                "Albania": [41.1533, 20.1683],
                "Macedonia": [41.6086, 21.7453],
                "Kosovo": [42.6026, 20.9029],
                "Cyprus": [35.1264, 33.4299],
                "Malta": [35.9375, 14.3754],
                "Iceland": [64.9631, -19.0208],
                "Greenland": [71.7069, -42.6043],
                "Fiji": [-16.5781, 179.4144],
                "Papua New Guinea": [-6.3149, 143.9555],
                "Solomon Islands": [-9.6457, 160.1562],
                "Vanuatu": [-15.3767, 166.9592],
                "New Caledonia": [-21.5218, 165.6786],
                "French Polynesia": [-17.6797, -149.4068],
                "Samoa": [-13.7590, -172.1046],
                "Tonga": [-21.1789, -175.1982],
                "Cook Islands": [-21.2367, -159.7777],
                "Niue": [-19.0333, -169.8667],
                "Norfolk Island": [-29.0408, 167.9547],
                "Christmas Island": [-10.4475, 105.6904],
                "Cocos Islands": [-12.1641, 96.8652],
                "American Samoa": [-14.2710, -170.1322],
                "Guam": [13.4443, 144.7937],
                "Northern Mariana Islands": [15.2000, 145.7500],
                "Palau": [7.5149, 134.5825],
                "Micronesia": [7.4256, 150.5508],
                "Marshall Islands": [7.1317, 167.4846],
                "Nauru": [-0.5228, 166.9315],
                "Kiribati": [1.8741, -157.4120],
                "Tuvalu": [-7.1095, 178.6445],
                "Wallis and Futuna": [-13.7687, -177.1561],
                "Western Sahara": [24.2155, -12.8858],
                "Morocco": [31.7917, -7.0926],
                "Algeria": [28.0339, 1.6596],
                "Tunisia": [33.8869, 9.5375],
                "Libya": [26.3351, 17.2283],
                "Sudan": [12.8628, 30.2176],
                "Chad": [15.4542, 18.7322],
                "Niger": [17.6078, 8.0817],
                "Mali": [17.5707, -3.9962],
                "Mauritania": [20.9373, -10.9408],
                "Senegal": [14.4974, -14.4524],
                "Gambia": [13.4432, -15.3101],
                "Guinea-Bissau": [11.8037, -15.1804],
                "Guinea": [10.9409, -9.6966],
                "Sierra Leone": [8.4606, -11.7799],
                "Liberia": [6.4281, -9.4295],
                "Cote d'Ivoire": [7.5399, -5.5471],
                "Ghana": [7.9465, -1.0232],
                "Togo": [8.6195, 0.8248],
                "Benin": [9.3077, 2.3158],
                "Burkina Faso": [12.2383, -1.5616],
                "Nigeria": [9.0820, 8.6753],
                "Cameroon": [3.8480, 11.5021],
                "Equatorial Guinea": [1.6508, 10.2679],
                "Sao Tome and Principe": [0.1864, 6.6131],
                "Gabon": [-0.8037, 11.6094],
                "Republic of the Congo": [-1.4492, 15.8271],
                "Democratic Republic of the Congo": [-4.0383, 21.7587],
                "Central African Republic": [6.6111, 20.9394],
                "Chad": [15.4542, 18.7322],
                "Sudan": [12.8628, 30.2176],
                "South Sudan": [6.8770, 31.3070],
                "Ethiopia": [9.1450, 40.4897],
                "Eritrea": [15.1794, 39.7823],
                "Djibouti": [11.8251, 42.5903],
                "Somalia": [5.1521, 46.1996],
                "Kenya": [-0.0236, 37.9062],
                "Uganda": [1.3733, 32.2903],
                "Tanzania": [-6.3690, 34.8888],
                "Rwanda": [-1.9403, 29.8739],
                "Burundi": [-3.3731, 29.9189],
                "Malawi": [-13.2543, 34.3015],
                "Zambia": [-13.1339, 27.8493],
                "Mozambique": [-18.6657, 35.5296],
                "Zimbabwe": [-19.0154, 29.1549],
                "Botswana": [-22.3285, 24.6849],
                "Namibia": [-22.9576, 18.4904],
                "South Africa": [-30.5595, 22.9375],
                "Lesotho": [-29.6099, 28.2336],
                "Swaziland": [-26.5225, 31.4659],
                "Angola": [-11.2027, 17.8739],
                "Madagascar": [-18.7669, 46.8691],
                "Comoros": [-11.6455, 43.3333],
                "Seychelles": [-4.6796, 55.4794],
                "Mauritius": [-20.3484, 57.5522],
                "Maldives": [3.2028, 73.2207],
                "Sri Lanka": [7.8731, 80.7718],
                "Bhutan": [27.5142, 90.4336],
                "Nepal": [28.3949, 84.1240],
                "Afghanistan": [33.9399, 67.7099],
                "Kazakhstan": [48.0196, 66.9237],
                "Uzbekistan": [41.3775, 64.5853],
                "Turkmenistan": [38.9697, 59.5563],
                "Kyrgyzstan": [41.2044, 74.7661],
                "Tajikistan": [38.8610, 71.2761],
                "Armenia": [40.0691, 45.0360],
                "Azerbaijan": [40.1431, 47.5769],
                "Georgia": [42.3154, 43.3569],
                "Mongolia": [46.8625, 103.8467],
                "North Korea": [40.3399, 127.5101],
                "South Korea": [35.9078, 127.7669],
                "Taiwan": [23.6978, 120.9605],
                "Hong Kong": [22.3193, 114.1694],
                "Macau": [22.1987, 113.5439],
                "Philippines": [12.8797, 121.7740],
                "Malaysia": [2.5276, 112.9388],
                "Brunei": [4.5353, 114.7277],
                "Cambodia": [12.5657, 104.9915],
                "Laos": [19.8563, 102.4955],
                "Myanmar": [21.9139, 95.9560],
                "Bangladesh": [23.6850, 90.3563],
                "Nepal": [28.3949, 84.1240],
                "Bhutan": [27.5142, 90.4336],
                "Sri Lanka": [7.8731, 80.7718],
                "Maldives": [3.2028, 73.2207],
                "Pakistan": [30.3753, 69.3451],
                "India": [20.5937, 78.9629],
                "Sri Lanka": [7.8731, 80.7718],
                "Bangladesh": [23.6850, 90.3563],
                "Nepal": [28.3949, 84.1240],
                "Bhutan": [27.5142, 90.4336],
                "Afghanistan": [33.9399, 67.7099],
                "Iran": [32.4279, 53.6880],
                "Iraq": [33.2232, 43.6793],
                "Syria": [34.8021, 38.9968],
                "Lebanon": [33.8547, 35.8623],
                "Israel": [31.0461, 34.8516],
                "Palestine": [31.9522, 35.2332],
                "Jordan": [30.5852, 36.2384],
                "Saudi Arabia": [23.8859, 45.0792],
                "Yemen": [15.5527, 48.5164],
                "Oman": [21.5126, 55.9233],
                "United Arab Emirates": [23.4241, 53.8478],
                "Qatar": [25.3548, 51.1839],
                "Bahrain": [26.0275, 50.5518],
                "Kuwait": [29.3117, 47.4818],
                "Turkey": [38.9637, 35.2433],
                "Cyprus": [35.1264, 33.4299],
                "Armenia": [40.0691, 45.0360],
                "Azerbaijan": [40.1431, 47.5769],
                "Georgia": [42.3154, 43.3569],
                "Russia": [61.5240, 105.3188],
                "Ukraine": [48.3794, 31.1656],
                "Belarus": [53.7098, 27.9534],
                "Moldova": [47.4116, 28.3699],
                "Estonia": [58.5953, 25.0136],
                "Latvia": [56.8796, 24.6032],
                "Lithuania": [55.1694, 23.8813],
                "Poland": [51.9194, 19.1451],
                "Czech Republic": [49.8175, 15.4729],
                "Slovakia": [48.6690, 19.6990],
                "Hungary": [47.1625, 19.5033],
                "Austria": [47.5162, 14.5501],
                "Germany": [51.1657, 10.4515],
                "Switzerland": [46.8182, 8.2275],
                "Liechtenstein": [47.1410, 9.5215],
                "France": [46.2276, 2.2137],
                "Monaco": [43.7384, 7.4246],
                "Italy": [41.8719, 12.5674],
                "San Marino": [43.9424, 12.4578],
                "Vatican City": [41.9029, 12.4534],
                "Malta": [35.9375, 14.3754],
                "Greece": [39.0742, 21.8243],
                "Bulgaria": [42.7339, 25.4858],
                "Romania": [45.9432, 24.9668],
                "Serbia": [44.0165, 21.0059],
                "Kosovo": [42.6026, 20.9029],
                "Montenegro": [42.7087, 19.3744],
                "Bosnia and Herzegovina": [43.8666, 18.4131],
                "Croatia": [45.1, 15.2],
                "Slovenia": [46.1512, 14.9955],
                "Albania": [41.1533, 20.1683],
                "Macedonia": [41.6086, 21.7453],
                "Ireland": [53.4129, -8.2439],
                "United Kingdom": [55.3781, -3.4360],
                "Isle of Man": [54.2361, -4.5481],
                "Guernsey": [49.4653, -2.5852],
                "Jersey": [49.2144, -2.1312],
                "Iceland": [64.9631, -19.0208],
                "Norway": [60.1282, 18.6435],
                "Sweden": [60.1282, 18.6435],
                "Denmark": [56.2639, 9.5018],
                "Finland": [61.9241, 25.7482],
                "Estonia": [58.5953, 25.0136],
                "Latvia": [56.8796, 24.6032],
                "Lithuania": [55.1694, 23.8813],
                "Belarus": [53.7098, 27.9534],
                "Ukraine": [48.3794, 31.1656],
                "Moldova": [47.4116, 28.3699],
                "Russia": [61.5240, 105.3188],
                "Kazakhstan": [48.0196, 66.9237],
                "China": [35.8617, 104.1954],
                "Mongolia": [46.8625, 103.8467],
                "Japan": [36.2048, 138.2529],
                "North Korea": [40.3399, 127.5101],
                "South Korea": [35.9078, 127.7669],
                "Taiwan": [23.6978, 120.9605],
                "Hong Kong": [22.3193, 114.1694],
                "Macau": [22.1987, 113.5439],
                "Philippines": [12.8797, 121.7740],
                "Malaysia": [2.5276, 112.9388],
                "Brunei": [4.5353, 114.7277],
                "Singapore": [1.3521, 103.8198],
                "Indonesia": [-0.7893, 113.9213],
                "Timor-Leste": [-8.8742, 125.7275],
                "Australia": [-25.2744, 133.7751],
                "New Zealand": [-40.9006, 174.8860],
                "Papua New Guinea": [-6.3149, 143.9555],
                "Solomon Islands": [-9.6457, 160.1562],
                "Vanuatu": [-15.3767, 166.9592],
                "New Caledonia": [-21.5218, 165.6786],
                "Fiji": [-16.5781, 179.4144],
                "Samoa": [-13.7590, -172.1046],
                "Tonga": [-21.1789, -175.1982],
                "Cook Islands": [-21.2367, -159.7777],
                "Niue": [-19.0333, -169.8667],
                "French Polynesia": [-17.6797, -149.4068],
                "Wallis and Futuna": [-13.7687, -177.1561],
                "American Samoa": [-14.2710, -170.1322],
                "Palau": [7.5149, 134.5825],
                "Micronesia": [7.4256, 150.5508],
                "Marshall Islands": [7.1317, 167.4846],
                "Nauru": [-0.5228, 166.9315],
                "Kiribati": [1.8741, -157.4120],
                "Tuvalu": [-7.1095, 178.6445],
                "Norfolk Island": [-29.0408, 167.9547],
                "Christmas Island": [-10.4475, 105.6904],
                "Cocos Islands": [-12.1641, 96.8652],
                "Guam": [13.4443, 144.7937],
                "Northern Mariana Islands": [15.2000, 145.7500],
                "United States": [37.0902, -95.7129],
                "Canada": [56.1304, -106.3468],
                "Greenland": [71.7069, -42.6043],
                "Mexico": [23.6345, -102.5528],
                "Guatemala": [15.7835, -90.2308],
                "Belize": [17.1899, -88.4976],
                "Honduras": [15.1999, -86.2419],
                "El Salvador": [13.8333, -88.9167],
                "Nicaragua": [12.8654, -85.2072],
                "Costa Rica": [9.7489, -83.7534],
                "Panama": [8.5380, -80.2217],
                "Caribbean Sea": [15.0, -75.0],
                "Bahamas": [25.0343, -77.3963],
                "Cuba": [21.5218, -77.7812],
                "Jamaica": [18.1096, -77.2975],
                "Haiti": [18.9712, -72.2852],
                "Dominican Republic": [18.7357, -70.1627],
                "Puerto Rico": [18.2208, -66.5901],
                "Virgin Islands": [18.3358, -64.8963],
                "Guadeloupe": [16.2650, -61.5510],
                "Martinique": [14.6415, -61.0242],
                "Trinidad and Tobago": [10.6918, -61.2225],
                "Barbados": [13.1939, -59.5432],
                "Grenada": [12.1165, -61.6790],
                "Saint Lucia": [13.9094, -60.9789],
                "Saint Vincent and the Grenadines": [13.2500, -61.2500],
                "Antigua and Barbuda": [17.0608, -61.7964],
                "Dominica": [15.4140, -61.3710],
                "Saint Kitts and Nevis": [17.3578, -62.7829],
                "Anguilla": [18.2236, -63.0649],
                "Montserrat": [16.7425, -62.1873],
                "Turks and Caicos Islands": [21.7500, -71.5833],
                "Cayman Islands": [19.5135, -80.5669],
                "Aruba": [12.5211, -69.9683],
                "Bonaire": [12.1167, -68.2667],
                "Sint Eustatius": [17.4167, -62.9333],
                "Saba": [17.6333, -63.2167],
                "Curacao": [12.1696, -68.9093],
                "Colombia": [4.5709, -74.2973],
                "Venezuela": [6.4238, -66.5897],
                "Guyana": [4.8604, -58.9302],
                "Suriname": [3.9193, -56.0278],
                "French Guiana": [4.9333, -52.3333],
                "Brazil": [-14.2350, -51.9253],
                "Peru": [-9.1899, -75.0152],
                "Bolivia": [-16.2901, -63.5887],
                "Chile": [-35.6751, -71.5430],
                "Argentina": [-38.4161, -63.6167],
                "Paraguay": [-23.4425, -58.4438],
                "Uruguay": [-32.5228, -55.7658],
                "Ecuador": [-1.8312, -78.1834],
                "Galapagos": [-0.9492, -91.0993],
                "Falkland Islands": [-51.7963, -59.5236],
                "South Georgia and the South Sandwich Islands": [-54.5, -37.0],
                "Antarctica": [-90.0, 0.0]
            };
            
            var maxCount = data.maxCount || 100;
            
            data.countries.forEach(function(country) {
                var coords = countryCoords[country.name];
                if (coords) {
                    var intensity = Math.min(country.value / maxCount, 1);
                    var radius = 5 + (intensity * 15);
                    var opacity = 0.3 + (intensity * 0.7);
                    
                    L.circleMarker(coords, {
                        radius: radius,
                        fillColor: '#00d4ff',
                        color: '#00d4ff',
                        weight: 2,
                        opacity: opacity,
                        fillOpacity: opacity * 0.6
                    }).addTo(map).bindPopup('<b>' + country.name + '</b><br/>攻击次数: ' + country.value);
                }
            });
            
            var legend = L.control({position: 'bottomright'});
            legend.onAdd = function(map) {
                var div = L.DomUtil.create('div', 'legend');
                div.innerHTML = '<h4>攻击强度</h4>';
                var grades = [0, 20, 50, 100];
                var labels = [];
                for (var i = 0; i < grades.length; i++) {
                    div.innerHTML +=
                        '<i style="background:rgba(0,212,255,' + (0.3 + (grades[i]/100)*0.7) + ');width:' + (5 + (grades[i]/100)*15) + 'px;height:' + (5 + (grades[i]/100)*15) + 'px;border-radius:50%;display:inline-block;margin-right:5px;"></i> ' +
                        grades[i] + (grades[i + 1] ? '&ndash;' + grades[i + 1] : '+') + '<br>';
                }
                return div;
            };
            legend.addTo(map);
            
            window.addEventListener('resize', function() {
                map.invalidateSize();
            });
        }).catch(err => {
            console.error('地图数据加载失败:', err);
        });
    </script>
</body>
</html>
""")

    chart_data = generate_chart_data(df)
    heatmap_data = json.dumps(stats.get("heatmap_data", [0]*24))
    top_passwords = get_top_passwords(accounts)
    top_usernames = get_top_usernames(accounts)

    html_content = template.render(
        df=df, stats=stats, chart_data=chart_data,
        heatmap_data=heatmap_data,
        top_passwords=top_passwords, top_usernames=top_usernames,
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
        print(f"📊 总攻击 {stats['total_attacks']} 次 | 独立IP {stats['unique_ips']} 个 | 活跃蜜罐 {stats['active_honeypots']} 个")
        print(f"📈 较上周: {week_compare['trend']} ({week_compare['change']}次)")

        generate_map_data(df)
        export_csv(df)
        generate_html(df, stats, accounts, week_compare)
        print("✨ v6.0 所有任务完成！")
    else:
        print("⚠️ 未拉取到攻击数据")

if __name__ == "__main__":
    main()