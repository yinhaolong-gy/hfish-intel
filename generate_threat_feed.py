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
        .map-container { width: 100%; height: 500px; border-radius: 12px; position: relative; overflow: hidden; background: #0f172a; }
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
            var container = document.getElementById('worldMap');
            var mapHTML = `
            <div style="width:100%;height:100%;background:linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);position:relative;">
                <svg viewBox="0 0 800 400" style="width:100%;height:100%;">
                    <defs>
                        <filter id="glow2">
                            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
                            <feMerge>
                                <feMergeNode in="coloredBlur"/>
                                <feMergeNode in="SourceGraphic"/>
                            </feMerge>
                        </filter>
                    </defs>
                    
                    <g fill="#1e293b" stroke="#334155" stroke-width="0.8">
                        <path d="M60,100 L100,80 L140,100 L130,140 L95,155 L65,145 Z"/>
                        <path d="M160,115 L220,95 L260,120 L245,165 L205,180 L170,165 Z"/>
                        <path d="M280,90 L380,75 L430,115 L410,185 L330,205 L285,170 Z"/>
                        <path d="M480,65 L620,55 L670,100 L645,180 L530,200 L470,160 Z"/>
                        <path d="M510,220 L590,205 L640,240 L610,295 L530,310 L495,275 Z"/>
                        <path d="M680,100 L750,85 L785,125 L760,180 L705,195 L665,160 Z"/>
                        <path d="M60,240 L110,225 L145,255 L125,300 L85,310 L65,275 Z"/>
                        <path d="M180,215 L280,200 L330,240 L295,305 L220,320 L185,280 Z"/>
                        <path d="M380,240 L460,225 L510,260 L480,315 L420,325 L385,285 Z"/>
                        <path d="M580,220 L670,210 L710,250 L675,305 L610,315 L575,275 Z"/>
                        <path d="M720,300 L780,290 L800,320 L780,360 L730,370 L710,335 Z"/>
                    </g>
                    
                    <g fill="#00d4ff" filter="url(#glow2)">`;
            
            var maxCount = data.maxCount || 100;
            var positions = {
                "China": [550, 145], "United States": [200, 130], "Russia": [520, 100],
                "Canada": [220, 80], "Brazil": [270, 270], "Australia": [730, 320],
                "India": [590, 235], "Japan": [700, 130], "Germany": [420, 120],
                "United Kingdom": [350, 105], "France": [390, 115], "Italy": [445, 140],
                "South Korea": [660, 140], "Singapore": [620, 250], "Malaysia": [635, 260],
                "Indonesia": [660, 285], "Thailand": [600, 245], "Vietnam": [615, 225],
                "Turkey": [495, 155], "Iran": [530, 180], "Netherlands": [395, 108],
                "Sweden": [440, 85], "Switzerland": [420, 130], "Spain": [340, 120],
                "Ukraine": [475, 135], "Poland": [445, 125], "Mexico": [160, 180],
                "Nigeria": [400, 265], "Egypt": [480, 200], "South Africa": [460, 320],
                "Argentina": [250, 320], "Chile": [180, 300], "Saudi Arabia": [515, 195],
                "United Arab Emirates": [545, 205], "Israel": [485, 175], "Pakistan": [560, 220],
                "Bangladesh": [595, 230], "Philippines": [665, 235], "New Zealand": [760, 360],
                "Norway": [420, 70], "Denmark": [435, 95], "Finland": [455, 80],
                "Ireland": [335, 100], "Portugal": [325, 125], "Greece": [475, 165],
                "Austria": [435, 125], "Hungary": [450, 145], "Czech Republic": [440, 120],
                "Belgium": [380, 110], "Luxembourg": [385, 115], "Croatia": [460, 160],
                "Serbia": [470, 165], "Romania": [485, 175], "Bulgaria": [490, 180],
                "Slovakia": [445, 130], "Slovenia": [455, 145], "Bosnia and Herzegovina": [465, 155],
                "Montenegro": [468, 160], "Albania": [480, 170], "Cyprus": [495, 195],
                "Malta": [465, 155], "Iceland": [280, 55], "Greenland": [260, 40],
                "Fiji": [770, 295], "Papua New Guinea": [735, 270], "Solomon Islands": [750, 275],
                "Vanuatu": [765, 280], "New Caledonia": [755, 300], "French Polynesia": [700, 360],
                "Samoa": [780, 355], "Tonga": [785, 360], "Cook Islands": [760, 370],
                "Western Sahara": [360, 245], "Morocco": [345, 240], "Algeria": [385, 240],
                "Tunisia": [395, 245], "Libya": [410, 245], "Sudan": [445, 255],
                "Chad": [425, 270], "Niger": [385, 260], "Mali": [365, 255],
                "Mauritania": [350, 250], "Senegal": [340, 255], "Gambia": [345, 258],
                "Guinea-Bissau": [335, 260], "Guinea": [340, 265], "Sierra Leone": [345, 270],
                "Liberia": [350, 272], "Cote d'Ivoire": [355, 270], "Ghana": [360, 270],
                "Togo": [365, 272], "Benin": [370, 272], "Burkina Faso": [380, 265],
                "Nigeria": [390, 275], "Cameroon": [400, 280], "Equatorial Guinea": [405, 288],
                "Gabon": [410, 295], "Republic of the Congo": [415, 300], "Democratic Republic of the Congo": [425, 310],
                "Central African Republic": [420, 285], "South Sudan": [445, 275], "Ethiopia": [455, 260],
                "Eritrea": [465, 255], "Djibouti": [470, 260], "Somalia": [480, 265],
                "Kenya": [475, 285], "Uganda": [465, 290], "Tanzania": [470, 310],
                "Rwanda": [460, 295], "Burundi": [465, 300], "Malawi": [470, 330],
                "Zambia": [455, 320], "Mozambique": [475, 345], "Zimbabwe": [450, 340],
                "Botswana": [430, 355], "Namibia": [405, 350], "Angola": [385, 330],
                "Madagascar": [500, 330], "Comoros": [485, 320], "Seychelles": [480, 310],
                "Mauritius": [495, 335], "Maldives": [585, 215], "Sri Lanka": [595, 230],
                "Bhutan": [565, 215], "Nepal": [560, 215], "Afghanistan": [520, 195],
                "Kazakhstan": [485, 155], "Uzbekistan": [510, 180], "Turkmenistan": [525, 185],
                "Kyrgyzstan": [510, 160], "Tajikistan": [520, 175], "Armenia": [495, 155],
                "Azerbaijan": [500, 160], "Georgia": [485, 150], "Mongolia": [600, 135],
                "North Korea": [645, 135], "Taiwan": [635, 175], "Hong Kong": [610, 185],
                "Macau": [612, 190], "Brunei": [645, 270], "Cambodia": [590, 235],
                "Laos": [585, 225], "Myanmar": [570, 230], "Jordan": [488, 185],
                "Yemen": [525, 215], "Oman": [540, 210], "Qatar": [535, 205],
                "Bahrain": [530, 210], "Kuwait": [520, 190], "Belarus": [460, 110],
                "Moldova": [485, 145], "Estonia": [450, 95], "Latvia": [445, 105],
                "Lithuania": [450, 110], "Liechtenstein": [415, 125], "Monaco": [395, 125],
                "San Marino": [445, 145], "Vatican City": [445, 147], "Isle of Man": [345, 100],
                "Guernsey": [355, 105], "Jersey": [358, 107], "Bahamas": [140, 165],
                "Cuba": [155, 180], "Jamaica": [165, 175], "Haiti": [180, 185],
                "Dominican Republic": [185, 180], "Puerto Rico": [175, 170], "Virgin Islands": [170, 165],
                "Guadeloupe": [185, 190], "Martinique": [190, 195], "Trinidad and Tobago": [215, 245],
                "Barbados": [205, 240], "Grenada": [200, 245], "Saint Lucia": [195, 240],
                "Saint Vincent and the Grenadines": [195, 235], "Antigua and Barbuda": [185, 170],
                "Dominica": [190, 190], "Saint Kitts and Nevis": [180, 165], "Anguilla": [175, 160],
                "Montserrat": [180, 175], "Turks and Caicos Islands": [150, 155], "Cayman Islands": [185, 200],
                "Aruba": [225, 230], "Bonaire": [230, 230], "Sint Eustatius": [190, 190],
                "Saba": [190, 185], "Curacao": [230, 225], "Colombia": [215, 255],
                "Venezuela": [225, 235], "Guyana": [245, 275], "Suriname": [255, 280],
                "French Guiana": [265, 285], "Peru": [230, 280], "Bolivia": [215, 300],
                "Paraguay": [235, 310], "Uruguay": [235, 345], "Ecuador": [195, 260],
                "Galapagos": [175, 275], "Falkland Islands": [175, 340]
            };
            
            data.countries.forEach(function(country) {
                var pos = positions[country.name];
                if (pos) {
                    var intensity = Math.min(country.value / maxCount, 1);
                    var r = 4 + (intensity * 10);
                    mapHTML += `<circle cx="${pos[0]}" cy="${pos[1]}" r="${r}" fill-opacity="${0.3 + intensity * 0.5}" stroke="#00d4ff" stroke-opacity="${0.5 + intensity * 0.5}" stroke-width="1"/>`;
                }
            });
            
            mapHTML += `</g></svg>
                <div style="position:absolute;bottom:20px;right:20px;background:rgba(0,0,0,0.6);padding:12px;border-radius:8px;">
                    <div style="color:#94a3b8;font-size:12px;margin-bottom:8px;">攻击强度</div>
                    <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
                        <div style="width:8px;height:8px;border-radius:50%;background:#00d4ff;opacity:0.3;"></div>
                        <span style="color:#94a3b8;font-size:11px;">0-20</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
                        <div style="width:12px;height:12px;border-radius:50%;background:#00d4ff;opacity:0.5;"></div>
                        <span style="color:#94a3b8;font-size:11px;">20-50</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
                        <div style="width:16px;height:16px;border-radius:50%;background:#00d4ff;opacity:0.8;"></div>
                        <span style="color:#94a3b8;font-size:11px;">100+</span>
                    </div>
                </div>
                <div style="position:absolute;top:15px;left:15px;color:#94a3b8;font-size:11px;">提示: 圆圈大小表示攻击强度</div>
            </div>`;
            
            container.innerHTML = mapHTML;
        }).catch(err => {
            console.error('地图数据加载失败:', err);
            document.getElementById('worldMap').innerHTML = '<div style="text-align:center;padding-top:180px;color:#94a3b8;font-size:14px;">暂无攻击数据</div>';
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