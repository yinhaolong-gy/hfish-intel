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
        .map-container { width: 100%; height: 500px; }
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
        // 加载真实的世界地图数据
        fetch('country_data.json').then(res=>res.json()).then(data=>{
            // 从 CDN 加载真实的世界地图 GeoJSON 数据
            fetch('https://cdn.jsdelivr.net/npm/echarts@5.4.3/map/json/world.json')
            .then(mapRes=>mapRes.json())
            .then(worldJson=>{
                echarts.registerMap('world', worldJson);
                
                var mc = echarts.init(document.getElementById('worldMap'));
                mc.setOption({
                    backgroundColor: 'transparent',
                    tooltip: {
                        trigger: 'item',
                        formatter: function(params) {
                            return params.name + ': ' + (params.value || 0) + ' 次攻击';
                        }
                    },
                    visualMap: {
                        show: true,
                        left: 'right',
                        bottom: '5%',
                        min: 0,
                        max: data.maxCount || 100,
                        inRange: {
                            color: ['#1a1a3e', '#0d47a1', '#1565c0', '#00d4ff', '#06b6d4']
                        },
                        text: ['高', '低'],
                        textStyle: {
                            color: '#94a3b8'
                        },
                        calculable: true
                    },
                    series: [{
                        name: '攻击分布',
                        type: 'map',
                        map: 'world',
                        roam: true,
                        zoom: 1.5,
                        center: [0, 20],
                        label: {
                            show: false,
                            color: '#fff'
                        },
                        emphasis: {
                            label: {
                                show: true,
                                color: '#fff',
                                fontSize: 12
                            },
                            itemStyle: {
                                areaColor: '#00d4ff',
                                shadowColor: 'rgba(0, 212, 255, 0.5)',
                                shadowBlur: 10
                            }
                        },
                        itemStyle: {
                            borderColor: '#334155',
                            borderWidth: 1,
                            areaColor: '#1e293b'
                        },
                        data: data.countries
                    }]
                });
                window.addEventListener('resize', () => mc.resize());
            }).catch(err=>{
                console.error('地图数据加载失败，使用备用方案:', err);
                useSimpleMap(data);
            });
        }).catch(err=>{
            console.error('数据加载失败:', err);
        });
        
        // 备用方案：使用简化但更真实的地图
        function useSimpleMap(data) {
            var simpleMapData = {
                type: 'FeatureCollection',
                features: [
                    {"type":"Feature","properties":{"name":"China"},"geometry":{"type":"Polygon","coordinates":[[[73.5,18.2],[98.8,18.2],[108.9,20.3],[117.9,22.7],[126.6,23.6],[129.3,25.2],[135.1,29.5],[135.1,49.1],[130.8,52.9],[120.9,53.5],[111.2,53.0],[103.1,52.5],[94.1,51.7],[86.3,49.0],[80.0,45.5],[73.5,39.1],[73.5,18.2]]]}},
                    {"type":"Feature","properties":{"name":"United States"},"geometry":{"type":"Polygon","coordinates":[[[-179.2,18.9],[-160.0,50.0],[-140.0,60.0],[-120.0,49.0],[-100.0,49.0],[-80.0,49.0],[-66.9,45.0],[-66.9,25.0],[-90.0,25.0],[-120.0,25.0],[-179.2,18.9]]]}},
                    {"type":"Feature","properties":{"name":"Russia"},"geometry":{"type":"Polygon","coordinates":[[[20.1,41.2],[40.0,45.0],[60.0,50.0],[80.0,50.0],[100.0,50.0],[120.0,50.0],[140.0,50.0],[160.0,50.0],[179.9,50.0],[179.9,70.0],[150.0,70.0],[120.0,70.0],[90.0,70.0],[60.0,70.0],[30.0,60.0],[20.1,41.2]]]}},
                    {"type":"Feature","properties":{"name":"Canada"},"geometry":{"type":"Polygon","coordinates":[[[-141.0,41.7],[-120.0,49.0],[-100.0,49.0],[-80.0,49.0],[-60.0,49.0],[-60.0,70.0],[-100.0,80.0],[-141.0,83.2],[-141.0,41.7]]]}},
                    {"type":"Feature","properties":{"name":"Brazil"},"geometry":{"type":"Polygon","coordinates":[[[-74.0,-33.7],[-60.0,-30.0],[-40.0,-20.0],[-32.3,0.0],[-40.0,10.0],[-60.0,10.0],[-74.0,0.0],[-74.0,-33.7]]]}},
                    {"type":"Feature","properties":{"name":"Australia"},"geometry":{"type":"Polygon","coordinates":[[[112.9,-43.7],[120.0,-40.0],[140.0,-35.0],[153.4,-30.0],[153.4,-10.4],[140.0,-20.0],[120.0,-25.0],[112.9,-43.7]]]}},
                    {"type":"Feature","properties":{"name":"India"},"geometry":{"type":"Polygon","coordinates":[[[68.2,6.7],[75.0,10.0],[85.0,15.0],[97.4,20.0],[97.4,30.0],[80.0,35.0],[68.2,30.0],[68.2,6.7]]]}},
                    {"type":"Feature","properties":{"name":"Japan"},"geometry":{"type":"Polygon","coordinates":[[[129.9,30.3],[135.0,35.0],[140.0,40.0],[145.8,45.5],[140.0,40.0],[135.0,35.0],[129.9,30.3]]]}},
                    {"type":"Feature","properties":{"name":"Germany"},"geometry":{"type":"Polygon","coordinates":[[[5.8,47.3],[10.0,48.0],[15.2,50.0],[12.0,55.0],[7.0,55.0],[5.8,47.3]]]}},
                    {"type":"Feature","properties":{"name":"United Kingdom"},"geometry":{"type":"Polygon","coordinates":[[[-8.4,50.7],[-2.0,51.0],[1.7,53.0],[-2.0,58.0],[-6.0,58.0],[-8.4,50.7]]]}},
                    {"type":"Feature","properties":{"name":"France"},"geometry":{"type":"Polygon","coordinates":[[[-5.1,41.2],[2.0,43.0],[7.0,45.0],[9.5,50.0],[5.0,50.0],[-5.1,41.2]]]}},
                    {"type":"Feature","properties":{"name":"Italy"},"geometry":{"type":"Polygon","coordinates":[[[6.6,35.4],[12.0,38.0],[18.5,42.0],[15.0,47.0],[8.0,45.0],[6.6,35.4]]]}},
                    {"type":"Feature","properties":{"name":"South Korea"},"geometry":{"type":"Polygon","coordinates":[[[124.7,33.1],[128.0,35.0],[131.1,38.0],[128.0,38.5],[124.7,38.0],[124.7,33.1]]]}},
                    {"type":"Feature","properties":{"name":"Singapore"},"geometry":{"type":"Polygon","coordinates":[[[103.6,1.1],[104.0,1.1],[104.0,1.5],[103.6,1.5],[103.6,1.1]]]}},
                    {"type":"Feature","properties":{"name":"Malaysia"},"geometry":{"type":"Polygon","coordinates":[[[100.0,1.0],[115.0,1.0],[119.2,5.0],[105.0,7.0],[100.0,5.0],[100.0,1.0]]]}},
                    {"type":"Feature","properties":{"name":"Indonesia"},"geometry":{"type":"Polygon","coordinates":[[[95.0,-10.0],[110.0,-8.0],[130.0,-6.0],[141.0,-5.0],[130.0,0.0],[110.0,2.0],[95.0,-5.0],[95.0,-10.0]]]}},
                    {"type":"Feature","properties":{"name":"Thailand"},"geometry":{"type":"Polygon","coordinates":[[[98.0,5.5],[102.0,7.0],[105.6,10.0],[102.0,18.0],[98.0,15.0],[98.0,5.5]]]}},
                    {"type":"Feature","properties":{"name":"Vietnam"},"geometry":{"type":"Polygon","coordinates":[[[102.1,8.4],[106.0,10.0],[109.5,12.0],[106.0,22.0],[102.1,20.0],[102.1,8.4]]]}},
                    {"type":"Feature","properties":{"name":"Turkey"},"geometry":{"type":"Polygon","coordinates":[[[25.6,35.6],[30.0,37.0],[40.0,38.0],[44.8,40.0],[40.0,42.0],[30.0,41.0],[25.6,38.0],[25.6,35.6]]]}},
                    {"type":"Feature","properties":{"name":"Iran"},"geometry":{"type":"Polygon","coordinates":[[[44.0,25.0],[50.0,27.0],[60.0,29.0],[63.3,32.0],[55.0,38.0],[45.0,35.0],[44.0,25.0]]]}},
                    {"type":"Feature","properties":{"name":"Netherlands"},"geometry":{"type":"Polygon","coordinates":[[[3.3,50.7],[5.0,51.0],[7.2,52.0],[5.0,53.5],[3.3,52.0],[3.3,50.7]]]}},
                    {"type":"Feature","properties":{"name":"Sweden"},"geometry":{"type":"Polygon","coordinates":[[[11.1,55.3],[15.0,56.0],[20.0,60.0],[24.1,65.0],[18.0,69.0],[12.0,65.0],[11.1,55.3]]]}},
                    {"type":"Feature","properties":{"name":"Switzerland"},"geometry":{"type":"Polygon","coordinates":[[[5.9,45.8],[8.0,46.0],[10.5,47.0],[8.0,47.9],[5.9,47.0],[5.9,45.8]]]}},
                    {"type":"Feature","properties":{"name":"Spain"},"geometry":{"type":"Polygon","coordinates":[[[-9.4,35.9],[-5.0,36.0],[0.0,37.0],[-0.5,42.0],[-5.0,43.7],[-9.4,40.0],[-9.4,35.9]]]}},
                    {"type":"Feature","properties":{"name":"Ukraine"},"geometry":{"type":"Polygon","coordinates":[[[22.1,44.3],[30.0,45.0],[41.0,46.0],[38.0,52.0],[30.0,50.0],[22.1,48.0],[22.1,44.3]]]}},
                    {"type":"Feature","properties":{"name":"Poland"},"geometry":{"type":"Polygon","coordinates":[[[14.1,49.0],[18.0,50.0],[24.1,51.0],[20.0,55.6],[16.0,54.0],[14.1,51.0],[14.1,49.0]]]}}
                ]
            };
            echarts.registerMap('world', simpleMapData);
            
            var mc = echarts.init(document.getElementById('worldMap'));
            mc.setOption({
                tooltip: {trigger: 'item', formatter: p => p.name + ': ' + (p.value || 0) + ' 次攻击'},
                visualMap: {
                    show: true,
                    left: 'right',
                    bottom: '10%',
                    min: 0,
                    max: data.maxCount || 100,
                    inRange: {color: ['#1a1a3e', '#0d47a1', '#1565c0', '#00d4ff', '#06b6d4']},
                    textStyle: {color: '#94a3b8'}
                },
                series: [{
                    type: 'map',
                    map: 'world',
                    roam: true,
                    zoom: 1.5,
                    center: [0, 20],
                    emphasis: {
                        label: {show: true, color: '#fff'},
                        itemStyle: {areaColor: '#00d4ff'}
                    },
                    itemStyle: {
                        borderColor: '#333',
                        areaColor: '#1e293b'
                    },
                    data: data.countries
                }]
            });
            window.addEventListener('resize', () => mc.resize());
        }
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