#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — 报告输出模块

生成 HTML 报告页面和 CSV 数据导出。
"""

import json
import os
from datetime import datetime
from collections import Counter

from jinja2 import Template

from config import OUTPUT_DIR
from data_analyzer import gen_chart_data

SNAPSHOT_FILE = "weekly_snapshot.json"

def load_weekly_snapshot(output_dir=None):
    path = os.path.join(output_dir or OUTPUT_DIR, SNAPSHOT_FILE)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, KeyError):
            pass
    return None

def save_weekly_snapshot(attack_count, unique_ips, output_dir=None):
    path = os.path.join(output_dir or OUTPUT_DIR, SNAPSHOT_FILE)
    os.makedirs(os.path.dirname(path) or output_dir or OUTPUT_DIR, exist_ok=True)
    snapshot = {
        "count": int(attack_count),
        "ips": int(unique_ips),
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    print(f"  📸 本周快照已保存: {attack_count} 条 ({unique_ips} IP)")



def export_csv(df):
    """导出攻击数据为CSV文件"""
    if not df.empty:
        export_df = df[["attack_ip", "ip_location", "service_name",
                        "service_port", "create_time"]].head(500).copy()
        export_df.columns = ["攻击源IP", "地理位置", "服务类型", "端口", "攻击时间"]
        export_df.to_csv(
            os.path.join(OUTPUT_DIR, "threat_data.csv"),
            index=False, encoding="utf-8-sig",
        )
        print("📁 CSV 已导出 (前500条)")


def generate_html(df, stats, accounts, week_compare, map_data):
    """生成完整的威胁情报HTML页面"""

    chart_data = gen_chart_data(df, end_date=datetime.now().date())
    heatmap_list = stats.get("heatmap_data", [0] * 24)
    heatmap_data = json.dumps([int(x) if hasattr(x, 'item') else x for x in heatmap_list])

    # 弱口令和用户名统计
    def safe_truncate(text, max_len=30):
        if not isinstance(text, str):
            text = str(text)
        if len(text) > max_len:
            return text[:max_len] + "..."
        return text

    top_passwords = [(safe_truncate(p, 40), c) for p, c in Counter(
        [a.get("password", "") for a in accounts if a.get("password")]
    ).most_common(10)]

    top_usernames = [(safe_truncate(u, 30), c) for u, c in Counter(
        [a.get("username", "") for a in accounts if a.get("username")]
    ).most_common(5)]

    template = Template("""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>自动化威胁情报采集与分析系统</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        :root {
            --primary: #2563eb;
            --secondary: #7c3aed;
            --accent: #0891b2;
            --danger: #dc2626;
            --success: #16a34a;
            --warning: #f59e0b;
            --bg: #f1f5f9;
            --bg-card: #ffffff;
            --border: #e2e8f0;
            --text: #1e293b;
            --text-muted: #64748b;
            --shadow: 0 4px 24px rgba(0,0,0,0.06);
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
            background: var(--bg);
            min-height:100vh; padding:20px; color:var(--text);
        }
        .container { max-width:1440px; margin:0 auto; }
        .header {
            text-align:center; padding:40px 20px; margin-bottom:30px;
            background: linear-gradient(135deg, #1e40af, #7c3aed);
            border-radius:20px; color:#fff;
            box-shadow: 0 8px 32px rgba(37,99,235,0.2);
            position: relative; overflow: hidden;
        }
        .header::before {
            content: ''; position: absolute; top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: radial-gradient(circle at 30% 50%, rgba(255,255,255,0.08) 0%, transparent 60%);
        }
        .header h1 {
            font-size:clamp(1.6em,5vw,2.8em);
            color:#fff; margin-bottom:10px; position:relative;
            text-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        .header .subtitle { color: rgba(255,255,255,0.8); font-size:0.9em; letter-spacing:1px; position:relative; }
        .header .update-badge {
            display: inline-block; margin-top: 12px;
            background: rgba(255,255,255,0.15); color: #fff;
            padding: 4px 14px; border-radius: 20px; font-size: 0.75em;
            backdrop-filter: blur(4px); border: 1px solid rgba(255,255,255,0.2);
            position:relative;
        }
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:18px; margin-bottom:30px; }
        .stat-card {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius:16px; padding:22px 15px;
            text-align:center; position:relative; overflow:hidden;
            transition: all .3s ease; box-shadow: var(--shadow);
        }
        .stat-card::before {
            content:''; position:absolute; top:0; left:0; right:0; height:3px;
            background:linear-gradient(90deg,var(--primary),var(--secondary));
            transform:scaleX(0); transition:transform .3s ease;
        }
        .stat-card:hover::before { transform:scaleX(1); }
        .stat-card:hover { transform:translateY(-4px); box-shadow:0 8px 30px rgba(37,99,235,0.12); }
        .stat-number { font-size:clamp(1.8em,4vw,2.5em); font-weight:700; color:var(--primary); margin-bottom:6px; }
        .stat-number.up { color:var(--success); }
        .stat-number.down { color:var(--danger); }
        .stat-label { color:var(--text-muted); font-size:0.85em; letter-spacing:0.5px; font-weight:500; }
        .section {
            background:var(--bg-card); border:1px solid var(--border);
            border-radius:16px; padding:28px; margin-bottom:25px;
            box-shadow:var(--shadow); transition:all .3s ease;
        }
        .section:hover { border-color:var(--primary); box-shadow:0 8px 30px rgba(37,99,235,0.1); }
        .section-title { font-size:1.35em; color:var(--primary); margin-bottom:22px; border-bottom:2px solid var(--border); padding-bottom:14px; display:flex; align-items:center; gap:12px; font-weight:600; }
        .chart-container { width:100%; height:400px; position:relative; }
        .map-container { width:100%; height:550px; border-radius:16px; background:var(--bg); overflow:hidden; border:1px solid var(--border); }
        .heatmap-container { width:100%; height:320px; }
        .honeypot-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:15px; }
        .hp-item {
            background:linear-gradient(135deg,rgba(37,99,235,0.04),rgba(124,58,237,0.03));
            border:1px solid var(--border); border-radius:16px; padding:20px 12px;
            text-align:center; transition:all .3s ease; position:relative; overflow:hidden;
        }
        .hp-item::after {
            content:''; position:absolute; top:-50%; left:-50%; width:200%; height:200%;
            background:radial-gradient(circle,rgba(37,99,235,0.06) 0%,transparent 70%);
            opacity:0; transition:opacity .3s ease;
        }
        .hp-item:hover::after { opacity:1; }
        .hp-item:hover { transform:translateY(-4px); border-color:var(--primary); box-shadow:0 8px 30px rgba(37,99,235,0.12); }
        .hp-name { color:var(--text-muted); font-size:0.78em; margin-bottom:10px; word-break:break-all; }
        .hp-count { font-size:2em; font-weight:700; color:var(--primary); }
        .hp-zero { color:#475569; }
        .top-list { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px; }
        .list-item {
            background:var(--bg-card); border:1px solid var(--border);
            border-radius:16px; padding:18px; transition:all .3s ease; overflow:hidden;
        }
        .list-item:hover { border-color:var(--primary); box-shadow:0 8px 30px rgba(37,99,235,0.1); }
        .list-item h3 { color:var(--primary); margin-bottom:15px; font-size:1.05em; display:flex; align-items:center; gap:8px; }
        .rank-item { display:flex; justify-content:space-between; align-items:center; padding:10px 8px; border-bottom:1px solid var(--border); font-size:0.88em; transition:all .2s ease; word-break:break-all; gap:10px; }
        .rank-item:hover { background:rgba(37,99,235,0.04); border-radius:8px; }
        .rank-item span:first-child { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; min-width:0; }
        .rank-value { font-weight:700; color:var(--primary); font-size:1.1em; flex-shrink:0; white-space:nowrap; }
        .warning { color:#dc2626; font-family:monospace; word-break:break-all; max-width:100%; overflow:hidden; text-overflow:ellipsis; }
        .data-table { width:100%; border-collapse:collapse; margin-top:15px; font-size:0.85em; }
        .data-table th { background:rgba(37,99,235,0.08); color:var(--primary); padding:12px 15px; text-align:left; font-weight:600; }
        .data-table td { padding:11px 15px; border-bottom:1px solid var(--border); color:var(--text); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .data-table tr:hover td { background:rgba(37,99,235,0.03); }
        .badge { background:rgba(37,99,235,0.08); color:var(--primary); padding:4px 12px; border-radius:16px; font-size:0.8em; border:1px solid rgba(37,99,235,0.15); transition:all .2s ease; }
        .badge:hover { background:rgba(37,99,235,0.15); }
        .compare-section { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:20px; }
        .compare-card { background:var(--bg-card); border:1px solid var(--border); border-radius:18px; padding:25px; text-align:center; transition:all .3s ease; }
        .compare-card:hover { transform:translateY(-3px); border-color:var(--primary); box-shadow:var(--shadow); }
        .compare-value { font-size:3em; font-weight:700; margin-bottom:8px; }
        .compare-label { color:var(--text-muted); font-size:0.9em; margin-bottom:5px; }
        .compare-change { font-size:1.1em; font-weight:600; }
        .compare-change.up { color:#dc2626; }
        .compare-change.down { color:#16a34a; }
        .trend-icon { font-size:1.5em; margin-bottom:10px; }
        .footer { text-align:center; color:var(--text-muted); margin-top:40px; font-size:0.85em; padding:20px; border-top:1px solid var(--border); }
        @media (max-width:768px) {
            body { padding:10px; }
            .stats-grid { grid-template-columns:repeat(3,1fr); gap:12px; }
            .stat-card { padding:15px 8px; }
            .stat-number { font-size:1.5em; }
            .chart-container { height:300px; }
            .map-container { height:400px; }
            .heatmap-container { height:250px; }
            .top-list { grid-template-columns:1fr; }
        }
        @media (max-width:480px) {
            .stats-grid { grid-template-columns:repeat(2,1fr); }
            .header h1 { font-size:1.4em; }
            .section { padding:15px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>自动化威胁情报采集与分析系统</h1>
            <p class="subtitle">数据采集周期: {{ stats.time_range }} | 报告生成时间: {{ last_update }}</p>
            <span class="update-badge">基于 HFish 蜜罐 · 自动化威胁情报采集</span>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number">{{ stats.total_attacks }}</div><div class="stat-label">有效攻击事件总数</div></div>
            <div class="stat-card"><div class="stat-number">{{ stats.unique_ips }}</div><div class="stat-label">独立攻击源 IP</div></div>
            <div class="stat-card"><div class="stat-number">{{ account_count }}</div><div class="stat-label">采集账号口令记录</div></div>
            <div class="stat-card"><div class="stat-number">{{ stats.active_honeypots }}</div><div class="stat-label">活跃蜜罐节点</div></div>
            <div class="stat-card"><div class="stat-number">{{ week_compare.current }}</div><div class="stat-label">本周期攻击次数</div></div>
            <div class="stat-card">
                <div class="stat-number {{ 'up' if week_compare.trend == '上升' else 'down' if week_compare.trend == '下降' else '' }}">
                    {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
                </div>
                <div class="stat-label">较上周期{{ week_compare.trend }}</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">攻击趋势分析（近 7 天）</h2>
            <div class="chart-container"><canvas id="attackTrendChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">攻击时段分布（24 小时）</h2>
            <div class="heatmap-container"><canvas id="heatmapChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">周期攻击量环比分析</h2>
            <div class="compare-section">
                <div class="compare-card"><div class="compare-value" style="color:var(--primary);">{{ week_compare.current }}</div><div class="compare-label">本周期攻击次数</div></div>
                <div class="compare-card"><div class="trend-icon">📉</div><div class="compare-value" style="color:var(--text-muted);">{{ week_compare.last }}</div><div class="compare-label">上周期攻击次数</div></div>
                <div class="compare-card">
                    <div class="trend-icon">{{ '↑' if week_compare.trend == '上升' else '↓' if week_compare.trend == '下降' else '→' }}</div>
                    <div class="compare-value {{ 'up' if week_compare.trend == '上升' else 'down' if week_compare.trend == '下降' else '' }}">
                        {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
                    </div>
                    <div class="compare-label">环比变化量</div>
                    {% if week_compare.last > 0 %}
                    <div class="compare-change {{ 'up' if week_compare.trend == '上升' else 'down' if week_compare.trend == '下降' else '' }}">
                        {{ week_compare.change_percent }}{% if week_compare.change_percent > 0 %}+{% endif %}%
                    </div>
                    {% endif %}
                </div>
            </div>
            <div class="chart-container" style="height:300px;margin-top:20px;"><canvas id="weekCompareChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">攻击来源地理分布</h2>
            <div class="map-container" id="worldMap"></div>
        </div>

        <div class="section">
            <h2 class="section-title">蜜罐节点攻击量统计</h2>
            <div class="honeypot-grid">
                {% for name, count in stats.honeypot_data.items() %}
                <div class="hp-item"><div class="hp-name">{{ name }}</div><div class="hp-count {% if count == 0 %}hp-zero{% endif %}">{{ count }}</div></div>
                {% endfor %}
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">攻击数据多维统计</h2>
            <div class="top-list">
                <div class="list-item">
                    <h3>攻击源 IP Top 10</h3>
                    {% for ip, count in stats.top_ips.items() %}
                    <div class="rank-item"><span title="{{ ip }}">{{ ip }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>攻击来源国家/地区 Top 10</h3>
                    {% for country, count in stats.top_countries.items() %}
                    <div class="rank-item"><span>{{ country }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>弱口令爆破字典 Top 10</h3>
                    {% for pwd, count in top_passwords %}
                    <div class="rank-item"><span class="warning">{{ pwd }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>👤 高频攻击用户名 Top 5</h3>
                    {% for user, count in top_usernames %}
                    <div class="rank-item"><span>{{ user }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>目标端口分布 Top 10</h3>
                    {% for port, count in stats.top_ports.items() %}
                    <div class="rank-item"><span>端口 {{ port }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">最新攻击事件记录（前 100 条）</h2>
            <div style="overflow-x:auto;max-height:400px;overflow-y:auto;">
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
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>HFish 蜜罐系统自动采集 | 每6小时更新 | {{ last_update }}</p>
        </div>
    </div>

    <script>
        // --- 1. 攻击趋势图 ---
        const trendCtx = document.getElementById('attackTrendChart').getContext('2d');
        const trendData = {{ chart_data | safe }};
        const gradient = trendCtx.createLinearGradient(0,0,0,400);
        gradient.addColorStop(0,'rgba(37,99,235,0.25)');
        gradient.addColorStop(1,'rgba(37,99,235,0)');
        new Chart(trendCtx, {
            type:'line', data:{
                labels:trendData.dates||[],
                datasets:[
                    {label:'攻击事件数量',data:trendData.counts||[],borderColor:'#2563eb',backgroundColor:gradient,fill:true,tension:0.4,pointBackgroundColor:'#2563eb',pointBorderColor:'#fff',pointBorderWidth:2,pointRadius:6,pointHoverRadius:9},
                ]
            }, options:{
                responsive:true, maintainAspectRatio:false,
                interaction:{mode:'index',intersect:false},
                plugins:{
                    legend:{position:'top',labels:{color:'#64748b',font:{size:13},padding:20,usePointStyle:true,pointStyle:'circle'}},
                    tooltip:{backgroundColor:'#ffffff',titleColor:'#2563eb',bodyColor:'#475569',borderColor:'#e2e8f0',borderWidth:1,padding:12,boxShadow:'0 4px 12px rgba(0,0,0,0.1)'}
                },
                scales:{
                    x:{ticks:{color:'#64748b',font:{size:12}},grid:{color:'rgba(0,0,0,0.05)',drawBorder:false}},
                    y:{ticks:{color:'#64748b',font:{size:12}},grid:{color:'rgba(0,0,0,0.05)',drawBorder:false},beginAtZero:true}
                },
                animation:{duration:1500,easing:'easeOutQuart'}
            }
        });

        // --- 2. 热力图 ---
        const heatCtx = document.getElementById('heatmapChart').getContext('2d');
        const heatData = {{ heatmap_data | safe }};
        const barColors = heatData.map(v => v>200?'#7c3aed':v>100?'#2563eb':v>50?'#0891b2':v>20?'#3b82f6':'#94a3b8');
        new Chart(heatCtx, {
            type:'bar', data:{
                labels:Array.from({length:24},(_,i)=>i+':00'),
                datasets:[{label:'攻击事件数量',data:heatData,backgroundColor:barColors,borderColor:barColors.map(c=>c),borderWidth:1,borderRadius:8,borderSkipped:false}]
            }, options:{
                responsive:true, maintainAspectRatio:false,
                plugins:{legend:{display:false},tooltip:{backgroundColor:'#ffffff',titleColor:'#2563eb',bodyColor:'#475569',borderColor:'#e2e8f0',borderWidth:1,padding:12}},
                scales:{
                    x:{ticks:{color:'#64748b',font:{size:11},maxRotation:45,minRotation:45},grid:{display:false}},
                    y:{ticks:{color:'#64748b',font:{size:12}},grid:{color:'rgba(0,0,0,0.05)',drawBorder:false},beginAtZero:true}
                },
                animation:{duration:1200,easing:'easeOutQuart'}
            }
        });

        // --- 3. 周对比 ---
        const compareCtx = document.getElementById('weekCompareChart').getContext('2d');
        new Chart(compareCtx, {
            type:'bar', data:{
                labels:['本周','上周'],
                datasets:[{label:'攻击事件数量',data:[{{ week_compare.current }},{{ week_compare.last }}],backgroundColor:['#2563eb','#7c3aed'],borderColor:['#2563eb','#7c3aed'],borderWidth:2,borderRadius:12,barThickness:60}]
            }, options:{
                responsive:true, maintainAspectRatio:false,
                plugins:{legend:{display:false},tooltip:{backgroundColor:'#ffffff',titleColor:'#2563eb',bodyColor:'#475569',borderColor:'#e2e8f0',borderWidth:1,padding:12}},
                scales:{
                    x:{ticks:{color:'#64748b',font:{size:14,weight:'600'}},grid:{display:false}},
                    y:{ticks:{color:'#64748b',font:{size:12}},grid:{color:'rgba(0,0,0,0.05)',drawBorder:false},beginAtZero:true}
                },
                animation:{duration:1000,easing:'easeOutQuart'}
            }
        });

        // --- 4. 攻击来源分布 ---
        const mapDom = document.getElementById('worldMap');
        const countryNameMap = {
            "China":"中国","United States":"美国","Russia":"俄罗斯","Canada":"加拿大",
            "Brazil":"巴西","Australia":"澳大利亚","India":"印度","Japan":"日本",
            "Germany":"德国","United Kingdom":"英国","France":"法国","Italy":"意大利",
            "South Korea":"韩国","Singapore":"新加坡","Malaysia":"马来西亚","Indonesia":"印度尼西亚",
            "Thailand":"泰国","Vietnam":"越南","Turkey":"土耳其","Iran":"伊朗",
            "Netherlands":"荷兰","Sweden":"瑞典","Switzerland":"瑞士","Spain":"西班牙",
            "Ukraine":"乌克兰","Poland":"波兰","Mexico":"墨西哥","Nigeria":"尼日利亚",
            "Egypt":"埃及","South Africa":"南非","Argentina":"阿根廷","Chile":"智利",
            "Saudi Arabia":"沙特阿拉伯","United Arab Emirates":"阿联酋","Israel":"以色列",
            "Pakistan":"巴基斯坦","Bangladesh":"孟加拉","Philippines":"菲律宾","New Zealand":"新西兰",
            "Norway":"挪威","Denmark":"丹麦","Finland":"芬兰","Ireland":"爱尔兰",
            "Portugal":"葡萄牙","Greece":"希腊","Austria":"奥地利","Hungary":"匈牙利"
        };
        const mapData = {{ map_data | safe }};

        function showBarChart() {
            const sorted = [...mapData.countries].sort((a,b)=>b.value-a.value).slice(0,15);
            mapDom.innerHTML = '<canvas id="countryBarChart" style="width:100%;height:100%;"></canvas>';
            const ctx = document.getElementById('countryBarChart').getContext('2d');
            new Chart(ctx, {
                type:'bar', data:{
                    labels:sorted.map(c=>countryNameMap[c.name]||c.name),
                    datasets:[{label:'攻击事件数量',data:sorted.map(c=>c.value),backgroundColor:'rgba(37,99,235,0.6)',borderColor:'#2563eb',borderWidth:1,borderRadius:6}]
                }, options:{
                    responsive:true, maintainAspectRatio:false, indexAxis:'y',
                    plugins:{
                        legend:{display:false},
                        title:{display:true,text:'攻击来源 TOP 15 国家/地区',color:'#64748b',font:{size:14}}
                    },
                    scales:{
                        x:{ticks:{color:'#64748b'},grid:{color:'rgba(0,0,0,0.05)'}},
                        y:{ticks:{color:'#64748b'},grid:{display:false}}
                    }
                }
            });
        }

        if (mapData.countries.length > 0) {
            showBarChart();
        } else {
            mapDom.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#64748b;font-size:1.2em;">暂无地图数据</div>';
        }
    </script>
</body>
</html>
    """)

    html_content = template.render(
        df=df,
        stats=stats,
        chart_data=chart_data,
        heatmap_data=heatmap_data,
        map_data=map_data,
        top_passwords=top_passwords,
        top_usernames=top_usernames,
        week_compare=week_compare,
        account_count=len(accounts),
        last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ HTML 报告已生成: {OUTPUT_DIR}/index.html")
