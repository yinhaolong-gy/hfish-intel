#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v6.1
功能：全蜜罐数据 + 弱口令字典 + 攻击趋势图 + 完整世界地图 +
      攻击时段热力图 + 周数据对比 + CSV导出 + 分蜜罐统计
优化：地图修复、移动端适配、加载动画、数据面板优化
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

END_TIME = datetime.now()
START_TIME = END_TIME - timedelta(days=90)
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
    keep_cols = ["attack_ip", "ip_location", "client_name", "service_name", "service_port", "create_time"]
    cols = [c for c in keep_cols if c in df.columns]
    df = df[cols].copy()

    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour

    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(
            lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x
        )

    all_hp = [
        "SSH蜜罐", "TCP端口监听", "Elasticsearch蜜罐", "Telnet蜜罐",
        "FTP蜜罐", "HTTP代理蜜罐", "MYSQL蜜罐", "REDIS蜜罐",
        "Tomcat蜜罐", "Weblogic蜜罐"
    ]
    hp_counts = df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}
    hp_data = {hp: hp_counts.get(hp, 0) for hp in all_hp}

    heatmap_data = [0] * 24
    if "hour" in df.columns:
        hour_counts = df["hour"].value_counts().to_dict()
        for h, c in hour_counts.items():
            heatmap_data[int(h)] = c

    # 端口分布统计
    port_counts = df["service_port"].value_counts().head(10).to_dict() if "service_port" in df.columns else {}

    stats = {
        "total_attacks": len(df),
        "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
        "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
        "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
        "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
        "top_ports": port_counts,
        "honeypot_data": hp_data,
        "active_honeypots": sum(1 for v in hp_data.values() if v > 0),
        "heatmap_data": heatmap_data,
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }
    return df, stats

# ==================== 5. 世界地图数据 ====================
def generate_map_data(df):
    """生成世界地图JSON数据"""
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

# ==================== 6. CSV导出 ====================
def export_csv(df):
    """导出攻击数据为CSV"""
    if not df.empty:
        edf = df[["attack_ip", "ip_location", "service_name", "service_port", "create_time"]].head(500).copy()
        edf.columns = ["攻击源IP", "地理位置", "服务类型", "端口", "攻击时间"]
        edf.to_csv(os.path.join(OUTPUT_DIR, CSV_FILE), index=False, encoding="utf-8-sig")

# ==================== 7. 趋势图数据 ====================
def generate_chart_data(df):
    """生成近7天趋势数据"""
    if "create_time" in df.columns and not df.empty:
        df["date"] = pd.to_datetime(df["create_time"]).dt.strftime("%m-%d")
        daily = df["date"].value_counts().sort_index()
        return json.dumps({"dates": daily.index.tolist()[-7:], "counts": daily.values.tolist()[-7:]})
    return json.dumps({"dates": [], "counts": []})

# ==================== 8. 周对比 ====================
def compare_weeks(current_df, last_week_logs):
    """本周与上周数据对比"""
    if last_week_logs:
        last_count = len(last_week_logs)
        change = len(current_df) - last_count
        return {"current": len(current_df), "last": last_count, "change": change,
                "trend": "上升" if change > 0 else ("下降" if change < 0 else "持平")}
    return {"current": len(current_df), "last": 0, "change": 0, "trend": "无对比数据"}

# ==================== 9. HTML页面生成 ====================
def generate_html(df, stats, accounts, week_compare):
    """生成完整的威胁情报HTML页面"""
    template = Template("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HFish 威胁情报监控中心</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        :root {
            --bg: #0a0a14; --card: rgba(255,255,255,0.04);
            --primary: #00d4ff; --accent: #7c3aed;
            --text: #e2e8f0; --muted: #94a3b8; --border: rgba(0,212,255,0.12);
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
            background: linear-gradient(135deg, #0a0a14 0%, #0f172a 40%, #1e1b4b 70%, #0a0a14 100%);
            min-height:100vh; padding:15px; color:var(--text);
        }
        .container { max-width:1440px; margin:0 auto; }
        .header {
            text-align:center; padding:25px 20px; margin-bottom:25px;
            background:linear-gradient(135deg,rgba(0,212,255,0.08),rgba(124,58,237,0.06));
            border-radius:20px; border:1px solid var(--border);
        }
        .header h1 {
            font-size:clamp(1.5em, 4vw, 2.5em);
            background:linear-gradient(135deg,var(--primary),var(--accent));
            -webkit-background-clip:text; -webkit-text-fill-color:transparent;
        }
        .header .subtitle { color:var(--muted); font-size:0.85em; margin-top:6px; }
        .stats-grid {
            display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
            gap:12px; margin-bottom:25px;
        }
        .stat-card {
            background:var(--card); border:1px solid var(--border);
            border-radius:14px; padding:18px 12px; text-align:center;
            transition:all .3s;
        }
        .stat-card:hover { transform:translateY(-4px); border-color:var(--primary); }
        .stat-number { font-size:clamp(1.6em,3vw,2.2em); font-weight:700; color:var(--primary); }
        .stat-label { color:var(--muted); font-size:0.78em; margin-top:4px; }
        .section {
            background:rgba(255,255,255,0.02); border:1px solid var(--border);
            border-radius:16px; padding:20px; margin-bottom:20px;
        }
        .section-title {
            font-size:1.15em; color:var(--primary); margin-bottom:16px;
            border-bottom:1px solid var(--border); padding-bottom:10px;
        }
        .chart-box { width:100%; height:350px; }
        .map-box { width:100%; height:480px; }
        .heatmap-box { width:100%; height:280px; }
        .hp-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:10px; }
        .hp-item {
            background:rgba(0,212,255,0.05); border:1px solid var(--border);
            border-radius:12px; padding:14px; text-align:center; transition:all .3s;
        }
        .hp-item:hover { transform:translateY(-2px); border-color:var(--primary); }
        .hp-name { color:var(--muted); font-size:0.72em; }
        .hp-count { font-size:1.5em; font-weight:700; color:var(--primary); }
        .hp-zero { color:#475569; }
        .top-list { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; }
        .list-item {
            background:rgba(0,0,0,0.3); border:1px solid rgba(0,212,255,0.06);
            border-radius:12px; padding:16px;
        }
        .list-item h3 { color:var(--primary); font-size:0.95em; margin-bottom:10px; }
        .rank-row {
            display:flex; justify-content:space-between; padding:6px 0;
            border-bottom:1px solid rgba(255,255,255,0.04); font-size:0.82em;
        }
        .rank-val { font-weight:700; color:var(--primary); }
        table { width:100%; border-collapse:collapse; font-size:0.82em; margin-top:10px; }
        th { background:rgba(0,212,255,0.1); color:var(--primary); padding:10px; text-align:left; }
        td { padding:8px 10px; border-bottom:1px solid rgba(255,255,255,0.04); }
        tr:hover td { background:rgba(0,212,255,0.03); }
        .badge {
            background:rgba(0,212,255,0.12); color:var(--primary);
            padding:3px 8px; border-radius:12px; font-size:0.78em;
        }
        .footer { text-align:center; color:#555; margin-top:30px; font-size:0.8em; }
        .warn { color:#f87171; font-weight:500; }
        .up { color:#4ade80; } .down { color:#f87171; }
        .compare-row { display:flex; gap:20px; justify-content:center; flex-wrap:wrap; }
        .compare-item { background:rgba(0,0,0,0.3); border-radius:12px; padding:15px 22px; text-align:center; }
        .compare-num { font-size:1.8em; font-weight:700; }
        .compare-label { color:var(--muted); font-size:0.75em; }
        @media (max-width:768px) {
            .chart-box { height:250px; } .map-box { height:350px; }
            .stats-grid { grid-template-columns:repeat(3,1fr); }
        }
        @media (max-width:480px) {
            .stats-grid { grid-template-columns:repeat(2,1fr); }
            .header h1 { font-size:1.3em; }
        }
    </style>
</head>
<body>
<div class="container">

<!-- 头部 -->
<div class="header">
    <h1>🛡️ HFish 威胁情报监控中心</h1>
    <p class="subtitle">📊 {{ stats.time_range }} | 更新: {{ last_update }}</p>
</div>

<!-- 统计卡片 -->
<div class="stats-grid">
    <div class="stat-card"><div class="stat-number">{{ stats.total_attacks }}</div><div class="stat-label">总攻击次数</div></div>
    <div class="stat-card"><div class="stat-number">{{ stats.unique_ips }}</div><div class="stat-label">独立IP</div></div>
    <div class="stat-card"><div class="stat-number">{{ account_count }}</div><div class="stat-label">账号资产</div></div>
    <div class="stat-card"><div class="stat-number">{{ stats.active_honeypots }}</div><div class="stat-label">活跃蜜罐</div></div>
    <div class="stat-card"><div class="stat-number">{{ week_compare.current }}</div><div class="stat-label">本周攻击</div></div>
    <div class="stat-card">
        <div class="stat-number {{ 'up' if week_compare.trend=='上升' else 'down' if week_compare.trend=='下降' else '' }}">
            {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
        </div>
        <div class="stat-label">{{ week_compare.trend }}</div>
    </div>
</div>

<!-- 攻击趋势 -->
<div class="section">
    <h2 class="section-title">📈 攻击趋势（近7天）</h2>
    <div class="chart-box"><canvas id="trendChart"></canvas></div>
</div>

<!-- 攻击时段热力图 -->
<div class="section">
    <h2 class="section-title">🔥 攻击时段分布（24小时）</h2>
    <div class="heatmap-box"><canvas id="heatmapChart"></canvas></div>
</div>

<!-- 周对比 -->
<div class="section">
    <h2 class="section-title">📊 本周 vs 上周</h2>
    <div class="compare-row">
        <div class="compare-item"><div class="compare-num" style="color:var(--primary);">{{ week_compare.current }}</div><div class="compare-label">本周攻击</div></div>
        <div class="compare-item"><div class="compare-num" style="color:var(--muted);">{{ week_compare.last }}</div><div class="compare-label">上周攻击</div></div>
        <div class="compare-item">
            <div class="compare-num {{ 'up' if week_compare.trend=='上升' else 'down' if week_compare.trend=='下降' else '' }}">
                {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
            </div>
            <div class="compare-label">{{ week_compare.trend }}</div>
        </div>
    </div>
</div>

<!-- 世界地图 -->
<div class="section">
    <h2 class="section-title">🗺️ 攻击来源全球分布</h2>
    <div class="map-box" id="worldMap"></div>
</div>

<!-- 分蜜罐统计 -->
<div class="section">
    <h2 class="section-title">🎯 各蜜罐受攻击次数</h2>
    <div class="hp-grid">
        {% for name, count in stats.honeypot_data.items() %}
        <div class="hp-item"><div class="hp-name">{{ name }}</div><div class="hp-count {% if count==0 %}hp-zero{% endif %}">{{ count }}</div></div>
        {% endfor %}
    </div>
</div>

<!-- 攻击分析 -->
<div class="section">
    <h2 class="section-title">📊 攻击统计分析</h2>
    <div class="top-list">
        <div class="list-item"><h3>🔝 Top 10 攻击IP</h3>
            {% for ip, count in stats.top_ips.items() %}
            <div class="rank-row"><span>{{ ip }}</span><span class="rank-val">{{ count }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>🌍 攻击来源国家</h3>
            {% for country, count in stats.top_countries.items() %}
            <div class="rank-row"><span>{{ country }}</span><span class="rank-val">{{ count }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>🔑 弱口令 TOP 10</h3>
            {% for pwd, count in top_passwords %}
            <div class="rank-row"><span class="warn">{{ pwd }}</span><span class="rank-val">{{ count }}</span></div>{% endfor %}
            {% if not top_passwords %}<div class="rank-row"><span>暂无数据</span></div>{% endif %}</div>
        <div class="list-item"><h3>👤 用户名 TOP 5</h3>
            {% for user, count in top_usernames %}
            <div class="rank-row"><span>{{ user }}</span><span class="rank-val">{{ count }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>🔌 端口分布 TOP 10</h3>
            {% for port, count in stats.top_ports.items() %}
            <div class="rank-row"><span>端口 {{ port }}</span><span class="rank-val">{{ count }}</span></div>{% endfor %}</div>
    </div>
</div>

<!-- 最新攻击详情 -->
<div class="section">
    <h2 class="section-title">📋 最新攻击记录（前100条）</h2>
    <div style="overflow-x:auto; max-height:380px; overflow-y:auto;">
        <table><thead><tr><th>攻击IP</th><th>位置</th><th>服务</th><th>端口</th><th>时间</th></tr></thead><tbody>
            {% for _, row in df.head(100).iterrows() %}
            <tr><td><span class="badge">{{ row.get('attack_ip','-') }}</span></td><td>{{ row.get('ip_location','-') }}</td><td>{{ row.get('service_name','-') }}</td><td>{{ row.get('service_port','-') }}</td><td>{{ row.get('create_time','-') }}</td></tr>{% endfor %}
        </tbody></table>
    </div>
</div>

<div class="footer"><p>🤖 HFish 自动采集 | 每6小时更新 | 毕业设计作品 | {{ last_update }}</p></div>
</div>

<!-- 趋势图 -->
<script>
new Chart(document.getElementById('trendChart'),{
    type:'line',
    data:{labels:{{ chart_data|safe }}.dates,datasets:[{label:'攻击次数',data:{{ chart_data|safe }}.counts,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.08)',fill:true,tension:0.4,pointRadius:4,pointBackgroundColor:'#00d4ff'}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'}},y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'},beginAtZero:true}}}
});
</script>

<!-- 热力图 -->
<script>
new Chart(document.getElementById('heatmapChart'),{
    type:'bar',
    data:{labels:['0时','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23'],datasets:[{label:'攻击次数',data:{{ heatmap_data|safe }},backgroundColor:function(c){var v=c.raw;return v>200?'#7c3aed':v>100?'#00d4ff':v>50?'#0284c7':'#0d47a1';},borderRadius:5}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'},beginAtZero:true}}}
});
</script>

<!-- 世界地图 -->
<script>
(function(){
    var dom = document.getElementById('worldMap');
    var mc = echarts.init(dom);
    fetch('country_data.json').then(r=>r.json()).then(data=>{
        mc.setOption({
            tooltip:{trigger:'item',formatter:function(p){return '<b>'+p.name+'</b><br/>攻击: '+(p.value||0)+' 次';}},
            visualMap:{min:0,max:data.maxCount||100,text:['高','低'],realtime:false,calculable:true,inRange:{color:['#1a1a3e','#0d47a1','#1565c0','#00d4ff','#06b6d4']},textStyle:{color:'#94a3b8'}},
            series:[{type:'map',map:'world',roam:true,zoom:1.2,center:[20,30],aspectScale:0.75,
                emphasis:{label:{show:true,color:'#fff'},itemStyle:{areaColor:'#00d4ff'}},
                itemStyle:{borderColor:'rgba(255,255,255,0.15)',areaColor:'#1a1a3e'},
                data:data.countries||[]
            }]
        });
    }).catch(function(){
        mc.setOption({
            tooltip:{trigger:'item'},
            visualMap:{min:0,max:100,inRange:{color:['#1a1a3e','#0d47a1','#1565c0','#00d4ff']},textStyle:{color:'#94a3b8'}},
            series:[{type:'map',map:'world',roam:true,zoom:1.2,center:[20,30],aspectScale:0.75,
                itemStyle:{borderColor:'rgba(255,255,255,0.15)',areaColor:'#1a1a3e'},data:[]
            }]
        });
    });
    window.addEventListener('resize',function(){mc.resize();});
})();
</script>
</body>
</html>""")

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
    print(f"✅ HTML 已生成")

# ==================== 主函数 ====================
def main():
    print("🔄 拉取攻击日志...")
    logs = fetch_attack_logs(START_TIME, END_TIME)
    print("🔄 拉取上周数据...")
    last_week = fetch_attack_logs(LAST_WEEK_START, LAST_WEEK_END)
    print("🔄 拉取账号资产...")
    accounts = fetch_accounts()
    if logs:
        df, stats = process_data(logs)
        wc = compare_weeks(df, last_week)
        print(f"📊 攻击:{stats['total_attacks']} | IP:{stats['unique_ips']} | 账号:{len(accounts)} | 蜜罐:{stats['active_honeypots']}")
        generate_map_data(df)
        export_csv(df)
        generate_html(df, stats, accounts, wc)
        print("✨ v6.1 完成!")
    else:
        print("⚠️ 无数据")

if __name__ == "__main__":
    main()