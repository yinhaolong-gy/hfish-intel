#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish Threat Intelligence Automation Script v5.0
Features: Attack data + Weak passwords + Trend chart + World map + CSV export + Honeypot stats
"""

import requests
import pandas as pd
from datetime import datetime, timedelta
from jinja2 import Template
import os
import json
import urllib3
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HFISH_BASE_URL = "https://127.0.0.1:4433"
API_KEY = "SiFtBHLWzBmcRjndOoQEwPAjvBSBefxSDfvxMoxXwjetfnELGjXIbTZvhFZceacI"

END_TIME = datetime.now()
START_TIME = END_TIME - timedelta(days=90)

OUTPUT_DIR = "./docs"
OUTPUT_FILE = "index.html"
CSV_FILE = "threat_data.csv"

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
        print(f"Attack API failed: {e}")
    return []

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
        print(f"Account API failed: {e}")
    return []

def get_top_passwords(accounts):
    pws = [a.get("password", "") for a in accounts if a.get("password")]
    return Counter(pws).most_common(10)

def get_top_usernames(accounts):
    uns = [a.get("username", "") for a in accounts if a.get("username")]
    return Counter(uns).most_common(5)

def process_data(raw_logs):
    if not raw_logs:
        return pd.DataFrame(), {}
    df = pd.DataFrame(raw_logs)

    keep_cols = ["attack_ip", "ip_location", "client_name", "service_name", "service_port", "create_time"]
    cols = [c for c in keep_cols if c in df.columns]
    df = df[cols].copy()

    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x)

    all_hp = [
        "SSH蜜罐", "TCP端口监听", "Elasticsearch蜜罐", "Telnet蜜罐",
        "FTP蜜罐", "HTTP代理蜜罐", "MYSQL蜜罐", "REDIS蜜罐",
        "Tomcat蜜罐", "Weblogic蜜罐"
    ]
    hp_counts = df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}
    hp_data = {hp: hp_counts.get(hp, 0) for hp in all_hp}

    stats = {
        "total_attacks": len(df),
        "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
        "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
        "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
        "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
        "honeypot_data": hp_data,
        "active_honeypots": sum(1 for v in hp_data.values() if v > 0),
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }
    return df, stats

def generate_map_data(df):
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
        data = {"countries": countries, "maxCount": mx}
        with open(os.path.join(OUTPUT_DIR, "country_data.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

def export_csv(df):
    csv_path = os.path.join(OUTPUT_DIR, CSV_FILE)
    if not df.empty:
        edf = df[["attack_ip", "ip_location", "service_name", "service_port", "create_time"]].head(500).copy()
        edf.columns = ["攻击源IP", "地理位置", "服务类型", "端口", "攻击时间"]
        edf.to_csv(csv_path, index=False, encoding="utf-8-sig")

def generate_chart_data(df):
    if "create_time" in df.columns and not df.empty:
        df["date"] = pd.to_datetime(df["create_time"]).dt.strftime("%m-%d")
        daily = df["date"].value_counts().sort_index()
        return json.dumps({"dates": daily.index.tolist()[-7:], "counts": daily.values.tolist()[-7:]})
    return json.dumps({"dates": [], "counts": []})

def generate_html(df, stats, accounts):
    template = Template("""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HFish Threat Intelligence</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #0a0a14 0%, #0f172a 30%, #1e1b4b 60%, #0a0a14 100%);
            min-height: 100vh; padding: 25px 20px; color: #e2e8f0;
        }
        .container { max-width: 1440px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 35px; padding: 30px; background: rgba(0,212,255,0.06); border-radius: 20px; border: 1px solid rgba(0,212,255,0.12); }
        .header h1 { font-size: 2.8em; color: #00d4ff; margin-bottom: 8px; }
        .header .update-time { color: #94a3b8; font-size: 0.9em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(0,212,255,0.15); border-radius: 16px; padding: 22px; text-align: center; }
        .stat-number { font-size: 2.4em; font-weight: 700; color: #00d4ff; }
        .stat-label { color: #94a3b8; font-size: 0.85em; margin-top: 6px; }
        .section { background: rgba(255,255,255,0.03); border: 1px solid rgba(0,212,255,0.1); border-radius: 20px; padding: 30px; margin-bottom: 30px; }
        .section-title { font-size: 1.3em; color: #00d4ff; margin-bottom: 20px; border-bottom: 1px solid rgba(0,212,255,0.1); padding-bottom: 12px; }
        .chart-container { width: 100%; height: 380px; }
        .map-container { width: 100%; height: 500px; }
        .honeypot-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px; }
        .hp-item { background: rgba(0,212,255,0.06); border: 1px solid rgba(0,212,255,0.12); border-radius: 14px; padding: 20px; text-align: center; }
        .hp-name { color: #94a3b8; font-size: 0.8em; margin-bottom: 8px; }
        .hp-count { font-size: 1.8em; font-weight: 700; color: #00d4ff; }
        .hp-zero { color: #475569; }
        .top-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
        .list-item { background: rgba(0,0,0,0.35); border: 1px solid rgba(0,212,255,0.08); border-radius: 14px; padding: 20px; }
        .list-item h3 { color: #00d4ff; margin-bottom: 12px; font-size: 1em; }
        .rank-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06); color: #cbd5e1; font-size: 0.88em; }
        .rank-value { font-weight: 700; color: #00d4ff; }
        .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.88em; color: #cbd5e1; }
        .data-table th { background: rgba(0,212,255,0.12); color: #00d4ff; padding: 12px; text-align: left; }
        .data-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .data-table tr:hover { background: rgba(0,212,255,0.04); }
        .badge { background: rgba(0,212,255,0.15); color: #00d4ff; padding: 4px 10px; border-radius: 16px; font-size: 0.82em; }
        .footer { text-align: center; color: #64748b; margin-top: 40px; font-size: 0.85em; }
        .warning { color: #f87171; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>HFish Threat Intelligence</h1>
            <p class="update-time">{{ stats.time_range }} | Last Update: {{ last_update }}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number">{{ stats.total_attacks }}</div><div class="stat-label">Total Attacks</div></div>
            <div class="stat-card"><div class="stat-number">{{ stats.unique_ips }}</div><div class="stat-label">Unique IPs</div></div>
            <div class="stat-card"><div class="stat-number">{{ services_count }}</div><div class="stat-label">Service Types</div></div>
            <div class="stat-card"><div class="stat-number">{{ countries_count }}</div><div class="stat-label">Countries</div></div>
            <div class="stat-card"><div class="stat-number">{{ account_count }}</div><div class="stat-label">Accounts</div></div>
            <div class="stat-card"><div class="stat-number">{{ stats.active_honeypots }}</div><div class="stat-label">Active Honeypots</div></div>
        </div>

        <div class="section">
            <h2 class="section-title">Attack Trend (7 days)</h2>
            <div class="chart-container"><canvas id="attackChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">Global Attack Distribution</h2>
            <div class="map-container" id="worldMap"></div>
        </div>

        <div class="section">
            <h2 class="section-title">Attacks per Honeypot</h2>
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
            <h2 class="section-title">Analysis</h2>
            <div class="top-list">
                <div class="list-item"><h3>Top 10 IPs</h3>
                    {% for ip, count in stats.top_ips.items() %}
                    <div class="rank-item"><span>{{ ip }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}</div>
                <div class="list-item"><h3>Top Countries</h3>
                    {% for country, count in stats.top_countries.items() %}
                    <div class="rank-item"><span>{{ country }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}</div>
                <div class="list-item"><h3>Top 10 Weak Passwords</h3>
                    {% for pwd, count in top_passwords %}
                    <div class="rank-item"><span class="warning">{{ pwd }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}
                    {% if not top_passwords %}<div class="rank-item"><span>No data yet</span></div>{% endif %}</div>
                <div class="list-item"><h3>Top 5 Usernames</h3>
                    {% for user, count in top_usernames %}
                    <div class="rank-item"><span>{{ user }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Latest Attacks (100)</h2>
            <div style="overflow-x:auto; max-height:400px; overflow-y:auto;">
                <table class="data-table"><thead><tr><th>IP</th><th>Location</th><th>Service</th><th>Port</th><th>Time</th></tr></thead><tbody>
                    {% for _, row in df.head(100).iterrows() %}
                    <tr><td><span class="badge">{{ row.get('attack_ip', '-') }}</span></td><td>{{ row.get('ip_location', '-') }}</td><td>{{ row.get('service_name', '-') }}</td><td>{{ row.get('service_port', '-') }}</td><td>{{ row.get('create_time', '-') }}</td></tr>{% endfor %}</tbody></table>
            </div>
        </div>

        <div class="footer"><p>HFish Auto Collection | Updates every 6h | Graduation Project</p></div>
    </div>

    <script>
        const ctx = document.getElementById('attackChart').getContext('2d');
        const data = {{ chart_data | safe }};
        new Chart(ctx, {
            type:'line', 
            data:{labels:data.dates, datasets:[{label:'Attacks',data:data.counts,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.1)',fill:true,tension:0.3}]}, 
            options:{responsive:true, maintainAspectRatio:false, plugins:{legend:{labels:{color:'#94a3b8'}}}, scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}
        });
    </script>
    <script>
        fetch('country_data.json')
          .then(res => res.json())
          .then(data => {
              var mc = echarts.init(document.getElementById('worldMap'));
              mc.setOption({
                  tooltip: { trigger:'item', formatter: p => p.name + ': ' + (p.value||0) + ' attacks' },
                  visualMap: { show:false, min:0, max:data.maxCount||100, inRange:{color:['#1a1a3e','#0d47a1','#1565c0','#00d4ff']} },
                  series:[{ type:'map', map:'world', roam:true, emphasis:{label:{show:true,color:'#fff'},itemStyle:{areaColor:'#00d4ff'}}, itemStyle:{borderColor:'#333'}, data:data.countries }]
              });
              window.addEventListener('resize', () => mc.resize());
          });
    </script>
</body>
</html>
""")
    chart_data = generate_chart_data(df)
    top_passwords = get_top_passwords(accounts)
    top_usernames = get_top_usernames(accounts)
    html_content = template.render(
        df=df, stats=stats, chart_data=chart_data,
        top_passwords=top_passwords, top_usernames=top_usernames,
        account_count=len(accounts),
        last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        services_count=len(stats.get("top_services", {})),
        countries_count=len(stats.get("top_countries", {}))
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"HTML generated: {output_path}")

def main():
    print("Fetching attack logs...")
    logs = fetch_attack_logs()
    print("Fetching account data...")
    accounts = fetch_accounts()
    if logs:
        print(f"Attacks: {len(logs)}, Accounts: {len(accounts)}")
        df, stats = process_data(logs)
        print(f"Total: {stats['total_attacks']}, IPs: {stats['unique_ips']}, Active HPs: {stats['active_honeypots']}")
        generate_map_data(df)
        export_csv(df)
        generate_html(df, stats, accounts)
        print("v5.0 Done!")
    else:
        print("No data!")

if __name__ == "__main__":
    main()
