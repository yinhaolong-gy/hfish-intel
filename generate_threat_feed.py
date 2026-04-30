#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v5.0
功能：全蜜罐数据 + 弱口令字典 + 趋势图 + 世界地图 + CSV导出 + 分蜜罐统计
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

# ==================== 配置区域 ====================
HFISH_BASE_URL = "https://127.0.0.1:4433"
API_KEY = "SiFtBHLWzBmcRjndOoQEwPAjvBSBefxSDfvxMoxXwjetfnELGjXIbTZvhFZceacI"

END_TIME = datetime.now()
START_TIME = END_TIME - timedelta(days=90)

OUTPUT_DIR = "./docs"
OUTPUT_FILE = "index.html"

# ==================== 1. 攻击API ====================
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
        print(f"攻击API失败: {e}")
    return []

# ==================== 2. 账号API ====================
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
        print(f"账号API失败: {e}")
    return []

# ==================== 3. 弱口令统计 ====================
def get_top_passwords(accounts):
    pws = [a.get("password", "") for a in accounts if a.get("password")]
    return Counter(pws).most_common(10)

def get_top_usernames(accounts):
    uns = [a.get("username", "") for a in accounts if a.get("username")]
    return Counter(uns).most_common(5)

# ==================== 4. 数据清洗 ====================
def process_data(raw_logs):
    if not raw_logs:
        return pd.DataFrame(), {}
    df = pd.DataFrame(raw_logs)

    column_mapping = {
        "attack_ip": "攻击源IP",
        "ip_location": "地理位置",
        "client_name": "蜜罐节点",
        "service_name": "服务类型",
        "service_port": "端口",
        "create_time": "攻击时间"
    }
    cols = [c for c in column_mapping if c in df.columns]
    df = df[cols].copy()
    df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns}, inplace=True)

    if "攻击时间" in df.columns:
        df["攻击时间"] = pd.to_datetime(df["攻击时间"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
    if "地理位置" in df.columns:
        df["国家"] = df["地理位置"].apply(lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x)

    all_honeypots = ["SSH蜜罐", "TCP端口监听", "Elasticsearch蜜罐", "Telnet蜜罐",
                     "FTP蜜罐", "HTTP代理蜜罐", "MYSQL蜜罐", "REDIS蜜罐",
                     "Tomcat蜜罐", "Weblogic蜜罐"]
    honeypot_counts = df["服务类型"].value_counts().to_dict() if "服务类型" in df.columns else {}
    honeypot_data = {hp: honeypot_counts.get(hp, 0) for hp in all_honeypots}

    stats = {
        "total_attacks": len(df),
        "unique_ips": df["攻击源IP"].nunique() if "攻击源IP" in df.columns else 0,
        "top_ips": df["攻击源IP"].value_counts().head(10).to_dict() if "攻击源IP" in df.columns else {},
        "top_services": df["服务类型"].value_counts().head(10).to_dict() if "服务类型" in df.columns else {},
        "top_countries": df["国家"].value_counts().head(10).to_dict() if "国家" in df.columns else {},
        "honeypot_data": honeypot_data,
        "active_honeypots": sum(1 for v in honeypot_data.values() if v > 0),
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }
    return df, stats

# ==================== 5. 世界地图数据 ====================
def generate_map_data(df):
    country_name_map = {
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
    if "国家" in df.columns and not df.empty:
        country_counts = df["国家"].value_counts().to_dict()
        countries = []
        for cn_name, count in country_counts.items():
            en_name = country_name_map.get(cn_name, cn_name)
            countries.append({"name": en_name, "value": count})
        max_count = max(country_counts.values()) if country_counts else 1
        data = {"countries": countries, "maxCount": max_count}
        with open(os.path.join(OUTPUT_DIR, "country_data.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

# ==================== 6. 图表数据 ====================
def generate_chart_data(df):
    if "攻击时间" in df.columns and not df.empty:
        df["日期"] = pd.to_datetime(df["攻击时间"]).dt.strftime("%m-%d")
        daily = df["日期"].value_counts().sort_index()
        return json.dumps({"dates": daily.index.tolist()[-7:], "counts": daily.values.tolist()[-7:]})
    return json.dumps({"dates": [], "counts": []})

# ==================== 7. HTML 模板 ====================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HFish 威胁情报源</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a3e 50%, #0f0f2a 100%);
            min-height: 100vh; 
            padding: 30px 20px;
            color: #e0e0e0;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { 
            text-align: center; 
            margin-bottom: 35px; 
            padding: 25px;
            background: linear-gradient(135deg, rgba(0,212,255,0.1) 0%, rgba(13,71,177,0.1) 100%);
            border-radius: 20px;
            border: 1px solid rgba(0,212,255,0.2);
        }
        .header h1 { 
            font-size: 2.8em; 
            color: #00d4ff;
            text-shadow: 0 0 30px rgba(0,212,255,0.6), 0 0 60px rgba(0,212,255,0.3);
            margin-bottom: 10px;
            letter-spacing: 2px;
        }
        .header .update-time { 
            font-size: 0.95em; 
            color: #999;
            opacity: 0.9;
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); 
            gap: 15px; 
            margin-bottom: 30px; 
        }
        .stat-card {
            background: rgba(255,255,255,0.05); 
            backdrop-filter: blur(15px);
            border: 1px solid rgba(0,212,255,0.25); 
            border-radius: 18px; 
            padding: 22px;
            text-align: center; 
            transition: all 0.35s ease;
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0,212,255,0.1), transparent);
            transition: left 0.5s ease;
        }
        .stat-card:hover::before {
            left: 100%;
        }
        .stat-card:hover { 
            transform: translateY(-5px); 
            border-color: #00d4ff;
            box-shadow: 0 10px 40px rgba(0,212,255,0.2);
        }
        .stat-number { 
            font-size: 2.4em; 
            font-weight: 700; 
            color: #00d4ff;
            text-shadow: 0 0 20px rgba(0,212,255,0.5);
        }
        .stat-label { 
            color: #aaa; 
            margin-top: 8px; 
            font-size: 0.9em; 
            letter-spacing: 1px;
        }
        .section {
            background: rgba(255,255,255,0.03); 
            backdrop-filter: blur(15px);
            border: 1px solid rgba(0,212,255,0.18); 
            border-radius: 20px; 
            padding: 30px; 
            margin-bottom: 30px;
        }
        .section-title { 
            font-size: 1.4em; 
            color: #00d4ff; 
            margin-bottom: 22px; 
            padding-bottom: 12px;
            border-bottom: 2px solid rgba(0,212,255,0.25);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .section-title::before {
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(180deg, #00d4ff, #0d47a1);
            border-radius: 2px;
        }
        .chart-container { width: 100%; height: 380px; }
        .map-container { width: 100%; height: 520px; }
        .honeypot-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px; }
        .hp-item {
            background: rgba(0,212,255,0.06); 
            border: 1px solid rgba(0,212,255,0.18);
            border-radius: 14px; 
            padding: 20px; 
            text-align: center;
            transition: all 0.3s ease;
        }
        .hp-item:hover {
            border-color: rgba(0,212,255,0.4);
            transform: scale(1.03);
        }
        .hp-name { color: #a0a0a0; font-size: 0.8em; margin-bottom: 8px; }
        .hp-count { color: #00d4ff; font-size: 1.8em; font-weight: 700; }
        .hp-zero { color: #555; }
        .top-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 20px; }
        .list-item { 
            background: rgba(0,0,0,0.35); 
            border-radius: 14px; 
            padding: 20px;
            border: 1px solid rgba(0,212,255,0.1);
        }
        .list-item h3 { 
            color: #00d4ff; 
            margin-bottom: 15px; 
            font-size: 1.05em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .rank-item { 
            display: flex; 
            justify-content: space-between; 
            padding: 8px 0; 
            border-bottom: 1px solid rgba(255,255,255,0.06); 
            color: #ccc; 
            font-size: 0.88em;
            transition: background 0.2s ease;
        }
        .rank-item:hover {
            background: rgba(0,212,255,0.05);
            padding-left: 8px;
            border-radius: 4px;
        }
        .rank-value { 
            font-weight: 600; 
            color: #00d4ff;
        }
        .data-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
            font-size: 0.88em; 
            color: #ddd;
        }
        .data-table th { 
            background: rgba(0,212,255,0.15); 
            color: #00d4ff; 
            padding: 12px 15px; 
            text-align: left;
            font-weight: 600;
            border-radius: 8px 8px 0 0;
        }
        .data-table th:first-child { border-radius: 8px 0 0 0; }
        .data-table th:last-child { border-radius: 0 8px 0 0; }
        .data-table td { 
            padding: 10px 15px; 
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .data-table tr:hover { 
            background: rgba(0,212,255,0.06);
        }
        .badge { 
            background: rgba(0,212,255,0.15); 
            color: #00d4ff; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.8em;
            font-weight: 500;
        }
        .footer { 
            text-align: center; 
            color: #666; 
            margin-top: 50px; 
            padding: 20px;
            font-size: 0.9em;
            border-top: 1px solid rgba(255,255,255,0.08);
        }
        .warning { color: #ff6b6b; }
        .highlight {
            background: linear-gradient(135deg, rgba(0,212,255,0.15), rgba(13,71,177,0.15));
            border-left: 3px solid #00d4ff;
            padding: 15px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 15px;
        }
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8em; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .stat-number { font-size: 1.8em; }
            .section { padding: 20px; }
            .chart-container { height: 280px; }
            .map-container { height: 400px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ HFish 威胁情报监控中心</h1>
            <p class="update-time">📊 监控周期: {{ stats.time_range }} | 最后更新: {{ last_update }}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number">{{ stats.total_attacks }}</div><div class="stat-label">总攻击次数</div></div>
            <div class="stat-card"><div class="stat-number">{{ stats.unique_ips }}</div><div class="stat-label">独立攻击IP</div></div>
            <div class="stat-card"><div class="stat-number">{{ services_count }}</div><div class="stat-label">服务类型数</div></div>
            <div class="stat-card"><div class="stat-number">{{ countries_count }}</div><div class="stat-label">涉及国家/地区</div></div>
            <div class="stat-card"><div class="stat-number">{{ account_count }}</div><div class="stat-label">账号资产数据</div></div>
            <div class="stat-card"><div class="stat-number">{{ stats.active_honeypots }}</div><div class="stat-label">活跃蜜罐数</div></div>
        </div>

        <div class="section">
            <h2 class="section-title">📈 攻击趋势分析（近7天）</h2>
            <div class="chart-container"><canvas id="attackChart"></canvas></div>
        </div>

        <div class="section">
            <h2 class="section-title">🗺️ 攻击来源全球分布</h2>
            <div class="map-container" id="worldMap"></div>
        </div>

        <div class="section">
            <h2 class="section-title">🎯 各蜜罐受攻击统计</h2>
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
                <div class="list-item"><h3>🔝 Top 10 攻击源IP</h3>
                    {% for ip, count in stats.top_ips.items() %}
                    <div class="rank-item"><span>{{ ip }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}</div>
                <div class="list-item"><h3>🌍 攻击来源国家</h3>
                    {% for country, count in stats.top_countries.items() %}
                    <div class="rank-item"><span>{{ country }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}</div>
                <div class="list-item"><h3>🔑 弱口令字典 TOP 10</h3>
                    {% for pwd, count in top_passwords %}
                    <div class="rank-item"><span class="warning">{{ pwd }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}
                    {% if not top_passwords %}<div class="rank-item"><span>暂无弱口令数据</span></div>{% endif %}</div>
                <div class="list-item"><h3>👤 高频用户名 TOP 5</h3>
                    {% for user, count in top_usernames %}
                    <div class="rank-item"><span>{{ user }}</span><span class="rank-value">{{ count }}</span></div>{% endfor %}</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📋 最新攻击详情记录</h2>
            <div style="overflow-x:auto; max-height:420px; overflow-y:auto;">
                <table class="data-table"><thead><tr><th>攻击源IP</th><th>地理位置</th><th>服务类型</th><th>端口</th><th>攻击时间</th></tr></thead><tbody>
                    {% for _, row in df.head(100).iterrows() %}
                    <tr><td><span class="badge">{{ row.get('攻击源IP', '-') }}</span></td><td>{{ row.get('地理位置', '-') }}</td><td>{{ row.get('服务类型', '-') }}</td><td>{{ row.get('端口', '-') }}</td><td>{{ row.get('攻击时间', '-') }}</td></tr>{% endfor %}</tbody></table>
            </div>
        </div>

        <div class="footer">
            <p>🤖 HFish 蜜罐系统自动采集 · 每6小时更新 · 毕业设计作品</p>
            <p style="margin-top: 8px; font-size: 0.8em; color: #555;">© 2024 Security Monitoring System</p>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('attackChart').getContext('2d');
        const data = {{ chart_data | safe }};
        new Chart(ctx, {
            type:'line', 
            data:{labels:data.dates, datasets:[{label:'攻击次数',data:data.counts,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.1)',fill:true,tension:0.4,pointBackgroundColor:'#00d4ff',pointBorderColor:'#fff',pointBorderWidth:2,pointRadius:5,pointHoverRadius:8}]}, 
            options:{responsive:true, maintainAspectRatio:false, plugins:{legend:{display:true,labels:{color:'#ccc',font:{size:12}}},tooltip:{backgroundColor:'rgba(0,0,0,0.8)',titleColor:'#00d4ff',bodyColor:'#fff',borderColor:'rgba(0,212,255,0.3)',borderWidth:1}}, scales:{x:{grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},ticks:{color:'#999'}},y:{grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},ticks:{color:'#999'}}}}
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
                          return p.name + ': ' + (p.value || 0) + ' 次攻击'; 
                      }, 
                      backgroundColor: 'rgba(0,0,0,0.85)', 
                      textStyle: { color: '#fff' },
                      borderColor: 'rgba(0,212,255,0.3)',
                      borderWidth: 1
                  },
                  visualMap: { 
                      min: 0, 
                      max: data.maxCount || 100, 
                      text: ['高', '低'], 
                      realtime: false, 
                      calculable: true, 
                      inRange: { color: ['#1a1a3e', '#0d47a1', '#1565c0', '#00d4ff'] }, 
                      textStyle: { color: '#ccc' }, 
                      itemWidth: 15,
                      itemHeight: 100,
                      left: '5%',
                      top: 'center'
                  },
                  series: [{ 
                      type: 'map', 
                      map: 'world', 
                      roam: true, 
                      zoom: 1.2,
                      center: [100, 30],
                      label: {
                          show: false
                      },
                      emphasis: { 
                          label: { 
                              show: true, 
                              color: '#fff', 
                              fontSize: 11,
                              fontWeight: 'bold'
                          }, 
                          itemStyle: { 
                              areaColor: '#00d4ff', 
                              shadowBlur: 20, 
                              shadowColor: 'rgba(0,212,255,0.6)' 
                          } 
                      }, 
                      itemStyle: { 
                          borderColor: 'rgba(255,255,255,0.15)', 
                          areaColor: 'rgba(42, 42, 74, 0.8)', 
                          borderWidth: 1 
                      }, 
                      data: data.countries || [] 
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
                          return p.name + ': 0 次攻击'; 
                      }, 
                      backgroundColor: 'rgba(0,0,0,0.85)', 
                      textStyle: { color: '#fff' },
                      borderColor: 'rgba(0,212,255,0.3)',
                      borderWidth: 1
                  },
                  visualMap: { 
                      min: 0, 
                      max: 100, 
                      text: ['高', '低'], 
                      realtime: false, 
                      calculable: true, 
                      inRange: { color: ['#1a1a3e', '#0d47a1', '#1565c0', '#00d4ff'] }, 
                      textStyle: { color: '#ccc' }, 
                      itemWidth: 15,
                      itemHeight: 100,
                      left: '5%',
                      top: 'center'
                  },
                  series: [{ 
                      type: 'map', 
                      map: 'world', 
                      roam: true, 
                      zoom: 1.2,
                      center: [100, 30],
                      label: {
                          show: false
                      },
                      emphasis: { 
                          label: { 
                              show: true, 
                              color: '#fff', 
                              fontSize: 11,
                              fontWeight: 'bold'
                          }, 
                          itemStyle: { 
                              areaColor: '#00d4ff', 
                              shadowBlur: 20, 
                              shadowColor: 'rgba(0,212,255,0.6)' 
                          } 
                      }, 
                      itemStyle: { 
                          borderColor: 'rgba(255,255,255,0.15)', 
                          areaColor: 'rgba(42, 42, 74, 0.8)', 
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

# ==================== 9. 生成 HTML ====================
def generate_html(df, stats, accounts):
    template = Template(HTML_TEMPLATE)
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
    print(f"✅ HTML 已生成: {output_path}")

# ==================== 10. 主函数 ====================
def main():
    print("🔄 拉取攻击日志...")
    logs = fetch_attack_logs()
    print("🔄 拉取账号资产...")
    accounts = fetch_accounts()
    if logs:
        print(f"📥 攻击: {len(logs)} 条, 账号: {len(accounts)} 条")
        df, stats = process_data(logs)
        print(f"📊 总攻击 {stats['total_attacks']} 次, IP {stats['unique_ips']} 个, 活跃蜜罐 {stats['active_honeypots']} 个")
        generate_map_data(df)
        generate_html(df, stats, accounts)
        print("✨ v5.0 完成！")
    else:
        print("⚠️ 无数据")

if __name__ == "__main__":
    main()
