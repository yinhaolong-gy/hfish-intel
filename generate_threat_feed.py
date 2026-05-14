#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v7.1 (性能优化版)
功能：全蜜罐数据采集 + 弱口令字典 + 攻击趋势图 + 世界地图 +
      攻击时段热力图 + 数据对比 + CSV导出 + 分蜜罐统计
优化：地图快速加载，优先显示柱状图
"""

import requests, pandas as pd, os, json, urllib3
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

# ==================== 数据采集 ====================
def fetch_attack_logs(start_ts, end_ts):
    """从 HFish API 拉取攻击日志"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    try:
        r = requests.post(url, headers={"Content-Type":"application/json"}, 
                         params={"api_key":API_KEY},
                         json={"start_time":int(start_ts.timestamp()),
                               "end_time":int(end_ts.timestamp()),
                               "page":1,"page_size":5000}, 
                         verify=False, timeout=30)
        if r.json().get("response_code") == 0:
            return r.json().get("data", [])
    except Exception as e:
        print(f"API请求失败: {e}")
    return []

def fetch_accounts():
    """从 HFish API 拉取账号资产数据"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    try:
        r = requests.post(url, headers={"Content-Type":"application/json"}, 
                         params={"api_key":API_KEY},
                         json={"page":1,"page_size":5000}, 
                         verify=False, timeout=30)
        if r.json().get("response_code") == 0:
            return r.json().get("data", [])
    except Exception as e:
        print(f"账号API请求失败: {e}")
    return []

# ==================== 数据处理 ====================
def process_data(raw_logs):
    """清洗原始攻击日志，提取关键字段并统计"""
    if not raw_logs:
        return pd.DataFrame(), {}
    
    df = pd.DataFrame(raw_logs)
    keep_cols = ["attack_ip", "ip_location", "service_name", "service_port", "create_time"]
    df = df[[c for c in keep_cols if c in df.columns]].copy()
    
    # 时间处理
    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour
        df["date"] = pd.to_datetime(df["create_time"]).dt.date
    
    # 地理位置提取
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(
            lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x
        )
    
    # 蜜罐类型统计
    all_hp = ["SSH蜜罐", "FTP蜜罐", "Telnet蜜罐", "HTTP代理蜜罐", "MYSQL蜜罐", 
              "REDIS蜜罐", "Elasticsearch蜜罐", "CUSTOM蜜罐", "TCP端口监听", "Nginx蜜罐"]
    hp_counts = df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}
    hp_data = {hp: hp_counts.get(hp, 0) for hp in all_hp}
    
    # 攻击时段热力图数据
    heatmap_data = [0] * 24
    if "hour" in df.columns:
        hour_counts = df["hour"].value_counts().to_dict()
        for h, c in hour_counts.items():
            heatmap_data[int(h)] = c
    
    # 端口统计
    top_ports = df["service_port"].value_counts().head(10).to_dict() if "service_port" in df.columns else {}
    
    return df, {
        "total_attacks": len(df),
        "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
        "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
        "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
        "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
        "top_ports": top_ports,
        "honeypot_data": hp_data,
        "active_honeypots": sum(1 for v in hp_data.values() if v > 0),
        "heatmap_data": heatmap_data,
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }

# ==================== 国家名称映射 ====================
COUNTRY_MAP = {
    "中国": "China", "美国": "United States", "俄罗斯": "Russia", "加拿大": "Canada",
    "新加坡": "Singapore", "日本": "Japan", "韩国": "South Korea", "德国": "Germany",
    "英国": "United Kingdom", "法国": "France", "印度": "India", "巴西": "Brazil",
    "澳大利亚": "Australia", "荷兰": "Netherlands", "越南": "Vietnam",
    "乌克兰": "Ukraine", "波兰": "Poland", "意大利": "Italy", "西班牙": "Spain",
    "瑞典": "Sweden", "瑞士": "Switzerland", "土耳其": "Turkey", "伊朗": "Iran",
    "泰国": "Thailand", "马来西亚": "Malaysia", "印度尼西亚": "Indonesia",
    "巴基斯坦": "Pakistan", "比利时": "Belgium", "保加利亚": "Bulgaria",
    "南非": "South Africa", "肯尼亚": "Kenya", "菲律宾": "Philippines",
    "埃塞俄比亚": "Ethiopia", "葡萄牙": "Portugal", "匈牙利": "Hungary",
    "哈萨克斯坦": "Kazakhstan", "乌兹别克斯坦": "Uzbekistan",
    "阿根廷": "Argentina", "委内瑞拉": "Venezuela", "伊拉克": "Iraq",
    "孟加拉": "Bangladesh", "玻利维亚": "Bolivia", "巴拉圭": "Paraguay",
    "萨尔瓦多": "El Salvador", "尼加拉瓜": "Nicaragua",
    "特立尼达和多巴哥": "Trinidad and Tobago",
    "欧洲地区": "Russia", "亚太地区": "China", "非洲地区": "South Africa"
}

# ==================== 地图数据生成 ====================
def generate_map_data(df):
    """生成世界地图数据，返回JSON字符串（直接内嵌到HTML）"""
    if "country" not in df.columns or df.empty:
        return json.dumps({"countries": [], "maxCount": 1}, ensure_ascii=False)
    
    country_counts = df["country"].value_counts().to_dict()
    countries = []
    max_count = 1
    
    for country, count in country_counts.items():
        en_name = COUNTRY_MAP.get(country)
        if en_name:
            countries.append({"name": en_name, "value": int(count)})
            if count > max_count:
                max_count = int(count)
    
    return json.dumps({"countries": countries, "maxCount": max_count}, ensure_ascii=False)

# ==================== CSV导出 ====================
def export_csv(df):
    """导出攻击数据为CSV文件"""
    if not df.empty:
        export_df = df[["attack_ip", "ip_location", "service_name", "service_port", "create_time"]].head(500).copy()
        export_df.columns = ["攻击源IP", "地理位置", "服务类型", "端口", "攻击时间"]
        export_df.to_csv(os.path.join(OUTPUT_DIR, "threat_data.csv"), index=False, encoding="utf-8-sig")

# ==================== 图表数据生成 ====================
def gen_chart_data(df):
    """生成近7天攻击趋势图数据"""
    if "date" not in df.columns or df.empty:
        return json.dumps({"dates": [], "counts": [], "prev_counts": []})
    
    # 近7天数据
    daily_counts = df.groupby("date")["attack_ip"].count()
    recent_dates = sorted(daily_counts.index)[-14:]  # 获取最近14天用于对比
    
    # 本周数据
    this_week_dates = recent_dates[-7:]
    this_week_counts = [int(daily_counts.get(d, 0)) for d in this_week_dates]
    
    # 上周数据（用于对比）
    last_week_dates = recent_dates[:7] if len(recent_dates) >= 14 else []
    last_week_counts = [int(daily_counts.get(d, 0)) for d in last_week_dates]
    
    date_labels = [d.strftime("%m-%d") for d in this_week_dates]
    
    return json.dumps({
        "dates": date_labels,
        "counts": this_week_counts,
        "prev_counts": last_week_counts
    })

# ==================== 数据对比 ====================
def compare_weeks(current_df, last_week_logs):
    """本周与上周攻击数据对比"""
    current_count = len(current_df)
    last_count = len(last_week_logs)
    change = current_count - last_count
    
    if last_count == 0:
        trend = "无对比数据"
        change_percent = 0
    else:
        change_percent = round((change / last_count) * 100, 1)
        if change > 0:
            trend = "上升"
        elif change < 0:
            trend = "下降"
        else:
            trend = "持平"
    
    return {
        "current": current_count,
        "last": last_count,
        "change": change,
        "change_percent": change_percent,
        "trend": trend
    }

# ==================== HTML页面生成 ====================
def generate_html(df, stats, accounts, week_compare, map_data):
    """生成完整的威胁情报HTML页面"""
    
    chart_data = gen_chart_data(df)
    # 转换热力图数据中的 pandas 类型为 Python 原生类型
    heatmap_list = stats.get("heatmap_data", [0] * 24)
    heatmap_data = json.dumps([int(x) if hasattr(x, 'item') else x for x in heatmap_list])
    
    # 弱口令和用户名统计（对超长内容进行截断）
    def safe_truncate(text, max_len=30):
        """安全截断文本"""
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
    <title>HFish 威胁情报监控中心</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        :root {
            --primary: #00d4ff;
            --secondary: #7c3aed;
            --bg-dark: #0a0a14;
            --bg-card: rgba(255,255,255,0.03);
            --border: rgba(0,212,255,0.12);
            --text: #e2e8f0;
            --text-muted: #94a3b8;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #0a0a14 0%, #0f172a 40%, #1e1b4b 70%, #0a0a14 100%);
            min-height: 100vh;
            padding: 20px;
            color: var(--text);
        }

        .container {
            max-width: 1440px;
            margin: 0 auto;
        }

        /* 头部样式 */
        .header {
            text-align: center;
            padding: 35px 20px;
            margin-bottom: 30px;
            background: linear-gradient(135deg, rgba(0,212,255,0.08), rgba(124,58,237,0.06));
            border-radius: 24px;
            border: 1px solid var(--border);
            box-shadow: 0 8px 32px rgba(0,212,255,0.08);
        }

        .header h1 {
            font-size: clamp(1.6em, 5vw, 2.8em);
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px rgba(0,212,255,0.3);
            margin-bottom: 10px;
        }

        .header .subtitle {
            color: var(--text-muted);
            font-size: 0.9em;
            letter-spacing: 1px;
        }

        /* 统计卡片 */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 18px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 22px 15px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }

        .stat-card:hover::before {
            transform: scaleX(1);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
            box-shadow: 0 12px 40px rgba(0,212,255,0.15);
        }

        .stat-number {
            font-size: clamp(1.8em, 4vw, 2.5em);
            font-weight: 700;
            color: var(--primary);
            text-shadow: 0 0 20px rgba(0,212,255,0.4);
            margin-bottom: 6px;
        }

        .stat-number.up { color: #4ade80; text-shadow: 0 0 20px rgba(74,222,128,0.4); }
        .stat-number.down { color: #f87171; text-shadow: 0 0 20px rgba(248,113,113,0.4); }
        .stat-label { color: var(--text-muted); font-size: 0.85em; letter-spacing: 0.5px; }

        /* 区块样式 */
        .section {
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 28px;
            margin-bottom: 25px;
            transition: all 0.3s ease;
        }

        .section:hover {
            border-color: rgba(0,212,255,0.25);
            box-shadow: 0 8px 30px rgba(0,212,255,0.1);
        }

        .section-title {
            font-size: 1.35em;
            color: var(--primary);
            margin-bottom: 22px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 12px;
            text-shadow: 0 0 15px rgba(0,212,255,0.3);
        }

        /* 图表容器 */
        .chart-container {
            width: 100%;
            height: 400px;
            position: relative;
        }

        .map-container {
            width: 100%;
            height: 550px;
            border-radius: 16px;
            background: rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .heatmap-container {
            width: 100%;
            height: 320px;
        }

        /* 蜜罐网格 */
        .honeypot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
        }

        .hp-item {
            background: linear-gradient(135deg, rgba(0,212,255,0.06), rgba(124,58,237,0.04));
            border: 1px solid rgba(0,212,255,0.12);
            border-radius: 16px;
            padding: 20px 12px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .hp-item::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0,212,255,0.1) 0%, transparent 70%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .hp-item:hover::after {
            opacity: 1;
        }

        .hp-item:hover {
            transform: translateY(-4px);
            border-color: var(--primary);
            box-shadow: 0 10px 30px rgba(0,212,255,0.15);
        }

        .hp-name {
            color: var(--text-muted);
            font-size: 0.78em;
            margin-bottom: 10px;
            word-break: break-all;
        }

        .hp-count {
            font-size: 2em;
            font-weight: 700;
            color: var(--primary);
            text-shadow: 0 0 15px rgba(0,212,255,0.4);
        }

        .hp-zero { color: #475569; }

        /* 列表项 */
        .top-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
        }

        .list-item {
            background: rgba(0,0,0,0.35);
            border: 1px solid rgba(0,212,255,0.08);
            border-radius: 16px;
            padding: 18px;
            transition: all 0.3s ease;
            overflow: hidden;
        }

        .list-item:hover {
            border-color: rgba(0,212,255,0.2);
            box-shadow: 0 8px 25px rgba(0,212,255,0.1);
        }

        .list-item h3 {
            color: var(--primary);
            margin-bottom: 15px;
            font-size: 1.05em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .rank-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.88em;
            transition: all 0.2s ease;
            word-break: break-all;
            gap: 10px;
        }

        .rank-item:hover {
            background: rgba(0,212,255,0.05);
            border-radius: 8px;
        }

        .rank-item span:first-child {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            min-width: 0;
        }

        .rank-value {
            font-weight: 700;
            color: var(--primary);
            font-size: 1.1em;
            flex-shrink: 0;
            white-space: nowrap;
        }

        .warning {
            color: #f87171;
            font-family: monospace;
            word-break: break-all;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* 表格 */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.85em;
        }

        .data-table th {
            background: rgba(0,212,255,0.12);
            color: var(--primary);
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
        }

        .data-table td {
            padding: 11px 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            color: var(--text);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .data-table tr:hover td {
            background: rgba(0,212,255,0.04);
        }

        /* 徽章 */
        .badge {
            background: rgba(0,212,255,0.15);
            color: var(--primary);
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 0.8em;
            border: 1px solid rgba(0,212,255,0.2);
            transition: all 0.2s ease;
        }

        .badge:hover {
            background: rgba(0,212,255,0.25);
            box-shadow: 0 0 15px rgba(0,212,255,0.3);
        }

        /* 对比区块 */
        .compare-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
        }

        .compare-card {
            background: linear-gradient(135deg, rgba(0,212,255,0.08), rgba(124,58,237,0.06));
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .compare-card:hover {
            transform: translateY(-3px);
            border-color: var(--primary);
        }

        .compare-value {
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 8px;
            text-shadow: 0 0 20px rgba(0,212,255,0.3);
        }

        .compare-label {
            color: var(--text-muted);
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .compare-change {
            font-size: 1.1em;
            font-weight: 600;
        }

        .compare-change.up { color: #f87171; }
        .compare-change.down { color: #4ade80; }

        .trend-icon {
            font-size: 1.5em;
            margin-bottom: 10px;
        }

        /* 页脚 */
        .footer {
            text-align: center;
            color: #64748b;
            margin-top: 40px;
            font-size: 0.85em;
            padding: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }

        /* 响应式 */
        @media (max-width: 768px) {
            body { padding: 10px; }
            .stats-grid { grid-template-columns: repeat(3, 1fr); gap: 12px; }
            .stat-card { padding: 15px 8px; }
            .stat-number { font-size: 1.5em; }
            .chart-container { height: 300px; }
            .map-container { height: 400px; }
            .heatmap-container { height: 250px; }
            .top-list { grid-template-columns: 1fr; }
        }

        @media (max-width: 480px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .header h1 { font-size: 1.4em; }
            .section { padding: 15px; }
        }
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
                <div class="stat-number">{{ week_compare.current }}</div>
                <div class="stat-label">本周攻击</div>
            </div>
            <div class="stat-card">
                <div class="stat-number {{ 'up' if week_compare.trend == '上升' else 'down' if week_compare.trend == '下降' else '' }}">
                    {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
                </div>
                <div class="stat-label">较上周{{ week_compare.trend }}</div>
            </div>
        </div>

        <!-- 攻击趋势图 -->
        <div class="section">
            <h2 class="section-title">📈 攻击趋势分析（近7天）</h2>
            <div class="chart-container">
                <canvas id="attackTrendChart"></canvas>
            </div>
        </div>

        <!-- 攻击时段分布 -->
        <div class="section">
            <h2 class="section-title">🔥 攻击时段热力图（24小时）</h2>
            <div class="heatmap-container">
                <canvas id="heatmapChart"></canvas>
            </div>
        </div>

        <!-- 周对比分析 -->
        <div class="section">
            <h2 class="section-title">📊 本周 vs 上周攻击对比</h2>
            <div class="compare-section">
                <div class="compare-card">
                    <div class="trend-icon">📊</div>
                    <div class="compare-value" style="color: var(--primary);">{{ week_compare.current }}</div>
                    <div class="compare-label">本周攻击次数</div>
                </div>
                <div class="compare-card">
                    <div class="trend-icon">📉</div>
                    <div class="compare-value" style="color: var(--text-muted);">{{ week_compare.last }}</div>
                    <div class="compare-label">上周攻击次数</div>
                </div>
                <div class="compare-card">
                    <div class="trend-icon">{{ '📈' if week_compare.trend == '上升' else '📉' if week_compare.trend == '下降' else '➡️' }}</div>
                    <div class="compare-value {{ 'up' if week_compare.trend == '上升' else 'down' if week_compare.trend == '下降' else '' }}">
                        {{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}
                    </div>
                    <div class="compare-label">数量变化</div>
                    {% if week_compare.last > 0 %}
                    <div class="compare-change {{ 'up' if week_compare.trend == '上升' else 'down' if week_compare.trend == '下降' else '' }}">
                        {{ week_compare.change_percent }}{% if week_compare.change_percent > 0 %}+{% endif %}%
                    </div>
                    {% endif %}
                </div>
            </div>
            <!-- 周对比图表 -->
            <div class="chart-container" style="height: 300px; margin-top: 20px;">
                <canvas id="weekCompareChart"></canvas>
            </div>
        </div>

        <!-- 攻击来源分布 -->
        <div class="section">
            <h2 class="section-title">🗺️ 攻击来源分布</h2>
            <div class="map-container" id="worldMap"></div>
        </div>

        <!-- 蜜罐统计 -->
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
            <h2 class="section-title">📊 攻击统计详情</h2>
            <div class="top-list">
                <div class="list-item">
                    <h3>🔝 Top 10 攻击源IP</h3>
                    {% for ip, count in stats.top_ips.items() %}
                    <div class="rank-item"><span title="{{ ip }}">{{ ip }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>🌍 攻击来源国家</h3>
                    {% for country, count in stats.top_countries.items() %}
                    <div class="rank-item"><span>{{ country }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>🔑 弱口令 TOP 10</h3>
                    {% for pwd, count in top_passwords %}
                    <div class="rank-item"><span class="warning">{{ pwd }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>👤 高频用户名 TOP 5</h3>
                    {% for user, count in top_usernames %}
                    <div class="rank-item"><span>{{ user }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
                <div class="list-item">
                    <h3>🔌 热门攻击端口</h3>
                    {% for port, count in stats.top_ports.items() %}
                    <div class="rank-item"><span>端口 {{ port }}</span><span class="rank-value">{{ count }}次</span></div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- 攻击记录表格 -->
        <div class="section">
            <h2 class="section-title">📋 最新攻击详情记录（前100条）</h2>
            <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr><th>攻击源IP</th><th>地理位置</th><th>服务类型</th><th>端口</th><th>攻击时间</th></tr>
                    </thead>
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

        <!-- 页脚 -->
        <div class="footer">
            <p>🤖 HFish 蜜罐系统自动采集 | 每6小时更新 | 毕业设计作品 | {{ last_update }}</p>
        </div>
    </div>

    <script>
        // --- 1. 攻击趋势图（双折线对比）---
        const trendCtx = document.getElementById('attackTrendChart').getContext('2d');
        const trendData = {{ chart_data | safe }};
        
        const gradient = trendCtx.createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, 'rgba(0, 212, 255, 0.3)');
        gradient.addColorStop(1, 'rgba(0, 212, 255, 0)');
        
        const prevGradient = trendCtx.createLinearGradient(0, 0, 0, 400);
        prevGradient.addColorStop(0, 'rgba(124, 58, 237, 0.2)');
        prevGradient.addColorStop(1, 'rgba(124, 58, 237, 0)');

        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: trendData.dates || [],
                datasets: [
                    {
                        label: '本周攻击',
                        data: trendData.counts || [],
                        borderColor: '#00d4ff',
                        backgroundColor: gradient,
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: '#00d4ff',
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 6,
                        pointHoverRadius: 9,
                        pointHoverBackgroundColor: '#00d4ff',
                        pointHoverBorderColor: '#fff',
                        pointHoverBorderWidth: 3
                    },
                    {
                        label: '上周攻击',
                        data: trendData.prev_counts || [],
                        borderColor: '#7c3aed',
                        backgroundColor: prevGradient,
                        fill: true,
                        tension: 0.4,
                        borderDash: [5, 5],
                        pointBackgroundColor: '#7c3aed',
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 5,
                        pointHoverRadius: 8
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#94a3b8',
                            font: { size: 13 },
                            padding: 20,
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(0, 212, 255, 0.3)',
                        borderWidth: 1,
                        padding: 12,
                        displayColors: true,
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.raw + ' 次攻击';
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { size: 12 } },
                        grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { size: 12 } },
                        grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false },
                        beginAtZero: true,
                        suggestedMin: 0
                    }
                },
                animation: {
                    duration: 1500,
                    easing: 'easeOutQuart'
                }
            }
        });

        // --- 2. 攻击时段热力图 ---
        const heatCtx = document.getElementById('heatmapChart').getContext('2d');
        const heatData = {{ heatmap_data | safe }};
        
        const barColors = heatData.map(val => {
            if (val > 200) return '#7c3aed';
            if (val > 100) return '#00d4ff';
            if (val > 50) return '#0284c7';
            if (val > 20) return '#0d47a1';
            return '#1e293b';
        });

        new Chart(heatCtx, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => i + ':00'),
                datasets: [{
                    label: '攻击次数',
                    data: heatData,
                    backgroundColor: barColors,
                    borderColor: barColors.map(c => c),
                    borderWidth: 1,
                    borderRadius: 8,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(0, 212, 255, 0.3)',
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: function(context) {
                                return '攻击次数: ' + context.raw + ' 次';
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { 
                            color: '#94a3b8', 
                            font: { size: 11 },
                            maxRotation: 45,
                            minRotation: 45
                        },
                        grid: { display: false }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { size: 12 } },
                        grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false },
                        beginAtZero: true
                    }
                },
                animation: {
                    duration: 1200,
                    easing: 'easeOutQuart'
                }
            }
        });

        // --- 3. 周对比柱状图 ---
        const compareCtx = document.getElementById('weekCompareChart').getContext('2d');
        const compareData = {
            labels: ['本周', '上周'],
            datasets: [{
                label: '攻击次数',
                data: [{{ week_compare.current }}, {{ week_compare.last }}],
                backgroundColor: ['#00d4ff', '#7c3aed'],
                borderColor: ['#00d4ff', '#7c3aed'],
                borderWidth: 2,
                borderRadius: 12,
                barThickness: 60
            }]
        };

        new Chart(compareCtx, {
            type: 'bar',
            data: compareData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(0, 212, 255, 0.3)',
                        borderWidth: 1,
                        padding: 12
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { size: 14, weight: '600' } },
                        grid: { display: false }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { size: 12 } },
                        grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false },
                        beginAtZero: true
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart'
                }
            }
        });

        // --- 4. 攻击来源分布（优先显示柱状图，地图后台加载）---
        const mapDom = document.getElementById('worldMap');
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

        // 直接使用内嵌数据
        const mapData = {{ map_data | safe }};
        
        // 快速显示柱状图（优先加载）
        function showBarChart() {
            const sortedCountries = [...mapData.countries].sort((a, b) => b.value - a.value).slice(0, 15);
            mapDom.innerHTML = '<canvas id="countryBarChart" style="width: 100%; height: 100%;"></canvas>';
            const barCtx = document.getElementById('countryBarChart').getContext('2d');
            
            new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: sortedCountries.map(c => countryNameMap[c.name] || c.name),
                    datasets: [{
                        label: '攻击次数',
                        data: sortedCountries.map(c => c.value),
                        backgroundColor: 'rgba(0, 212, 255, 0.7)',
                        borderColor: '#00d4ff',
                        borderWidth: 1,
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: { display: false },
                        title: {
                            display: true,
                            text: '攻击来源 TOP 15 国家/地区',
                            color: '#94a3b8',
                            font: { size: 14 }
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#94a3b8' },
                            grid: { color: 'rgba(255, 255, 255, 0.05)' }
                        },
                        y: {
                            ticks: { color: '#94a3b8' },
                            grid: { display: false }
                        }
                    }
                }
            });
        }
        
        // 先快速显示柱状图
        if (mapData.countries.length > 0) {
            showBarChart();
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
        last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ HTML 报告已生成: {OUTPUT_DIR}/index.html")

# ==================== 主函数 ====================
def main():
    print("🔄 正在拉取攻击日志（近90天）...")
    logs = fetch_attack_logs(START_TIME, END_TIME)
    
    print("🔄 正在拉取上周攻击日志...")
    last_week_logs = fetch_attack_logs(LAST_WEEK_START, LAST_WEEK_END)
    
    print("🔄 正在拉取账号资产数据...")
    accounts = fetch_accounts()
    
    if logs:
        print(f"📥 攻击数据: {len(logs)} 条 | 账号数据: {len(accounts)} 条 | 上周数据: {len(last_week_logs)} 条")
        
        df, stats = process_data(logs)
        week_compare = compare_weeks(df, last_week_logs)
        map_data = generate_map_data(df)
        
        export_csv(df)
        generate_html(df, stats, accounts, week_compare, map_data)
        
        print("✨ v7.1 (性能优化版) 所有任务完成！")
    else:
        print("⚠️ 未拉取到攻击数据")

if __name__ == "__main__":
    main()
