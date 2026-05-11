#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v9.0 (互动增强版)
功能：全蜜罐数据采集 + 弱口令字典 + 攻击趋势图 + 攻击时段热力图 +
      数据对比 + CSV导出 + 分蜜罐统计 + Tab交互 + 搜索排序导出 +
      威胁等级 + 扫描检测 + IP段聚合 + 异常检测 + 日历热力图 + 主题切换
"""

import os, json, requests, pandas as pd, urllib3
from datetime import datetime, timedelta
from jinja2 import Template
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HFISH_BASE_URL = "https://127.0.0.1:4433"
API_KEY = "SiFtBHLWzBmcRjndOoQEwPAjvBSBefxSDfvxMoxXwjetfnELGjXIbTZvhFZceacI"
OUTPUT_DIR = "./docs"
LOOKBACK_DAYS = 90
PAGE_SIZE = 5000

# ==================== 数据采集 ====================
def _fetch_paginated(url, body_base, page_size=PAGE_SIZE, max_pages=20):
    all_data = []; seen = set()
    for page in range(1, max_pages + 1):
        body = dict(body_base)
        body["page"] = page; body["page_size"] = page_size
        try:
            r = requests.post(url, headers={"Content-Type": "application/json"},
                              params={"api_key": API_KEY}, json=body, verify=False, timeout=30)
            resp = r.json()
            if resp.get("response_code") != 0:
                print(f"  ⚠ API返回非0状态码(第{page}页): {resp.get('response_code')}"); break
            data = resp.get("data", [])
            if not data: break
            new_batch = 0
            for item in data:
                key = item.get("id", item.get("attack_ip", "")) + str(item.get("create_time", ""))
                if key not in seen: seen.add(key); all_data.append(item); new_batch += 1
            print(f"  📄 第{page}页: {len(data)}条 | 新增(去重后): {new_batch}条 | 累计: {len(all_data)}条")
            if len(data) < page_size: break
        except Exception as e: print(f"  ❌ API请求失败(第{page}页): {e}"); break
    return all_data

def fetch_attack_logs(start_ts, end_ts):
    return _fetch_paginated(f"{HFISH_BASE_URL}/api/v1/attack/detail",
                            {"start_time": int(start_ts.timestamp()), "end_time": int(end_ts.timestamp())})

def fetch_accounts():
    return _fetch_paginated(f"{HFISH_BASE_URL}/api/v1/attack/account", {})

# ==================== 数据处理 ====================
def process_data(raw_logs):
    if not raw_logs: return pd.DataFrame(), {}
    df = pd.DataFrame(raw_logs)
    keep_cols = ["attack_ip", "ip_location", "service_name", "service_port", "create_time"]
    df = df[[c for c in keep_cols if c in df.columns]].copy()
    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour
        df["date"] = pd.to_datetime(df["create_time"]).dt.date
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(
            lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x)
    hp_counts = df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}
    heatmap_data = [0] * 24
    if "hour" in df.columns:
        for h, c in df["hour"].value_counts().to_dict().items(): heatmap_data[int(h)] = c
    top_ports = df["service_port"].value_counts().head(10).to_dict() if "service_port" in df.columns else {}
    ip_counts = df["attack_ip"].value_counts() if "attack_ip" in df.columns else pd.Series(dtype=int)
    top_ips_full = [{"ip": ip, "count": int(c)} for ip, c in ip_counts.head(50).items()]
    service_pie = sorted(
        [{"name": n, "value": int(c)} for n, c in df["service_name"].value_counts().head(10).items()],
        key=lambda x: x["value"], reverse=True) if "service_name" in df.columns else []
    daily_counts_list = []
    if "date" in df.columns:
        for d, c in df.groupby("date")["attack_ip"].count().items():
            daily_counts_list.append({"date": str(d), "count": int(c)})
    return df, {"total_attacks": len(df), "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
                 "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
                 "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
                 "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
                 "top_ports": top_ports, "honeypot_data": hp_counts, "active_honeypots": len(hp_counts),
                 "heatmap_data": heatmap_data, "service_pie": service_pie,
                 "top_ips_full": top_ips_full, "daily_counts_list": daily_counts_list}

# ==================== 深度分析函数 ====================
def compute_ip_threats(df, top_n=50):
    if "attack_ip" not in df.columns or df.empty: return []
    ip_counts = df["attack_ip"].value_counts()
    if ip_counts.empty: return []
    high_th, med_th = ip_counts.quantile(0.9), ip_counts.quantile(0.7)
    return [{"ip": ip, "count": int(c),
             "level": "high" if c >= high_th else "medium" if c >= med_th else "low"}
            for ip, c in ip_counts.head(top_n).items()]

def detect_scanners(df):
    if "attack_ip" not in df.columns or "service_name" not in df.columns or df.empty: return []
    ip_services = df.groupby("attack_ip")["service_name"].apply(set).reset_index()
    scanners = ip_services[ip_services["service_name"].apply(len) >= 3].sort_values(
        "service_name", key=lambda x: x.apply(len), ascending=False).head(20)
    return [{"ip": row["attack_ip"], "services": len(row["service_name"]),
             "service_list": list(row["service_name"])[:5]} for _, row in scanners.iterrows()]

def aggregate_subnets(df, top_n=10):
    if "attack_ip" not in df.columns or df.empty: return []
    df2 = df.copy()
    df2["subnet"] = df2["attack_ip"].apply(
        lambda x: ".".join(x.split(".")[:3]) + ".0/24" if isinstance(x, str) and x.count(".") == 3 else x)
    return [{"subnet": s, "count": int(c)} for s, c in df2["subnet"].value_counts().head(top_n).items()]

def detect_anomaly_days(df):
    if "date" not in df.columns or df.empty: return []
    daily = df.groupby("date")["attack_ip"].count()
    if len(daily) < 3: return []
    threshold = daily.mean() + 2 * daily.std()
    return [{"date": str(d), "count": int(c)} for d, c in daily[daily > threshold].items()]

def gen_weekday_pattern(df):
    if "create_time" not in df.columns or df.empty: return []
    df2 = df.copy()
    df2["weekday"] = pd.to_datetime(df2["create_time"], format="%Y-%m-%d %H:%M").dt.weekday
    wd = df2["weekday"].value_counts().to_dict()
    names = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
    return [{"day": names[i], "count": int(wd.get(i, 0))} for i in range(7)]

# ==================== 图表与对比数据 ====================
def gen_chart_data(df):
    if "date" not in df.columns or df.empty:
        return {"dates": [], "counts": [], "prev_counts": [], "this_week_total": 0,
                "prev_week_total": 0, "change": 0, "change_percent": 0, "trend": "无数据"}
    daily = df.groupby("date")["attack_ip"].count()
    if daily.empty:
        return {"dates": [], "counts": [], "prev_counts": [], "this_week_total": 0,
                "prev_week_total": 0, "change": 0, "change_percent": 0, "trend": "无数据"}
    recent = sorted(daily.index)[-14:]; n = len(recent)
    print(f"📊 gen_chart_data: 总日期数={len(daily)}, 取最近{n}天, 总攻击数={len(df)}")
    if n >= 7:
        tw, lw = recent[-7:], recent[-min(n,14):-7]
    elif n >= 2:
        s = n // 2; tw, lw = recent[-s:], recent[:s]
    else:
        tw, lw = recent, []
    tc = [int(daily.get(d,0)) for d in tw]; lc = [int(daily.get(d,0)) for d in lw]
    mx = max(len(tc), len(lc), 1)
    while len(tc) < mx: tc.append(0)
    while len(lc) < mx: lc.append(0)
    tt, pt = sum(tc), sum(lc); ch = tt - pt
    if pt == 0:
        tr, cp = "无对比数据" if tt == 0 else "新增", 0
    else:
        cp = round((ch / pt) * 100, 1); tr = "上升" if ch > 0 else "下降" if ch < 0 else "持平"
    print(f"  近7天={tt}/前7天={pt}/趋势={tr}")
    return {"dates": [d.strftime("%m-%d") for d in tw], "counts": tc, "prev_counts": lc,
            "this_week_total": tt, "prev_week_total": pt, "change": ch, "change_percent": cp, "trend": tr}

# ==================== 地图数据生成 ====================
def generate_map_data(df):
    if "country" not in df.columns or df.empty:
        return json.dumps({"countries": [], "maxCount": 1}, ensure_ascii=False)
    cc = df["country"].value_counts().to_dict()
    cs = [{"name": n, "value": int(v)} for n, v in cc.items()]
    mx = max(c["value"] for c in cs) if cs else 1
    return json.dumps({"countries": cs, "maxCount": mx}, ensure_ascii=False)

# ==================== CSV导出 ====================
def export_csv(df):
    if df.empty: return
    ed = df[["attack_ip", "ip_location", "service_name", "service_port", "create_time"]].copy()
    ed.columns = ["攻击源IP", "地理位置", "服务类型", "端口", "攻击时间"]
    ed.to_csv(os.path.join(OUTPUT_DIR, "threat_data.csv"), index=False, encoding="utf-8-sig")

# ==================== HTML页面生成 ====================
def generate_html(df, stats, accounts, map_data, time_range):
    chart_data = gen_chart_data(df)
    wc = {"current": chart_data["this_week_total"], "last": chart_data["prev_week_total"],
          "change": chart_data["change"], "change_percent": chart_data["change_percent"],
          "trend": chart_data["trend"]}
    hl = [int(x) if hasattr(x,'item') else x for x in stats.get("heatmap_data",[0]*24)]

    def safe_truncate(t, ml=30):
        if not isinstance(t, str): t = str(t)
        return t[:ml] + "..." if len(t) > ml else t

    tp = [(safe_truncate(p,40),c) for p,c in Counter(a.get("password","") for a in accounts if a.get("password")).most_common(10)]
    tu = [(safe_truncate(u,30),c) for u,c in Counter(a.get("username","") for a in accounts if a.get("username")).most_common(5)]

    ti = compute_ip_threats(df); sc = detect_scanners(df); sb = aggregate_subnets(df)
    ad = detect_anomaly_days(df); wp = gen_weekday_pattern(df)

    cols = ["attack_ip","ip_location","service_name","service_port","create_time"]
    all_rows = [{c: str(r[c]) if c in r else "" for c in cols} for _, r in df[cols].iterrows()]

    page_data = json.dumps({
        "chart": chart_data, "heatmap": hl, "wc": wc,
        "pie": stats.get("service_pie",[]),
        "threats": ti, "scanners": sc, "subnets": sb,
        "anomaly": ad, "weekday": wp,
        "daily": stats.get("daily_counts_list",[]),
        "ips": stats.get("top_ips_full",[]),
        "rows": all_rows,
        "hp": [{"n":n,"c":int(c)} for n,c in stats.get("honeypot_data",{}).items()],
        "passwords": [{"p":p,"c":c} for p,c in tp],
        "usernames": [{"u":u,"c":c} for u,c in tu],
        "map": json.loads(map_data) if isinstance(map_data, str) else map_data,
        "total": len(df),
    }, ensure_ascii=False)

    total_records = len(df)
    summary_parts = []
    if wc["trend"] != "无对比数据":
        d = "上升" if wc["change"] > 0 else "下降"
        summary_parts.append(f"近7天攻击{wc['change_percent']}%{d}")
    if ad: summary_parts.append(f"检测到{len(ad)}个异常攻击日")
    if sc: summary_parts.append(f"发现{len(sc)}个扫描行为IP")
    if ti: summary_parts.append(f"高危IP{sum(1 for t in ti if t['level']=='high')}个")
    summary_text = "，".join(summary_parts) + "。" if summary_parts else "数据采集中。"

    template = Template(r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HFish 威胁情报监控中心</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--p:#00d4ff;--s:#7c3aed;--bg:#0a0a14;--card:rgba(255,255,255,0.03);--brd:rgba(0,212,255,0.12);--txt:#e2e8f0;--mt:#94a3b8}
[data-theme="light"]{--bg:#f1f5f9;--card:rgba(0,0,0,0.02);--brd:rgba(0,0,0,0.12);--txt:#1e293b;--mt:#64748b}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(135deg,var(--bg));
 min-height:100vh;padding:20px;color:var(--txt);transition:background .3s,color .3s}
.container{max-width:1440px;margin:0 auto}
.header{text-align:center;padding:25px 20px;margin-bottom:20px;background:var(--card);border-radius:20px;border:1px solid var(--brd)}
.header h1{font-size:clamp(1.4em,4vw,2.4em);background:linear-gradient(135deg,var(--p),var(--s));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.header .subtitle{color:var(--mt);font-size:.85em}

/* Ticker */
.ticker{background:rgba(255,255,255,0.02);border:1px solid var(--brd);border-radius:12px;padding:10px 18px;margin-bottom:20px;
 overflow:hidden;white-space:nowrap;position:relative;height:42px;line-height:22px}
.ticker-content{display:inline-block;animation:scroll 30s linear infinite;color:var(--mt);font-size:.9em}
.ticker-content span{margin-right:40px}
.ticker-content .ip{color:var(--p)}
@keyframes scroll{0%{transform:translateX(100%)}100%{transform:translateX(-100%)}}

/* Tabs */
.tab-nav{display:flex;gap:4px;margin-bottom:25px;background:var(--card);border-radius:16px;padding:4px;border:1px solid var(--brd);flex-wrap:wrap}
.tab-btn{flex:1;padding:12px 8px;border:none;background:transparent;color:var(--mt);font-size:.95em;cursor:pointer;border-radius:12px;
 transition:all .3s;font-weight:500;min-width:60px;text-align:center}
.tab-btn:hover{color:var(--p);background:rgba(0,212,255,0.08)}
.tab-btn.active{background:linear-gradient(135deg,rgba(0,212,255,0.2),rgba(124,58,237,0.15));color:var(--p);font-weight:600}
.tab-content{display:none}
.tab-content.active{display:block;animation:fadeIn .3s}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:22px}
.stat-card{background:var(--card);border:1px solid var(--brd);border-radius:16px;padding:18px 12px;text-align:center;
 overflow:hidden;transition:all .3s;position:relative}
.stat-card:hover{transform:translateY(-3px);border-color:var(--p);box-shadow:0 8px 30px rgba(0,212,255,0.12)}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--p),var(--s));transform:scaleX(0);transition:transform .3s}
.stat-card:hover::before{transform:scaleX(1)}
.stat-num{font-size:clamp(1.6em,3.5vw,2.2em);font-weight:700;color:var(--p);text-shadow:0 0 15px rgba(0,212,255,0.3);margin-bottom:4px}
.stat-num.up{color:#4ade80;text-shadow:0 0 15px rgba(74,222,128,0.3)}
.stat-num.down{color:#f87171;text-shadow:0 0 15px rgba(248,113,113,0.3)}
.stat-lbl{color:var(--mt);font-size:.8em}

/* Sections */
.section{background:var(--card);border:1px solid var(--brd);border-radius:18px;padding:24px;margin-bottom:22px;transition:border-color .3s}
.section:hover{border-color:rgba(0,212,255,0.2)}
.sec-title{font-size:1.2em;color:var(--p);margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--brd);display:flex;align-items:center;gap:10px}
.chart-box{width:100%;height:350px;position:relative}
.chart-box.tall{height:450px}
.chart-box.short{height:280px}

/* Split layout */
.split{display:grid;grid-template-columns:1fr 1fr;gap:22px}
@media(max-width:900px){.split{grid-template-columns:1fr}}

/* Honeypot grid */
.hp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px}
.hp-item{background:rgba(0,0,0,0.3);border:1px solid rgba(0,212,255,0.08);border-radius:14px;padding:16px 10px;text-align:center;transition:all .3s}
.hp-item:hover{transform:translateY(-2px);border-color:var(--p)}
.hp-name{color:var(--mt);font-size:.75em;margin-bottom:6px;word-break:break-all}
.hp-cnt{font-size:1.8em;font-weight:700;color:var(--p)}

/* Rank lists */
.top-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px}
.list-box{background:rgba(0,0,0,0.3);border:1px solid rgba(0,212,255,0.08);border-radius:14px;padding:16px;overflow:hidden}
.list-box h3{color:var(--p);font-size:1em;margin-bottom:12px;display:flex;align-items:center;gap:6px}
.rank-item{display:flex;justify-content:space-between;align-items:center;padding:8px 6px;border-bottom:1px solid rgba(255,255,255,0.04);font-size:.85em;gap:8px}
.rank-item:hover{background:rgba(0,212,255,0.05);border-radius:6px}
.rank-item span:first-child{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rank-val{font-weight:700;color:var(--p);font-size:1em;flex-shrink:0;white-space:nowrap}
.warning{color:#f87171;font-family:monospace;word-break:break-all}

/* Threat badges */
.badge-h{display:inline-block;background:rgba(248,113,113,0.2);color:#f87171;padding:2px 10px;border-radius:10px;font-size:.75em;font-weight:600}
.badge-m{background:rgba(251,191,36,0.2);color:#fbbf24}
.badge-l{background:rgba(74,222,128,0.2);color:#4ade80}

/* Theme toggle */
.theme-btn{position:fixed;top:20px;right:20px;z-index:999;background:var(--card);border:1px solid var(--brd);border-radius:50%;
 width:42px;height:42px;cursor:pointer;font-size:1.2em;display:flex;align-items:center;justify-content:center;color:var(--txt);transition:all .3s}
.theme-btn:hover{transform:scale(1.1);border-color:var(--p)}

/* Table */
.data-table{width:100%;border-collapse:collapse;font-size:.82em}
.data-table th{background:rgba(0,212,255,0.1);color:var(--p);padding:10px 12px;text-align:left;font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
.data-table th:hover{background:rgba(0,212,255,0.18)}
.data-table td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,0.04);color:var(--txt);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.data-table tr:hover td{background:rgba(0,212,255,0.04)}

/* Search bar */
.toolbar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-input{flex:1;min-width:180px;padding:10px 16px;border-radius:10px;border:1px solid var(--brd);background:rgba(0,0,0,0.3);
 color:var(--txt);font-size:.9em;outline:none;transition:border-color .3s}
.search-input:focus{border-color:var(--p)}
.search-input::placeholder{color:var(--mt)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 18px;border-radius:10px;border:1px solid var(--brd);background:var(--card);
 color:var(--txt);cursor:pointer;font-size:.85em;transition:all .3s;white-space:nowrap}
.btn:hover{border-color:var(--p);color:var(--p);background:rgba(0,212,255,0.08)}
.btn-p{background:linear-gradient(135deg,rgba(0,212,255,0.2),rgba(124,58,237,0.15));color:var(--p);border-color:var(--p)}
.topn-select{padding:8px 12px;border-radius:8px;border:1px solid var(--brd);background:rgba(0,0,0,0.3);color:var(--txt);font-size:.85em;outline:none}

/* Calendar heatmap */
.cal-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(14px,1fr));gap:3px;max-height:130px;overflow-y:auto}
.cal-day{width:100%;aspect-ratio:1;border-radius:3px;position:relative;cursor:pointer}
.cal-day:hover::after{content:attr(data-tip);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);
 background:rgba(0,0,0,0.9);color:#fff;padding:4px 8px;border-radius:6px;font-size:.7em;white-space:nowrap;z-index:10}

/* Anomaly day marker */
.anomaly-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#f87171;margin-right:4px;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

/* Footer */
.footer{text-align:center;color:#64748b;margin-top:40px;font-size:.82em;padding:20px;border-top:1px solid rgba(255,255,255,0.05)}

@media(max-width:768px){body{padding:10px}.stats-grid{grid-template-columns:repeat(3,1fr);gap:10px}
 .stat-card{padding:12px 8px}.stat-num{font-size:1.3em}.chart-box{height:280px}.chart-box.tall{height:320px}
 .top-list{grid-template-columns:1fr}.tab-btn{padding:10px 6px;font-size:.85em}}
@media(max-width:480px){.stats-grid{grid-template-columns:repeat(2,1fr)}.header h1{font-size:1.2em}.section{padding:14px}}
</style>
</head>
<body>
<div class="container">
<button class="theme-btn" onclick="toggleTheme()" id="themeBtn" title="切换主题">🌙</button>

<div class="header">
<h1>🛡️ HFish 威胁情报监控中心</h1>
<p class="subtitle">📊 监控周期: {{ time_range }} | 最后更新: {{ last_update }}</p>
</div>

<div class="ticker"><div class="ticker-content">{% for _, r in df.head(5).iterrows() %}<span>⚡ <span class="ip">{{ r.get('attack_ip','-') }}</span> → {{ r.get('service_name','-') }} @ {{ r.get('create_time','-') }}</span>{% endfor %}</div></div>

<div class="tab-nav">
<button class="tab-btn active" data-tab="overview">📊 总览</button>
<button class="tab-btn" data-tab="trends">📈 趋势</button>
<button class="tab-btn" data-tab="analysis">🔍 分析</button>
<button class="tab-btn" data-tab="details">📋 详情</button>
</div>

<!-- ==================== TAB 1: 总览 ==================== -->
<div class="tab-content active" id="tab-overview">
<div class="stats-grid">
<div class="stat-card"><div class="stat-num" data-count="{{ stats.total_attacks }}">0</div><div class="stat-lbl">总攻击次数</div></div>
<div class="stat-card"><div class="stat-num" data-count="{{ stats.unique_ips }}">0</div><div class="stat-lbl">独立攻击IP</div></div>
<div class="stat-card"><div class="stat-num" data-count="{{ account_count }}">0</div><div class="stat-lbl">账号资产数据</div></div>
<div class="stat-card"><div class="stat-num" data-count="{{ stats.active_honeypots }}">0</div><div class="stat-lbl">活跃蜜罐数</div></div>
<div class="stat-card"><div class="stat-num" data-count="{{ week_compare.current }}">0</div><div class="stat-lbl">近7天攻击</div></div>
<div class="stat-card"><div class="stat-num {{'up' if week_compare.trend=='上升' else 'down' if week_compare.trend=='下降' else ''}}" data-count="{{ week_compare.change }}">0</div><div class="stat-lbl">较前7天{{ week_compare.trend }}</div></div>
</div>

<div class="split">
<div class="section"><h2 class="sec-title">📊 服务攻击分布</h2><div class="chart-box short"><canvas id="pieChart"></canvas></div></div>
<div class="section"><h2 class="sec-title">📈 攻击强度</h2><div class="chart-box short"><canvas id="gaugeChart"></canvas></div></div>
</div>

<div class="section"><h2 class="sec-title">🗓️ 攻击日历热力图 ({{ stats.total_attacks }}条/{{ stats.daily_counts_list|length }}天)</h2>
<div class="cal-grid" id="calendarHeatmap"></div></div>

<div class="section"><h2 class="sec-title">🎯 各蜜罐受攻击次数</h2>
<div class="hp-grid">{% for n,c in stats.honeypot_data.items() %}<div class="hp-item"><div class="hp-name">{{ n }}</div><div class="hp-cnt" style="color:{% if c==0 %}#475569{% else %}var(--p){% endif %}">{{ c }}</div></div>{% endfor %}</div></div>

<div class="section"><h2 class="sec-title">📝 分析摘要</h2><p style="color:var(--mt);font-size:.95em;line-height:1.6">{{ summary_text }}</p></div>
</div>

<!-- ==================== TAB 2: 趋势 ==================== -->
<div class="tab-content" id="tab-trends">
<div class="section"><h2 class="sec-title">📈 攻击趋势分析（近7天 vs 前7天）</h2><div class="chart-box"><canvas id="trendChart"></canvas></div></div>
<div class="split">
<div class="section"><h2 class="sec-title">🔥 攻击时段分布（24小时）</h2><div class="chart-box short"><canvas id="heatChart"></canvas></div></div>
<div class="section"><h2 class="sec-title">🗺️ 攻击来源 TOP 15</h2><div class="chart-box short" id="mapChart"></div></div>
</div>
<div class="section"><h2 class="sec-title">📊 近7天 vs 前7天对比</h2>
{% set wc_chart_data = [week_compare.current, week_compare.last] %}
<div class="chart-box short"><canvas id="compareChart"></canvas></div>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-top:18px">
<div style="text-align:center;padding:16px;background:rgba(0,0,0,0.3);border-radius:12px;border:1px solid var(--brd)">
<div style="color:var(--mt);font-size:.85em">近7天</div><div style="font-size:2.4em;font-weight:700;color:var(--p);margin:6px 0">{{ week_compare.current }}</div></div>
<div style="text-align:center;padding:16px;background:rgba(0,0,0,0.3);border-radius:12px;border:1px solid var(--brd)">
<div style="color:var(--mt);font-size:.85em">前7天</div><div style="font-size:2.4em;font-weight:700;color:var(--mt);margin:6px 0">{{ week_compare.last }}</div></div>
<div style="text-align:center;padding:16px;background:rgba(0,0,0,0.3);border-radius:12px;border:1px solid var(--brd)">
<div style="color:var(--mt);font-size:.85em">变化量</div>
<div style="font-size:2.4em;font-weight:700;margin:6px 0;color:{% if week_compare.trend=='上升' %}#f87171{% elif week_compare.trend=='下降' %}#4ade80{% else %}var(--mt){% endif %}">{{ week_compare.change }}{% if week_compare.change > 0 %}+{% endif %}</div>
</div></div></div>
</div>

<!-- ==================== TAB 3: 分析 ==================== -->
<div class="tab-content" id="tab-analysis">
<div class="split">
<div class="section"><h2 class="sec-title">🛡️ IP威胁等级 (Top 50)</h2>
<div style="max-height:300px;overflow-y:auto">{% for t in page_data %}{% endfor %}
<table class="data-table"><thead><tr><th>IP地址</th><th>攻击次数</th><th>等级</th></tr></thead>
<tbody id="threatTableBody"></tbody></table></div></div>
<div class="section"><h2 class="sec-title">🔍 扫描行为检测</h2><div id="scannerList"></div></div>
</div>
<div class="split">
<div class="section"><h2 class="sec-title">🌐 /24 网段聚合</h2><div id="subnetList"></div></div>
<div class="section"><h2 class="sec-title">📅 星期分布</h2><div class="chart-box short"><canvas id="weekdayChart"></canvas></div></div>
</div>
<div class="section"><h2 class="sec-title">⚠️ 异常攻击日检测</h2><div id="anomalyList"></div></div>
</div>

<!-- ==================== TAB 4: 详情 ==================== -->
<div class="tab-content" id="tab-details">
<div class="section">
<h2 class="sec-title">📋 攻击详情记录 (共 <span id="totalCount">{{ total_records }}</span> 条，显示 <span id="shownCount">0</span> 条)</h2>
<div class="toolbar">
<input class="search-input" id="searchInput" placeholder="🔍 搜索IP/端口/服务/国家..." oninput="filterTable()">
<select class="topn-select" id="topNSelect" onchange="updateTopLists()"><option value="10">Top 10</option><option value="20">Top 20</option><option value="50" selected>Top 50</option></select>
<button class="btn" onclick="exportCSV()">📥 导出CSV</button>
<button class="btn" onclick="exportJSON()">📋 导出JSON</button>
</div>
<div style="overflow-x:auto;max-height:500px;overflow-y:auto">
<table class="data-table"><thead><tr>
<th onclick="sortTable('ip')">攻击源IP <span class="sort-icon">↕</span></th>
<th onclick="sortTable('location')">地理位置 <span class="sort-icon">↕</span></th>
<th onclick="sortTable('service')">服务类型 <span class="sort-icon">↕</span></th>
<th onclick="sortTable('port')">端口 <span class="sort-icon">↕</span></th>
<th onclick="sortTable('time')">攻击时间 <span class="sort-icon">↕</span></th>
</tr></thead>
<tbody id="tableBody"></tbody></table></div></div>

<div class="section"><h2 class="sec-title">🔝 <span id="topNLabel">Top 50</span> 攻击源IP</h2><div id="topIPList" class="rank-list"></div></div>
</div>

<div class="footer"><p>🤖 HFish 蜜罐系统自动采集 | 每6小时更新 | 毕业设计作品 | {{ last_update }}</p></div>
</div>

<script>
const PD = {{ page_data|safe }};
var sortDir = {}; var filtered = [];

// === Count-up Animation ===
function countUp(){document.querySelectorAll('.stat-num[data-count]').forEach(e=>{let t=parseInt(e.dataset.count);let n=0;let i=Math.ceil(t/60);let h=setInterval(()=>{n+=i;if(n>=t){n=t;clearInterval(h)}e.textContent=n.toLocaleString()},20)})}

// === Tabs ===
document.querySelectorAll('.tab-btn').forEach(b=>{b.onclick=()=>{
document.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'))
document.querySelectorAll('.tab-content').forEach(x=>x.classList.remove('active'))
b.classList.add('active');document.getElementById('tab-'+b.dataset.tab).classList.add('active')}})

// === Theme ===
function toggleTheme(){let d=document.documentElement;let b=document.getElementById('themeBtn')
if(d.getAttribute('data-theme')==='light'){d.removeAttribute('data-theme');b.textContent='🌙';localStorage.setItem('theme','dark')}
else{d.setAttribute('data-theme','light');b.textContent='☀️';localStorage.setItem('theme','light')}}
if(localStorage.getItem('theme')==='light'){document.documentElement.setAttribute('data-theme','light');document.getElementById('themeBtn').textContent='☀️'}

// === 1. Trend Chart ===
if(document.getElementById('trendChart')){(function(){
let ctx=document.getElementById('trendChart').getContext('2d');
let d=PD.chart;
let g1=ctx.createLinearGradient(0,0,0,350);g1.addColorStop(0,'rgba(0,212,255,0.3)');g1.addColorStop(1,'rgba(0,212,255,0)');
let g2=ctx.createLinearGradient(0,0,0,350);g2.addColorStop(0,'rgba(124,58,237,0.2)');g2.addColorStop(1,'rgba(124,58,237,0)');
new Chart(ctx,{type:'line',data:{labels:d.dates||[],datasets:[
{label:'近7天攻击',data:d.counts||[],borderColor:'#00d4ff',backgroundColor:g1,fill:true,tension:0.4,
 pointBackgroundColor:'#00d4ff',pointBorderColor:'#fff',pointBorderWidth:2,pointRadius:5,pointHoverRadius:8},
{label:'前7天攻击',data:d.prev_counts||[],borderColor:'#7c3aed',backgroundColor:g2,fill:true,tension:0.4,
 borderDash:[5,5],pointBackgroundColor:'#7c3aed',pointBorderColor:'#fff',pointBorderWidth:2,pointRadius:4,pointHoverRadius:7}
]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},
plugins:{legend:{position:'top',labels:{color:'#94a3b8',font:{size:13},usePointStyle:true}},
tooltip:{backgroundColor:'rgba(15,23,42,0.95)',titleColor:'#00d4ff',bodyColor:'#e2e8f0',borderColor:'rgba(0,212,255,0.3)',
 borderWidth:1,padding:10,displayColors:true,callbacks:{label:function(c){return c.dataset.label+': '+c.raw+' 次攻击'}}}},
scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)',drawBorder:false}},
y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},beginAtZero:true}},
animation:{duration:1500,easing:'easeOutQuart'}}})})()}

// === 2. Heatmap Chart ===
if(document.getElementById('heatChart')){(function(){
let ctx=document.getElementById('heatChart').getContext('2d');
let data=PD.heatmap||[];
let colors=data.map(v=>v>200?'#7c3aed':v>100?'#00d4ff':v>50?'#0284c7':v>20?'#0d47a1':'#1e293b');
new Chart(ctx,{type:'bar',data:{labels:Array.from({length:24},(_,i)=>i+':00'),datasets:[{label:'攻击次数',data:data,
 backgroundColor:colors,borderColor:colors,borderWidth:1,borderRadius:6,borderSkipped:false}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},
tooltip:{backgroundColor:'rgba(15,23,42,0.95)',titleColor:'#00d4ff',bodyColor:'#e2e8f0',
 borderColor:'rgba(0,212,255,0.3)',borderWidth:1,padding:10,callbacks:{label:function(c){return '攻击次数: '+c.raw+' 次'}}}}},
scales:{x:{ticks:{color:'#94a3b8',font:{size:11}},grid:{display:false}},
y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},beginAtZero:true}},
animation:{duration:1200,easing:'easeOutQuart'}}})})()}

// === 3. Compare Chart ===
if(document.getElementById('compareChart')){(function(){
let wc=PD.wc;let ctx=document.getElementById('compareChart').getContext('2d');
new Chart(ctx,{type:'bar',data:{labels:['近7天','前7天'],datasets:[{label:'攻击次数',
 data:[wc.current,wc.last],backgroundColor:['#00d4ff','#7c3aed'],borderColor:['#00d4ff','#7c3aed'],
 borderWidth:2,borderRadius:12,barThickness:50}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},
tooltip:{backgroundColor:'rgba(15,23,42,0.95)',titleColor:'#00d4ff',bodyColor:'#e2e8f0',
 borderColor:'rgba(0,212,255,0.3)',borderWidth:1,padding:10}},
scales:{x:{ticks:{color:'#94a3b8',font:{size:14,weight:'600'}},grid:{display:false}},
y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},beginAtZero:true}},
animation:{duration:1000,easing:'easeOutQuart'}}})})()}

// === 4. Country Bar Chart ===
if(document.getElementById('mapChart')){(function(){
let mapDom=document.getElementById('mapChart');let mapData=PD.map||{countries:[]};
if(mapData.countries.length>0){
let sorted=[...mapData.countries].sort((a,b)=>b.value-a.value).slice(0,15);
mapDom.innerHTML='<canvas id="countryBarChart" style="width:100%;height:100%"></canvas>';
let ctx=document.getElementById('countryBarChart').getContext('2d');
new Chart(ctx,{type:'bar',data:{labels:sorted.map(c=>c.name),datasets:[{label:'攻击次数',
 data:sorted.map(c=>c.value),backgroundColor:'rgba(0,212,255,0.7)',borderColor:'#00d4ff',borderWidth:1,borderRadius:6}]},
options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
plugins:{legend:{display:false},title:{display:true,text:'攻击来源 TOP 15 国家/地区',color:'#94a3b8',font:{size:13}}},
scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)'}},
y:{ticks:{color:'#94a3b8'},grid:{display:false}}}}})}})()}

// === 5. Pie Chart ===
if(document.getElementById('pieChart')){(function(){
let ctx=document.getElementById('pieChart').getContext('2d');
let data=PD.pie||[];
let colors=['#00d4ff','#7c3aed','#4ade80','#fbbf24','#f87171','#60a5fa','#a78bfa','#34d399','#f472b6','#64748b'];
if(data.length===0){ctx.canvas.parentNode.innerHTML='<div style="color:var(--mt);text-align:center;padding:60px 0">暂无数据</div>';return}
new Chart(ctx,{type:'doughnut',data:{labels:data.map(d=>d.name),datasets:[{data:data.map(d=>d.value),
 backgroundColor:colors.slice(0,data.length),borderColor:'rgba(0,0,0,0.3)',borderWidth:2}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',
 labels:{color:'#94a3b8',font:{size:12},boxWidth:12,padding:12}},
tooltip:{backgroundColor:'rgba(15,23,42,0.95)',titleColor:'#00d4ff',bodyColor:'#e2e8f0'}}}})})()}

// === 6. Gauge Chart ===
if(document.getElementById('gaugeChart')){(function(){
let ctx=document.getElementById('gaugeChart').getContext('2d');
let wc=PD.wc;let total=PD.total||0;
let days=PD.daily?PD.daily.length:1;let dailyAvg=days>0?Math.round(total/days):0;
let maxVal=dailyAvg*2||1;
new Chart(ctx,{type:'bar',data:{labels:['日均攻击'],datasets:[{data:[Math.min(dailyAvg,maxVal)],
 backgroundColor:['rgba(0,212,255,0.7)'],borderColor:['#00d4ff'],borderWidth:2,borderRadius:12,barThickness:40}]},
options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
plugins:{legend:{display:false},
tooltip:{backgroundColor:'rgba(15,23,42,0.95)',bodyColor:'#e2e8f0',callbacks:{label:function(){return '日均: '+dailyAvg+' 次'}}},
annotation:{annotations:{line:{type:'line',yMin:maxVal*0.5,yMax:maxVal*0.5,borderColor:'rgba(248,113,113,0.6)',
 borderWidth:2,borderDash:[6,3],label:{display:true,content:'线',position:'end'}}}}},
scales:{x:{max:maxVal,ticks:{color:'#94a3b8'},grid:{display:false}},
y:{ticks:{color:'#94a3b8'},grid:{display:false}}},
animation:{duration:1500,easing:'easeOutQuart'}}})})()}

// === 7. Calendar Heatmap ===
(function(){let daily=PD.daily||[];let cont=document.getElementById('calendarHeatmap');
if(!cont)return;
if(daily.length===0){cont.innerHTML='<div style="color:var(--mt);padding:10px">暂无数据</div>';return}
let maxC=Math.max(...daily.map(d=>d.count),1);
daily.forEach(d=>{let r=Math.round((d.count/maxC)*255);
let box=document.createElement('div');box.className='cal-day';
let color=d.count===0?'rgba(255,255,255,0.05)':`rgba(0,212,255,${0.15+(d.count/maxC)*0.85})`;
if((PD.anomaly||[]).some(a=>a.date===d.date)){color='rgba(248,113,113,0.6)'}
box.style.background=color;box.dataset.tip=`${d.date}: ${d.count}次`;
cont.appendChild(box)})})();

// === 8. Weekday Chart ===
if(document.getElementById('weekdayChart')){(function(){
let ctx=document.getElementById('weekdayChart').getContext('2d');
let data=PD.weekday||[];
let colors=data.map(()=>'rgba(0,212,255,0.7)');
new Chart(ctx,{type:'bar',data:{labels:data.map(d=>d.day),datasets:[{label:'攻击次数',data:data.map(d=>d.count),
 backgroundColor:colors,borderColor:'#00d4ff',borderWidth:1,borderRadius:6}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},
tooltip:{backgroundColor:'rgba(15,23,42,0.95)',bodyColor:'#e2e8f0'}},
scales:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},
y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},beginAtZero:true}},
animation:{duration:1000,easing:'easeOutQuart'}}})})()}

// === 9. Threat Levels ===
(function(){let threats=PD.threats||[];let tbody=document.getElementById('threatTableBody');
if(!tbody)return;
if(threats.length===0){tbody.innerHTML='<tr><td colspan="3" style="text-align:center;color:var(--mt)">暂无数据</td></tr>';return}
let levelNames={high:'高危',medium:'中危',low:'低危'};
let badges={high:'badge-h',medium:'badge-m',low:'badge-l'};
threats.forEach(t=>{tbody.innerHTML+=`<tr><td><span class="badge-${t.level}" style="display:inline-block;background:rgba(${t.level==='high'?'248,113,113':t.level==='medium'?'251,191,36':'74,222,128'},0.15);color:${t.level==='high'?'#f87171':t.level==='medium'?'#fbbf24':'#4ade80'};padding:2px 10px;border-radius:10px;font-size:.75em;font-weight:600;margin-right:6px">${levelNames[t.level]}</span>${t.ip}</td><td>${t.count}次</td><td><span class="badge-${t.level}" style="background:rgba(${t.level==='high'?'248,113,113':t.level==='medium'?'251,191,36':'74,222,128'},0.2);color:${t.level==='high'?'#f87171':t.level==='medium'?'#fbbf24':'#4ade80'};padding:2px 10px;border-radius:10px;font-size:.75em">${levelNames[t.level]}</span></td></tr>`})})();

// === 10. Scanner List ===
(function(){let scanners=PD.scanners||[];let cont=document.getElementById('scannerList');
if(!cont)return;
if(scanners.length===0){cont.innerHTML='<div style="color:var(--mt);padding:20px;text-align:center">未检测到扫描行为</div>';return}
let h='<div style="max-height:300px;overflow-y:auto">';
scanners.forEach(s=>{h+=`<div class="rank-item"><span style="flex:1">🔍 ${s.ip}</span><span class="rank-val">${s.services}种服务</span></div>
<div style="font-size:.78em;color:var(--mt);padding:0 6px 8px 6px">${s.service_list.join(', ')}</div>`});
h+='</div>';cont.innerHTML=h})();

// === 11. Subnet List ===
(function(){let subnets=PD.subnets||[];let cont=document.getElementById('subnetList');
if(!cont)return;
if(subnets.length===0){cont.innerHTML='<div style="color:var(--mt);padding:20px;text-align:center">暂无数据</div>';return}
let h='<div style="max-height:250px;overflow-y:auto">';
subnets.forEach(s=>{h+=`<div class="rank-item"><span>🌐 ${s.subnet}</span><span class="rank-val">${s.count}次</span></div>`});
h+='</div>';cont.innerHTML=h})();

// === 12. Anomaly Days ===
(function(){let anomaly=PD.anomaly||[];let cont=document.getElementById('anomalyList');
if(!cont)return;
if(anomaly.length===0){cont.innerHTML='<div style="color:var(--mt);padding:20px;text-align:center">✅ 未检测到异常攻击日（超过均值+2σ）</div>';return}
let h='<div style="max-height:200px;overflow-y:auto">';
anomaly.forEach(a=>{h+=`<div class="rank-item"><span><span class="anomaly-dot"></span>⚠️ ${a.date}</span><span class="rank-val" style="color:#f87171">${a.count}次</span></div>`});
h+='</div>';cont.innerHTML=h})();

// === 13. Table Rendering + Search + Sort ===
function renderTable(data){
let tbody=document.getElementById('tableBody');if(!tbody)return;
document.getElementById('shownCount').textContent=data.length;
tbody.innerHTML=data.map(r=>`<tr><td><span class="badge-${r.level||'l'}" style="background:rgba(0,212,255,0.15);color:var(--p);padding:2px 10px;border-radius:10px;font-size:.75em">${r.ip}</span></td><td>${r.location}</td><td>${r.service}</td><td>${r.port}</td><td>${r.time}</td></tr>`).join('')}

function filterTable(){
let q=document.getElementById('searchInput').value.toLowerCase();
filtered=PD.rows.filter(r=>r.attack_ip.toLowerCase().includes(q)||r.service_name.toLowerCase().includes(q)||
 r.service_port.toLowerCase().includes(q)||r.ip_location.toLowerCase().includes(q));
renderTable(filtered.map(r=>({ip:r.attack_ip,location:r.ip_location,service:r.service_name,port:r.service_port,time:r.create_time,level:''})))}

function sortTable(col){
let map={ip:'attack_ip',location:'ip_location',service:'service_name',port:'service_port',time:'create_time'};
let key=map[col];sortDir[col]=!(sortDir[col]||false);
let data=filtered.length>0?filtered:(PD.rows||[]);
data.sort((a,b)=>{let va=a[key]||'';let vb=b[key]||'';
 if(col==='port'){va=parseInt(va)||0;vb=parseInt(vb)||0}
 else{if(typeof va==='string'){va=va.toLowerCase();vb=vb.toLowerCase()}}
 return sortDir[col]?va<vb?-1:va>vb?1:0:va<vb?1:va>vb?-1:0});
renderTable(data.map(r=>({ip:r.attack_ip,location:r.ip_location,service:r.service_name,port:r.service_port,time:r.create_time,level:''})))}

// Init table
filtered=PD.rows||[];filterTable();

// === 14. Top N Switcher + IP/Country lists ===
function updateTopLists(){
let n=parseInt(document.getElementById('topNSelect').value);
document.getElementById('topNLabel').textContent='Top '+n;
let ips=PD.ips||[];let cont=document.getElementById('topIPList');
if(!cont)return;
cont.innerHTML=ips.slice(0,n).map((r,i)=>`<div class="rank-item"><span>${i+1}. ${r.ip}</span><span class="rank-val">${r.count}次</span></div>`).join('')}
setTimeout(updateTopLists,0);

// === 15. Export ===
function exportCSV(){
let rows=filtered.length>0?filtered:(PD.rows||[]);
let csv='攻击源IP,地理位置,服务类型,端口,攻击时间\n';
rows.forEach(r=>{csv+=`"${r.attack_ip}","${r.ip_location}","${r.service_name}","${r.service_port}","${r.create_time}"\n`});
let blob=new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8;'});
let a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='threat_export.csv';a.click()}

function exportJSON(){
let rows=filtered.length>0?filtered:(PD.rows||[]);
let blob=new Blob([JSON.stringify(rows,null,2)],{type:'application/json;charset=utf-8;'});
let a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='threat_export.json';a.click()}

// === 16. Page Summary ===
(function(){let anomalies=PD.anomaly||[];if(anomalies.length>0){
let summary=document.querySelector('.section:last-child .sec-title');
if(summary){summary.innerHTML+=' <span style="color:#f87171;font-size:.8em">⚠️</span>'}}})();

// Init
countUp();
</script>
</body>
</html>
""")

    html_content = template.render(
        df=df, stats=stats, time_range=time_range,
        week_compare=wc, account_count=len(accounts),
        summary_text=summary_text, total_records=total_records,
        page_data=page_data,
        last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ HTML 报告已生成: {OUTPUT_DIR}/index.html")

# ==================== 主函数 ====================
def main():
    end_time = datetime.now()
    start_time = end_time - timedelta(days=LOOKBACK_DAYS)
    time_range = f"{start_time.strftime('%Y-%m-%d %H:%M')} ~ {end_time.strftime('%Y-%m-%d %H:%M')}"
    print(f"🔄 正在拉取攻击日志（近{LOOKBACK_DAYS}天）...")
    logs = fetch_attack_logs(start_time, end_time)
    print("🔄 正在拉取账号资产数据...")
    accounts = fetch_accounts()
    if logs:
        print(f"📥 攻击数据: {len(logs)} 条 | 账号数据: {len(accounts)} 条")
        df, stats = process_data(logs)
        print(f"📊 处理后DataFrame: {len(df)}行, {len(df.columns)}列")
        print(f"   总攻击: {stats['total_attacks']} | 独立IP: {stats['unique_ips']} | 活跃蜜罐: {stats['active_honeypots']}")
        map_data = generate_map_data(df)
        export_csv(df)
        generate_html(df, stats, accounts, map_data, time_range)
        print("✨ v9.0 (互动增强版) 所有任务完成！")
    else:
        print("⚠️ 未拉取到攻击数据")

if __name__ == "__main__":
    main()