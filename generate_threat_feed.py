#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v7.0
全新UI + 地图GeoJSON修复 + 响应式布局 + 动画效果
"""

import requests, pandas as pd, os, json, urllib3
from datetime import datetime, timedelta
from jinja2 import Template
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HFISH_BASE_URL = "https://127.0.0.1:4433"
API_KEY = "SiFtBHLWzBmcRjndOoQEwPAjvBSBefxSDfvxMoxXwjetfnELGjXIbTZvhFZceacI"

END_TIME = datetime.now()
START_TIME = END_TIME - timedelta(days=90)
LAST_WEEK_END = START_TIME
LAST_WEEK_START = LAST_WEEK_END - timedelta(days=7)
OUTPUT_DIR = "./docs"

def fetch_attack_logs(start_ts, end_ts):
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    try:
        r = requests.post(url, headers={"Content-Type":"application/json"}, params={"api_key":API_KEY},
            json={"start_time":int(start_ts.timestamp()),"end_time":int(end_ts.timestamp()),"page":1,"page_size":5000}, verify=False, timeout=30)
        if r.json().get("response_code")==0: return r.json().get("data",[])
    except: pass
    return []

def fetch_accounts():
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    try:
        r = requests.post(url, headers={"Content-Type":"application/json"}, params={"api_key":API_KEY},
            json={"page":1,"page_size":5000}, verify=False, timeout=30)
        if r.json().get("response_code")==0: return r.json().get("data",[])
    except: pass
    return []

def process_data(raw_logs):
    if not raw_logs: return pd.DataFrame(),{}
    df = pd.DataFrame(raw_logs)
    keep = ["attack_ip","ip_location","service_name","service_port","create_time"]
    df = df[[c for c in keep if c in df.columns]].copy()
    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"],unit='s').dt.strftime("%Y-%m-%d %H:%M")
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(lambda x: x.split("-")[0] if isinstance(x,str) and "-" in x else x)
    all_hp = ["SSH蜜罐","FTP蜜罐","Telnet蜜罐","HTTP代理蜜罐","MYSQL蜜罐","REDIS蜜罐",
              "Elasticsearch蜜罐","CUSTOM蜜罐","TCP端口监听","Nginx蜜罐"]
    hp_counts = df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}
    hp_data = {hp: hp_counts.get(hp,0) for hp in all_hp}
    heatmap = [0]*24
    if "hour" in df.columns:
        for h,c in df["hour"].value_counts().to_dict().items(): heatmap[int(h)]=c
    ports = df["service_port"].value_counts().head(10).to_dict() if "service_port" in df.columns else {}
    return df, {
        "total_attacks":len(df),
        "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
        "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
        "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
        "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
        "top_ports": ports, "honeypot_data": hp_data,
        "active_honeypots": sum(1 for v in hp_data.values() if v>0),
        "heatmap_data": heatmap,
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }

COUNTRY_MAP = {
    "中国":"China","美国":"United States","俄罗斯":"Russia","加拿大":"Canada",
    "新加坡":"Singapore","日本":"Japan","韩国":"South Korea","德国":"Germany",
    "英国":"United Kingdom","法国":"France","印度":"India","巴西":"Brazil",
    "澳大利亚":"Australia","荷兰":"Netherlands","越南":"Vietnam",
    "乌克兰":"Ukraine","波兰":"Poland","意大利":"Italy","西班牙":"Spain",
    "瑞典":"Sweden","瑞士":"Switzerland","土耳其":"Turkey","伊朗":"Iran",
    "泰国":"Thailand","马来西亚":"Malaysia","印度尼西亚":"Indonesia",
    "巴基斯坦":"Pakistan","比利时":"Belgium","保加利亚":"Bulgaria",
    "南非":"South Africa","肯尼亚":"Kenya","菲律宾":"Philippines",
    "埃塞俄比亚":"Ethiopia","葡萄牙":"Portugal","匈牙利":"Hungary",
    "哈萨克斯坦":"Kazakhstan","乌兹别克斯坦":"Uzbekistan",
    "阿根廷":"Argentina","委内瑞拉":"Venezuela","伊拉克":"Iraq",
    "孟加拉":"Bangladesh","玻利维亚":"Bolivia","巴拉圭":"Paraguay",
    "萨尔瓦多":"El Salvador","尼加拉瓜":"Nicaragua",
    "特立尼达和多巴哥":"Trinidad and Tobago",
    "欧洲地区":"Russia","亚太地区":"China","非洲地区":"South Africa"
}

def generate_map_data(df):
    if "country" not in df.columns or df.empty: return
    cc = df["country"].value_counts().to_dict()
    countries = [{"name":COUNTRY_MAP.get(k), "value":v} for k,v in cc.items() if COUNTRY_MAP.get(k)]
    mx = max(cc.values()) if cc else 1
    with open(os.path.join(OUTPUT_DIR,"country_data.json"),"w",encoding="utf-8") as f:
        json.dump({"countries":countries,"maxCount":mx},f,ensure_ascii=False)

def export_csv(df):
    if not df.empty:
        e = df[["attack_ip","ip_location","service_name","service_port","create_time"]].head(500).copy()
        e.columns = ["攻击源IP","地理位置","服务类型","端口","攻击时间"]
        e.to_csv(os.path.join(OUTPUT_DIR,"threat_data.csv"),index=False,encoding="utf-8-sig")

def gen_chart(df):
    if "create_time" in df.columns and not df.empty:
        df["date"] = pd.to_datetime(df["create_time"]).dt.strftime("%m-%d")
        d = df["date"].value_counts().sort_index()
        return json.dumps({"dates":d.index.tolist()[-7:],"counts":d.values.tolist()[-7:]})
    return json.dumps({"dates":[],"counts":[]})

def compare_weeks(cur, last):
    if last:
        ch = len(cur)-len(last)
        return {"current":len(cur),"last":len(last),"change":ch,"trend":"上升" if ch>0 else ("下降" if ch<0 else "持平")}
    return {"current":len(cur),"last":0,"change":0,"trend":"无对比数据"}

def safe_pwd(pwd, max_len=20):
    return pwd if len(pwd) <= max_len else pwd[:17]+"..."

def generate_html(df, stats, accounts, wc):
    cd = gen_chart(df)
    hd = json.dumps(stats.get("heatmap_data",[0]*24))
    tp = [(safe_pwd(p),c) for p,c in Counter([a.get("password","") for a in accounts if a.get("password")]).most_common(10)]
    tu = Counter([a.get("username","") for a in accounts if a.get("username")]).most_common(5)

    t = Template(r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HFish 威胁情报监控中心</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<style>
:root{
    --bg:#06060f; --card-bg:rgba(255,255,255,0.03);
    --primary:#00d4ff; --accent:#7c3aed; --accent2:#06b6d4;
    --text:#e2e8f0; --muted:#94a3b8; --border:rgba(255,255,255,0.06);
    --shadow:0 4px 24px rgba(0,0,0,0.4);
    --glow:0 0 20px rgba(0,212,255,0.15);
    --radius:16px; --radius-sm:12px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{
    font-family:'Inter','Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
    background:#06060f;
    color:var(--text); min-height:100vh;
    line-height:1.5; -webkit-font-smoothing:antialiased;
}
body::before{
    content:''; position:fixed; inset:0;
    background:radial-gradient(ellipse at 30% 20%,rgba(0,212,255,0.06) 0%,transparent 60%),
               radial-gradient(ellipse at 70% 60%,rgba(124,58,237,0.05) 0%,transparent 60%),
               radial-gradient(ellipse at 50% 80%,rgba(6,182,212,0.04) 0%,transparent 50%);
    pointer-events:none; z-index:0;
}
.container{max-width:1440px;margin:0 auto;padding:20px;position:relative;z-index:1}

/* 头部 */
.header{
    text-align:center; padding:35px 25px; margin-bottom:30px;
    background:linear-gradient(135deg,rgba(0,212,255,0.06),rgba(124,58,237,0.04));
    border:1px solid var(--border); border-radius:var(--radius);
    box-shadow:var(--shadow);
}
.header h1{
    font-size:clamp(1.6em,4vw,2.8em); font-weight:800; letter-spacing:-0.5px;
    background:linear-gradient(135deg,var(--primary),var(--accent2),var(--accent));
    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
    margin-bottom:8px;
}
.header .sub{color:var(--muted);font-size:0.88em;}

/* 统计卡片 */
.stats-grid{
    display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:16px; margin-bottom:30px;
}
.stat-card{
    background:var(--card-bg); border:1px solid var(--border);
    border-radius:var(--radius); padding:22px 16px; text-align:center;
    transition:all 0.3s cubic-bezier(0.4,0,0.2,1);
    position:relative; overflow:hidden;
    box-shadow:var(--shadow);
}
.stat-card::after{
    content:''; position:absolute; top:0; left:0; right:0; height:2px;
    background:linear-gradient(90deg,var(--primary),var(--accent));
    opacity:0; transition:opacity 0.3s;
}
.stat-card:hover{
    transform:translateY(-6px); border-color:rgba(0,212,255,0.3);
    box-shadow:var(--glow);
}
.stat-card:hover::after{opacity:1}
.stat-number{
    font-size:clamp(1.8em,3vw,2.4em); font-weight:800;
    background:linear-gradient(135deg,var(--primary),var(--accent2));
    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
}
.stat-label{color:var(--muted);font-size:0.8em;margin-top:6px;text-transform:uppercase;letter-spacing:0.5px}

/* 通用区块 */
.section{
    background:var(--card-bg); border:1px solid var(--border);
    border-radius:var(--radius); padding:28px 24px; margin-bottom:24px;
    box-shadow:var(--shadow);
}
.section-title{
    font-size:1.2em; font-weight:700; color:var(--primary);
    margin-bottom:20px; padding-bottom:12px;
    border-bottom:2px solid var(--border);
    display:flex; align-items:center; gap:10px;
}
.section-title::before{
    content:''; width:4px; height:24px; border-radius:2px;
    background:linear-gradient(180deg,var(--primary),var(--accent));
}

/* 图表容器 */
.chart-box{width:100%;height:380px}
.map-box{width:100%;height:520px;min-height:400px}
.heatmap-box{width:100%;height:300px}

/* 蜜罐卡片 */
.hp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px}
.hp-item{
    background:rgba(0,212,255,0.04); border:1px solid var(--border);
    border-radius:var(--radius-sm); padding:16px; text-align:center;
    transition:all 0.3s ease;
}
.hp-item:hover{transform:translateY(-3px);border-color:rgba(0,212,255,0.3);box-shadow:var(--glow)}
.hp-name{color:var(--muted);font-size:0.75em;margin-bottom:6px}
.hp-count{font-size:1.6em;font-weight:800;color:var(--primary)}
.hp-zero{color:#3a3a50}

/* 列表卡片 */
.top-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.list-item{
    background:rgba(0,0,0,0.4); border:1px solid var(--border);
    border-radius:var(--radius-sm); padding:20px;
}
.list-item h3{color:var(--primary);font-size:1em;margin-bottom:14px;font-weight:600}
.rank-row{
    display:flex;justify-content:space-between;align-items:center;
    padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.85em;
    gap:10px;
}
.rank-row span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:72%}
.rank-val{font-weight:700;color:var(--primary);flex-shrink:0}

/* 表格 */
.tbl-wrap{overflow-x:auto;max-height:400px;overflow-y:auto;border-radius:var(--radius-sm)}
table{width:100%;border-collapse:collapse;font-size:0.85em;color:var(--text)}
th{background:rgba(0,212,255,0.08);color:var(--primary);padding:12px 14px;text-align:left;font-weight:600;position:sticky;top:0;z-index:1}
td{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.04);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:rgba(0,212,255,0.03)}
.badge{background:rgba(0,212,255,0.1);color:var(--primary);padding:3px 10px;border-radius:20px;font-size:0.8em;font-weight:500}

/* 周对比 */
.compare-row{display:flex;gap:24px;justify-content:center;flex-wrap:wrap}
.compare-item{background:rgba(0,0,0,0.4);border-radius:var(--radius-sm);padding:20px 28px;text-align:center;border:1px solid var(--border)}
.compare-num{font-size:2em;font-weight:800}
.compare-label{color:var(--muted);font-size:0.8em;margin-top:4px}

/* 颜色 */
.up{color:#4ade80}.down{color:#f87171}.warn{color:#f87171;font-weight:600}
.footer{text-align:center;color:#4a4a60;margin-top:40px;padding:20px;font-size:0.82em;border-top:1px solid var(--border)}

/* 响应式 */
@media(max-width:768px){
    .container{padding:12px}
    .section{padding:20px 16px}
    .chart-box{height:280px}.map-box{height:380px}.heatmap-box{height:240px}
    .stats-grid{grid-template-columns:repeat(3,1fr);gap:10px}
    .top-list{grid-template-columns:1fr}
}
@media(max-width:480px){
    .stats-grid{grid-template-columns:repeat(2,1fr)}
    .header h1{font-size:1.4em}
}
</style>
</head>
<body>
<div class="container">

<!-- 头部 -->
<header class="header">
    <h1>🛡️ HFish 威胁情报监控中心</h1>
    <p class="sub">{{ stats.time_range }} &nbsp;|&nbsp; 最后更新: {{ last_update }}</p>
</header>

<!-- 统计卡片 -->
<div class="stats-grid">
    <div class="stat-card"><div class="stat-number">{{ stats.total_attacks }}</div><div class="stat-label">总攻击次数</div></div>
    <div class="stat-card"><div class="stat-number">{{ stats.unique_ips }}</div><div class="stat-label">独立攻击IP</div></div>
    <div class="stat-card"><div class="stat-number">{{ account_count }}</div><div class="stat-label">账号资产</div></div>
    <div class="stat-card"><div class="stat-number">{{ stats.active_honeypots }}</div><div class="stat-label">活跃蜜罐</div></div>
    <div class="stat-card"><div class="stat-number">{{ wc.current }}</div><div class="stat-label">本周攻击</div></div>
    <div class="stat-card">
        <div class="stat-number {{ 'up' if wc.trend=='上升' else 'down' if wc.trend=='下降' else '' }}">
            {{ wc.change }}{% if wc.change>0 %}+{% endif %}
        </div>
        <div class="stat-label">较上周{{ wc.trend }}</div>
    </div>
</div>

<!-- 攻击趋势 -->
<section class="section">
    <h2 class="section-title">📈 攻击趋势（近7天）</h2>
    <div class="chart-box"><canvas id="trendChart"></canvas></div>
</section>

<!-- 攻击时段 -->
<section class="section">
    <h2 class="section-title">🔥 攻击时段分布（24小时）</h2>
    <div class="heatmap-box"><canvas id="heatmapChart"></canvas></div>
</section>

<!-- 周对比 -->
<section class="section">
    <h2 class="section-title">📊 本周 vs 上周对比</h2>
    <div class="compare-row">
        <div class="compare-item"><div class="compare-num" style="color:var(--primary)">{{ wc.current }}</div><div class="compare-label">本周攻击</div></div>
        <div class="compare-item"><div class="compare-num" style="color:var(--muted)">{{ wc.last }}</div><div class="compare-label">上周攻击</div></div>
        <div class="compare-item">
            <div class="compare-num {{ 'up' if wc.trend=='上升' else 'down' if wc.trend=='下降' else '' }}">
                {{ wc.change }}{% if wc.change>0 %}+{% endif %}
            </div>
            <div class="compare-label">{{ wc.trend }}</div>
        </div>
    </div>
</section>

<!-- 世界地图 -->
<section class="section">
    <h2 class="section-title">🗺️ 攻击来源全球分布</h2>
    <div class="map-box" id="worldMap"></div>
</section>

<!-- 分蜜罐统计 -->
<section class="section">
    <h2 class="section-title">🎯 各蜜罐受攻击次数</h2>
    <div class="hp-grid">
        {% for n,c in stats.honeypot_data.items() %}
        <div class="hp-item"><div class="hp-name">{{ n }}</div><div class="hp-count {% if c==0 %}hp-zero{% endif %}">{{ c }}</div></div>
        {% endfor %}
    </div>
</section>

<!-- 攻击分析 -->
<section class="section">
    <h2 class="section-title">📊 攻击统计分析</h2>
    <div class="top-list">
        <div class="list-item"><h3>🔝 Top 10 攻击源IP</h3>
            {% for ip,c in stats.top_ips.items() %}<div class="rank-row"><span title="{{ ip }}">{{ ip }}</span><span class="rank-val">{{ c }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>🌍 攻击来源国家</h3>
            {% for ct,c in stats.top_countries.items() %}<div class="rank-row"><span>{{ ct }}</span><span class="rank-val">{{ c }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>🔑 弱口令字典 TOP 10</h3>
            {% for p,c in tp %}<div class="rank-row"><span class="warn" title="{{ p }}">{{ p }}</span><span class="rank-val">{{ c }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>👤 高频用户名 TOP 5</h3>
            {% for u,c in tu %}<div class="rank-row"><span>{{ u }}</span><span class="rank-val">{{ c }}</span></div>{% endfor %}</div>
        <div class="list-item"><h3>🔌 目标端口 TOP 10</h3>
            {% for p,c in stats.top_ports.items() %}<div class="rank-row"><span>端口 {{ p }}</span><span class="rank-val">{{ c }}</span></div>{% endfor %}</div>
    </div>
</section>

<!-- 最新攻击 -->
<section class="section">
    <h2 class="section-title">📋 最新攻击详情</h2>
    <div class="tbl-wrap">
        <table><thead><tr><th>攻击源IP</th><th>地理位置</th><th>服务类型</th><th>端口</th><th>攻击时间</th></tr></thead><tbody>
            {% for _,r in df.head(100).iterrows() %}
            <tr><td><span class="badge">{{ r.get('attack_ip','-') }}</span></td><td>{{ r.get('ip_location','-') }}</td><td>{{ r.get('service_name','-') }}</td><td>{{ r.get('service_port','-') }}</td><td>{{ r.get('create_time','-') }}</td></tr>
            {% endfor %}
        </tbody></table>
    </div>
</section>

<footer class="footer"><p>🤖 HFish 蜜罐系统自动采集 &nbsp;|&nbsp; 每6小时自动更新 &nbsp;|&nbsp; 毕业设计作品 &nbsp;|&nbsp; {{ last_update }}</p></footer>
</div>

<script>
// 攻击趋势图
(function(){
var ctx=document.getElementById('trendChart').getContext('2d');
var d={{ cd|safe }};
new Chart(ctx,{type:'line',data:{labels:d.dates,datasets:[{label:'攻击次数',data:d.counts,borderColor:'#00d4ff',backgroundColor:function(ctx){var g=ctx.chart.ctx.createLinearGradient(0,0,0,380);g.addColorStop(0,'rgba(0,212,255,0.15)');g.addColorStop(1,'rgba(0,212,255,0)');return g},fill:true,tension:0.4,pointRadius:5,pointBackgroundColor:'#00d4ff',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8',font:{size:12}}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'}},y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'},beginAtZero:true}}});
})();

// 时段热力图
(function(){
var ctx=document.getElementById('heatmapChart').getContext('2d');
new Chart(ctx,{type:'bar',data:{labels:Array.from({length:24},(_,i)=>i+'时'),datasets:[{label:'攻击次数',data:{{ hd|safe }},backgroundColor:function(ctx){var v=ctx.raw;return v>200?'#7c3aed':v>100?'#00d4ff':v>50?'#0284c7':'rgba(0,212,255,0.4)'},borderRadius:6,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'},beginAtZero:true}}});
})();

// 世界地图 (GeoJSON)
(function(){
var dom=document.getElementById('worldMap');
if(!dom) return;
var mc=echarts.init(dom);
mc.showLoading({text:'地图加载中...',color:'#00d4ff',textColor:'#94a3b8',maskColor:'rgba(6,6,15,0.8)'});
fetch('country_data.json').then(function(r){return r.json()}).then(function(data){
    fetch('https://geo.datav.aliyun.com/areas_v3/bound/world.json')
    .then(function(r){return r.json()})
    .then(function(geo){
        mc.hideLoading();
        echarts.registerMap('world',geo);
        mc.setOption({
            backgroundColor:'transparent',
            tooltip:{trigger:'item',backgroundColor:'rgba(0,0,0,0.9)',borderColor:'rgba(0,212,255,0.3)',textStyle:{color:'#e2e8f0'},
                formatter:function(p){return '<b style="color:#00d4ff">'+p.name+'</b><br/>攻击次数: <b>'+ (p.value||0) +'</b>'}},
            visualMap:{min:0,max:data.maxCount||100,text:['高','低'],realtime:false,calculable:true,orient:'horizontal',left:'center',bottom:10,
                inRange:{color:['#1a1a3e','#0d47a1','#1565c0','#0284c7','#00d4ff','#06b6d4']},textStyle:{color:'#94a3b8'}},
            series:[{type:'map',map:'world',roam:true,zoom:1.2,center:[20,30],aspectScale:0.75,
                emphasis:{label:{show:true,color:'#fff',fontWeight:'bold'},itemStyle:{areaColor:'#00d4ff',shadowBlur:20,shadowColor:'rgba(0,212,255,0.5)'}},
                itemStyle:{borderColor:'rgba(255,255,255,0.1)',areaColor:'#1a1a3e',borderWidth:1},
                data:data.countries||[],
                nameMap:{'United States':'美国','Russia':'俄罗斯','China':'中国','Canada':'加拿大','United Kingdom':'英国','Germany':'德国','France':'法国','India':'印度','Brazil':'巴西','Japan':'日本','South Korea':'韩国','Netherlands':'荷兰','Italy':'意大利','Spain':'西班牙','Sweden':'瑞典','Turkey':'土耳其','Iran':'伊朗','Thailand':'泰国','Malaysia':'马来西亚','Vietnam':'越南','Indonesia':'印度尼西亚','Pakistan':'巴基斯坦','Belgium':'比利时','Bulgaria':'保加利亚','South Africa':'南非','Kenya':'肯尼亚','Philippines':'菲律宾','Ethiopia':'埃塞俄比亚','Portugal':'葡萄牙','Hungary':'匈牙利','Kazakhstan':'哈萨克斯坦','Uzbekistan':'乌兹别克斯坦','Argentina':'阿根廷','Venezuela':'委内瑞拉','Iraq':'伊拉克','Bangladesh':'孟加拉','Bolivia':'玻利维亚','Paraguay':'巴拉圭','El Salvador':'萨尔瓦多','Nicaragua':'尼加拉瓜','Trinidad and Tobago':'特立尼达和多巴哥','Ukraine':'乌克兰','Poland':'波兰','Switzerland':'瑞士','Australia':'澳大利亚'}
            }]
        });
    }).catch(function(){
        mc.hideLoading();
        mc.setOption({title:{text:'地图加载失败',left:'center',top:'center',textStyle:{color:'#94a3b8'}}});
    });
}).catch(function(){
    mc.hideLoading();
});
window.addEventListener('resize',function(){mc.resize();});
})();
</script>
</body>
</html>""")

    html = t.render(df=df, stats=stats, cd=cd, hd=hd, tp=tp, tu=tu, wc=wc,
                     account_count=len(accounts), last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR,"index.html"),"w",encoding="utf-8") as f: f.write(html)
    print("✅ HTML 已生成")

def main():
    print("🔄 拉取数据...")
    logs = fetch_attack_logs(START_TIME, END_TIME)
    last = fetch_attack_logs(LAST_WEEK_START, LAST_WEEK_END)
    accts = fetch_accounts()
    if logs:
        df, stats = process_data(logs)
        wc = compare_weeks(df, last)
        print(f"📊 攻击:{stats['total_attacks']} | IP:{stats['unique_ips']} | 账号:{len(accts)} | 蜜罐:{stats['active_honeypots']}")
        generate_map_data(df)
        export_csv(df)
        generate_html(df, stats, accts, wc)
        print("✨ v7.0 完成！")
    else:
        print("⚠️ 无数据")

if __name__ == "__main__":
    main()