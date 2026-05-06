#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报自动化生成脚本 v6.2
地图修复版：完整国家名称映射
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
OUTPUT_FILE = "index.html"
CSV_FILE = "threat_data.csv"

def fetch_attack_logs(start_ts, end_ts):
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    params = {"api_key": API_KEY}
    payload = {"start_time": int(start_ts.timestamp()), "end_time": int(end_ts.timestamp()), "page": 1, "page_size": 5000}
    try:
        r = requests.post(url, headers={"Content-Type": "application/json"}, params=params, json=payload, verify=False, timeout=30)
        if r.json().get("response_code") == 0:
            return r.json().get("data", [])
    except: pass
    return []

def fetch_accounts():
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    try:
        r = requests.post(url, headers={"Content-Type": "application/json"}, params={"api_key": API_KEY}, json={"page": 1, "page_size": 5000}, verify=False, timeout=30)
        if r.json().get("response_code") == 0:
            return r.json().get("data", [])
    except: pass
    return []

def process_data(raw_logs):
    if not raw_logs: return pd.DataFrame(), {}
    df = pd.DataFrame(raw_logs)
    cols = [c for c in ["attack_ip","ip_location","client_name","service_name","service_port","create_time"] if c in df.columns]
    df = df[cols].copy()
    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit='s').dt.strftime("%Y-%m-%d %H:%M")
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x)
    all_hp = ["SSH蜜罐","TCP端口监听","Elasticsearch蜜罐","Telnet蜜罐","FTP蜜罐","HTTP代理蜜罐","MYSQL蜜罐","REDIS蜜罐","Tomcat蜜罐","Weblogic蜜罐"]
    hp_data = {hp: (df["service_name"].value_counts().to_dict() if "service_name" in df.columns else {}).get(hp, 0) for hp in all_hp}
    heatmap = [0]*24
    if "hour" in df.columns:
        for h, c in df["hour"].value_counts().to_dict().items(): heatmap[int(h)] = c
    port_top = df["service_port"].value_counts().head(10).to_dict() if "service_port" in df.columns else {}
    return df, {
        "total_attacks": len(df),
        "unique_ips": df["attack_ip"].nunique() if "attack_ip" in df.columns else 0,
        "top_ips": df["attack_ip"].value_counts().head(10).to_dict() if "attack_ip" in df.columns else {},
        "top_services": df["service_name"].value_counts().head(10).to_dict() if "service_name" in df.columns else {},
        "top_countries": df["country"].value_counts().head(10).to_dict() if "country" in df.columns else {},
        "top_ports": port_top, "honeypot_data": hp_data,
        "active_honeypots": sum(1 for v in hp_data.values() if v>0),
        "heatmap_data": heatmap,
        "time_range": f"{START_TIME.strftime('%Y-%m-%d %H:%M')} ~ {END_TIME.strftime('%Y-%m-%d %H:%M')}"
    }

# ★★★ 完整国家映射表 ★★★
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
    countries = []
    for k, v in cc.items():
        en = COUNTRY_MAP.get(k)
        if en: countries.append({"name": en, "value": v})
    mx = max(cc.values()) if cc else 1
    with open(os.path.join(OUTPUT_DIR, "country_data.json"), "w", encoding="utf-8") as f:
        json.dump({"countries": countries, "maxCount": mx}, f, ensure_ascii=False)

def export_csv(df):
    if not df.empty:
        e = df[["attack_ip","ip_location","service_name","service_port","create_time"]].head(500).copy()
        e.columns = ["攻击源IP","地理位置","服务类型","端口","攻击时间"]
        e.to_csv(os.path.join(OUTPUT_DIR, CSV_FILE), index=False, encoding="utf-8-sig")

def generate_chart_data(df):
    if "create_time" in df.columns and not df.empty:
        df["date"] = pd.to_datetime(df["create_time"]).dt.strftime("%m-%d")
        d = df["date"].value_counts().sort_index()
        return json.dumps({"dates": d.index.tolist()[-7:], "counts": d.values.tolist()[-7:]})
    return json.dumps({"dates":[],"counts":[]})

def compare_weeks(cur, last):
    if last:
        ch = len(cur) - len(last)
        return {"current":len(cur),"last":len(last),"change":ch,"trend":"上升" if ch>0 else ("下降" if ch<0 else "持平")}
    return {"current":len(cur),"last":0,"change":0,"trend":"无对比数据"}

def generate_html(df, stats, accounts, wc):
    t = Template("""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HFish 威胁情报监控中心</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<style>
:root{--bg:#0a0a14;--card:rgba(255,255,255,0.04);--p:#00d4ff;--a:#7c3aed;--t:#e2e8f0;--m:#94a3b8;--b:rgba(0,212,255,0.12)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(135deg,#0a0a14,#0f172a 40%,#1e1b4b 70%,#0a0a14);min-height:100vh;padding:15px;color:var(--t)}
.container{max-width:1440px;margin:0 auto}
.header{text-align:center;padding:25px 20px;margin-bottom:25px;background:linear-gradient(135deg,rgba(0,212,255,0.08),rgba(124,58,237,0.06));border-radius:20px;border:1px solid var(--b)}
.header h1{font-size:clamp(1.5em,4vw,2.5em);background:linear-gradient(135deg,var(--p),var(--a));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .sub{color:var(--m);font-size:.85em;margin-top:6px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:25px}
.sc{background:var(--card);border:1px solid var(--b);border-radius:14px;padding:18px 12px;text-align:center;transition:all .3s}
.sc:hover{transform:translateY(-4px);border-color:var(--p)}
.sn{font-size:clamp(1.6em,3vw,2.2em);font-weight:700;color:var(--p)}
.sl{color:var(--m);font-size:.78em;margin-top:4px}
.section{background:rgba(255,255,255,0.02);border:1px solid var(--b);border-radius:16px;padding:20px;margin-bottom:20px}
.st{font-size:1.15em;color:var(--p);margin-bottom:16px;border-bottom:1px solid var(--b);padding-bottom:10px}
.cb{width:100%;height:350px}.mb{width:100%;height:480px}.hb{width:100%;height:280px}
.hg{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px}
.hi{background:rgba(0,212,255,0.05);border:1px solid var(--b);border-radius:12px;padding:14px;text-align:center;transition:all .3s}
.hi:hover{transform:translateY(-2px);border-color:var(--p)}
.hn{color:var(--m);font-size:.72em}.hc{font-size:1.5em;font-weight:700;color:var(--p)}.hz{color:#475569}
.tl{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}
.li{background:rgba(0,0,0,0.3);border:1px solid rgba(0,212,255,0.06);border-radius:12px;padding:16px}
.li h3{color:var(--p);font-size:.95em;margin-bottom:10px}
.rr{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:.82em}
.rv{font-weight:700;color:var(--p)}
table{width:100%;border-collapse:collapse;font-size:.82em;margin-top:10px}
th{background:rgba(0,212,255,0.1);color:var(--p);padding:10px;text-align:left}
td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,0.04)}
tr:hover td{background:rgba(0,212,255,0.03)}
.badge{background:rgba(0,212,255,0.12);color:var(--p);padding:3px 8px;border-radius:12px;font-size:.78em}
.footer{text-align:center;color:#555;margin-top:30px;font-size:.8em}
.warn{color:#f87171;font-weight:500}.up{color:#4ade80}.down{color:#f87171}
.cr{display:flex;gap:20px;justify-content:center;flex-wrap:wrap}
.ci{background:rgba(0,0,0,0.3);border-radius:12px;padding:15px 22px;text-align:center}
.cn{font-size:1.8em;font-weight:700}.cl{color:var(--m);font-size:.75em}
@media(max-width:768px){.cb{height:250px}.mb{height:350px}.sg{grid-template-columns:repeat(3,1fr)}}
@media(max-width:480px){.sg{grid-template-columns:repeat(2,1fr)}.header h1{font-size:1.3em}}
</style></head><body><div class="container">
<div class="header"><h1>🛡️ HFish 威胁情报监控中心</h1><p class="sub">📊 {{ stats.time_range }} | 更新: {{ last_update }}</p></div>
<div class="sg">
<div class="sc"><div class="sn">{{ stats.total_attacks }}</div><div class="sl">总攻击次数</div></div>
<div class="sc"><div class="sn">{{ stats.unique_ips }}</div><div class="sl">独立IP</div></div>
<div class="sc"><div class="sn">{{ account_count }}</div><div class="sl">账号资产</div></div>
<div class="sc"><div class="sn">{{ stats.active_honeypots }}</div><div class="sl">活跃蜜罐</div></div>
<div class="sc"><div class="sn">{{ wc.current }}</div><div class="sl">本周攻击</div></div>
<div class="sc"><div class="sn {{ 'up' if wc.trend=='上升' else 'down' if wc.trend=='下降' else '' }}">{{ wc.change }}{% if wc.change>0 %}+{% endif %}</div><div class="sl">{{ wc.trend }}</div></div>
</div>
<div class="section"><h2 class="st">📈 攻击趋势（近7天）</h2><div class="cb"><canvas id="tc"></canvas></div></div>
<div class="section"><h2 class="st">🔥 攻击时段分布</h2><div class="hb"><canvas id="hc"></canvas></div></div>
<div class="section"><h2 class="st">📊 本周 vs 上周</h2><div class="cr">
<div class="ci"><div class="cn" style="color:var(--p)">{{ wc.current }}</div><div class="cl">本周</div></div>
<div class="ci"><div class="cn" style="color:var(--m)">{{ wc.last }}</div><div class="cl">上周</div></div>
<div class="ci"><div class="cn {{ 'up' if wc.trend=='上升' else 'down' if wc.trend=='下降' else '' }}">{{ wc.change }}{% if wc.change>0 %}+{% endif %}</div><div class="cl">{{ wc.trend }}</div></div>
</div></div>
<div class="section"><h2 class="st">🗺️ 攻击来源全球分布</h2><div class="mb" id="wm"></div></div>
<div class="section"><h2 class="st">🎯 各蜜罐攻击次数</h2><div class="hg">
{% for n,c in stats.honeypot_data.items() %}<div class="hi"><div class="hn">{{ n }}</div><div class="hc {% if c==0 %}hz{% endif %}">{{ c }}</div></div>{% endfor %}
</div></div>
<div class="section"><h2 class="st">📊 攻击统计分析</h2><div class="tl">
<div class="li"><h3>🔝 Top 10 IP</h3>{% for ip,c in stats.top_ips.items() %}<div class="rr"><span>{{ ip }}</span><span class="rv">{{ c }}</span></div>{% endfor %}</div>
<div class="li"><h3>🌍 来源国家</h3>{% for ct,c in stats.top_countries.items() %}<div class="rr"><span>{{ ct }}</span><span class="rv">{{ c }}</span></div>{% endfor %}</div>
<div class="li"><h3>🔑 弱口令 TOP 10</h3>{% for p,c in tp %}<div class="rr"><span class="warn">{{ p }}</span><span class="rv">{{ c }}</span></div>{% endfor %}{% if not tp %}<div class="rr"><span>暂无数据</span></div>{% endif %}</div>
<div class="li"><h3>👤 用户名 TOP 5</h3>{% for u,c in tu %}<div class="rr"><span>{{ u }}</span><span class="rv">{{ c }}</span></div>{% endfor %}</div>
<div class="li"><h3>🔌 端口 TOP 10</h3>{% for p,c in stats.top_ports.items() %}<div class="rr"><span>端口 {{ p }}</span><span class="rv">{{ c }}</span></div>{% endfor %}</div>
</div></div>
<div class="section"><h2 class="st">📋 最新攻击记录</h2><div style="overflow-x:auto;max-height:380px;overflow-y:auto">
<table><thead><tr><th>IP</th><th>位置</th><th>服务</th><th>端口</th><th>时间</th></tr></thead><tbody>
{% for _,r in df.head(100).iterrows() %}<tr><td><span class="badge">{{ r.get('attack_ip','-') }}</span></td><td>{{ r.get('ip_location','-') }}</td><td>{{ r.get('service_name','-') }}</td><td>{{ r.get('service_port','-') }}</td><td>{{ r.get('create_time','-') }}</td></tr>{% endfor %}
</tbody></table></div></div>
<div class="footer"><p>🤖 HFish自动采集 | 每6小时更新 | 毕业设计作品 | {{ last_update }}</p></div>
</div>
<script>
new Chart(document.getElementById('tc'),{type:'line',data:{labels:{{ cd|safe }}.dates,datasets:[{label:'攻击次数',data:{{ cd|safe }}.counts,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.08)',fill:true,tension:.4,pointRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'}},y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'},beginAtZero:true}}}});
new Chart(document.getElementById('hc'),{type:'bar',data:{labels:['0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23'].map(x=>x+'时'),datasets:[{label:'攻击次数',data:{{ hd|safe }},backgroundColor:function(c){var v=c.raw;return v>200?'#7c3aed':v>100?'#00d4ff':v>50?'#0284c7':'#0d47a1'},borderRadius:5}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},y:{ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.04)'},beginAtZero:true}}}});
(function(){var d=document.getElementById('wm'),m=echarts.init(d);fetch('country_data.json').then(r=>r.json()).then(data=>{m.setOption({tooltip:{trigger:'item',formatter:p=>'<b>'+p.name+'</b><br/>攻击: '+(p.value||0)+' 次'},visualMap:{min:0,max:data.maxCount||100,text:['高','低'],realtime:false,calculable:true,inRange:{color:['#1a1a3e','#0d47a1','#1565c0','#00d4ff']},textStyle:{color:'#94a3b8'}},series:[{type:'map',map:'world',roam:true,emphasis:{label:{show:true,color:'#fff'},itemStyle:{areaColor:'#00d4ff'}},itemStyle:{borderColor:'rgba(255,255,255,0.15)',areaColor:'#1a1a3e'},data:data.countries||[]}]})}).catch(()=>{m.setOption({series:[{type:'map',map:'world',roam:true,itemStyle:{borderColor:'rgba(255,255,255,0.15)',areaColor:'#1a1a3e'},data:[]}]})});window.addEventListener('resize',()=>m.resize())})();
</script></body></html>""")
    cd = generate_chart_data(df)
    hd = json.dumps(stats.get("heatmap_data", [0]*24))
    tp = Counter([a.get("password","") for a in accounts if a.get("password")]).most_common(10)
    tu = Counter([a.get("username","") for a in accounts if a.get("username")]).most_common(5)
    html = t.render(df=df, stats=stats, cd=cd, hd=hd, tp=tp, tu=tu, wc=wc, account_count=len(accounts), last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, OUTPUT_FILE), "w", encoding="utf-8") as f: f.write(html)

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
        print("✨ v6.2 完成!")
    else:
        print("⚠️ 无数据")

if __name__ == "__main__":
    main()
