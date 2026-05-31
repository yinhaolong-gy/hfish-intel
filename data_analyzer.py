#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — 数据处理与统计模块

清洗原始攻击日志，提取统计指标，生成图表数据和地图数据。
"""

import json
from datetime import datetime, timedelta

import pandas as pd

from config import START_TIME, END_TIME

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
    "欧洲地区": "Russia", "亚太地区": "China", "非洲地区": "South Africa",
}


def process_data(raw_logs, start_time=None, end_time=None):
    """清洗原始攻击日志，提取关键字段并统计

    参数:
        raw_logs: 原始API返回的攻击日志列表
        start_time: 统计时间范围起点（可选，默认用 config.START_TIME）
        end_time: 统计时间范围终点（可选，默认用 config.END_TIME）
    """
    if start_time is None:
        start_time = START_TIME
    if end_time is None:
        end_time = END_TIME

    if not raw_logs:
        return pd.DataFrame(), {}

    df = pd.DataFrame(raw_logs)
    keep_cols = ["attack_ip", "ip_location", "service_name", "service_port", "create_time"]
    df = df[[c for c in keep_cols if c in df.columns]].copy()

    # 时间处理
    if "create_time" in df.columns:
        df["create_time"] = pd.to_datetime(df["create_time"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
        df["hour"] = pd.to_datetime(df["create_time"]).dt.hour
        df["date"] = pd.to_datetime(df["create_time"]).dt.date

    # 地理位置提取
    if "ip_location" in df.columns:
        df["country"] = df["ip_location"].apply(
            lambda x: x.split("-")[0] if isinstance(x, str) and "-" in x else x
        )

    # 蜜罐类型统计
    all_hp = [
        "SSH蜜罐", "FTP蜜罐", "Telnet蜜罐", "HTTP代理蜜罐", "MYSQL蜜罐",
        "REDIS蜜罐", "Elasticsearch蜜罐", "CUSTOM蜜罐", "TCP端口监听", "Nginx蜜罐",
    ]
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
        "time_range": f"{start_time.strftime('%Y-%m-%d %H:%M')} ~ {end_time.strftime('%Y-%m-%d %H:%M')}",
    }


def generate_map_data(df):
    """生成世界地图数据，返回JSON字符串"""
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


def gen_chart_data(df, end_date=None):
    """生成近7天攻击趋势图数据（基于数据实际日期的日历周对齐）"""
    if "date" not in df.columns or df.empty:
        return json.dumps({"dates": [], "counts": [], "prev_counts": []})

    daily_counts = df.groupby("date")["attack_ip"].count()
    ref_date = end_date or max(daily_counts.index)

    this_week_dates = [ref_date - timedelta(days=i) for i in range(6, -1, -1)]
    last_week_dates = [ref_date - timedelta(days=i) for i in range(13, 6, -1)]

    this_week_counts = [int(daily_counts.get(d, 0)) for d in this_week_dates]
    last_week_counts = [int(daily_counts.get(d, 0)) for d in last_week_dates]

    date_labels = [d.strftime("%m-%d") for d in this_week_dates]

    return json.dumps({
        "dates": date_labels,
        "counts": this_week_counts,
        "prev_counts": last_week_counts,
    })


def compare_weeks(current_df, last_week_logs, end_time=None, fallback_last_count=0):
    """本周（近7天）与上周攻击数据对比

    参数:
        current_df: 当前时段攻击数据 DataFrame
        last_week_logs: 上周原始攻击日志列表
        end_time: 当前周期结束时间（默认使用 current_df 的最大日期）
    """
    if end_time is None:
        end_time = datetime.now()

    # 只取当前数据中最近7天用于对比
    if "date" in current_df.columns:
        week_ago = end_time.date() - timedelta(days=7)
        recent_df = current_df[current_df["date"] >= week_ago]
        current_count = len(recent_df)
    else:
        current_count = len(current_df)

    last_count = len(last_week_logs)
    if last_count == 0 and fallback_last_count > 0:
        last_count = fallback_last_count
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
        "trend": trend,
    }
