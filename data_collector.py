#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — 数据采集模块

从 HFish API 拉取攻击日志和账号资产数据。
支持自动分页和按天分批拉取。
"""

import requests
import urllib3
from datetime import timedelta

from config import HFISH_BASE_URL, API_KEY, PAGE_SIZE, REQUEST_TIMEOUT, INSTANCES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _paginated_fetch(url, api_key, base_json, desc="", max_pages=200):
    """通用分页请求"""
    all_data = []
    page = 1
    while page <= max_pages:
        json_data = {**base_json, "page": page}
        try:
            r = requests.post(
                url, headers={"Content-Type": "application/json"},
                params={"api_key": api_key}, json=json_data,
                verify=False, timeout=REQUEST_TIMEOUT,
            )
            resp = r.json()
            if resp.get("response_code") != 0:
                break
            data = resp.get("data", [])
            if not data:
                break
            all_data.extend(data)
            if len(data) < PAGE_SIZE:
                break
            page += 1
        except Exception as e:
            print(f"  请求失败 (page {page}): {e}")
            break
    if desc:
        print(f"  {desc}: {len(all_data)} 条（共 {page} 页）")
    return all_data


def fetch_attack_logs(start_ts, end_ts):
    """按天分批拉取攻击日志，避免某天数据填满分页配额"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    all_data = []
    seen = set()
    current = start_ts
    while current < end_ts:
        day_end = min(current + timedelta(days=1), end_ts)
        day_data = _paginated_fetch(
            url, API_KEY,
            {"start_time": int(current.timestamp()),
             "end_time": int(day_end.timestamp()),
             "page_size": PAGE_SIZE},
            desc=f"  {current.strftime('%m-%d')}",
            max_pages=2,
        )
        for d in day_data:
            key = (d.get("attack_ip", ""), d.get("create_time", ""))
            if key not in seen:
                seen.add(key)
                all_data.append(d)
        current = day_end
    print(f"  单实例攻击日志（按天分批）: {len(all_data)} 条")
    return all_data


def fetch_accounts():
    """从 HFish API 拉取账号资产数据"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    return _paginated_fetch(
        url, API_KEY, {"page_size": PAGE_SIZE},
        desc="单实例账号数据", max_pages=1,
    )


def fetch_all_attack_logs(start_ts, end_ts):
    """多实例聚合（按天分批）"""
    all_data = []
    seen = set()
    for inst in INSTANCES:
        url = f"{inst['url']}/api/v1/attack/detail"
        current = start_ts
        while current < end_ts:
            day_end = min(current + timedelta(days=1), end_ts)
            day_data = _paginated_fetch(
                url, inst["api_key"],
                {"start_time": int(current.timestamp()),
                 "end_time": int(day_end.timestamp()),
                 "page_size": PAGE_SIZE},
                max_pages=2,
            )
            for d in day_data:
                key = (d.get("attack_ip", ""), d.get("create_time", ""))
                if key not in seen:
                    seen.add(key)
                    all_data.append(d)
            current = day_end
        print(f"  实例 [{inst['name']}]: 去重后累计 {len(all_data)} 条")
    return all_data


def fetch_all_accounts():
    """多实例账号数据聚合"""
    all_data = []
    seen = set()
    for inst in INSTANCES:
        url = f"{inst['url']}/api/v1/attack/account"
        data = _paginated_fetch(
            url, inst["api_key"], {"page_size": PAGE_SIZE}, max_pages=1,
        )
        for d in data:
            key = (d.get("username", ""), d.get("password", ""))
            if key not in seen:
                seen.add(key)
                all_data.append(d)
        print(f"  实例 [{inst['name']}]: {len(data)} 条账号（去重后累计 {len(all_data)} 条）")
    return all_data
