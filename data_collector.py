#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — 数据采集模块

从 HFish API 拉取攻击日志和账号资产数据。
支持自动分页，确保获取完整数据。
"""

import requests
import urllib3

from config import HFISH_BASE_URL, API_KEY, PAGE_SIZE, REQUEST_TIMEOUT, INSTANCES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _paginated_fetch(url, api_key, base_json, desc="", max_pages=200):
    """通用分页请求，自动遍历所有页码（不依赖 total 字段）

    max_pages: 最大页数限制，防 OOM（账号数据建议 2-3 页）
    """
    all_data = []
    page = 1

    while page <= max_pages:
        json_data = {**base_json, "page": page}
        try:
            r = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                params={"api_key": api_key},
                json=json_data,
                verify=False,
                timeout=REQUEST_TIMEOUT,
            )
            resp = r.json()
            if resp.get("response_code") != 0:
                break

            data = resp.get("data", [])
            if not data:
                break

            all_data.extend(data)

            # 本页不足 page_size → 已是最后一页
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
    """从 HFish API 拉取攻击日志（自动分页）"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    return _paginated_fetch(
        url, API_KEY,
        {
            "start_time": int(start_ts.timestamp()),
            "end_time": int(end_ts.timestamp()),
            "page_size": PAGE_SIZE,
        },
        desc="单实例攻击日志",
    )


def fetch_accounts():
    """从 HFish API 拉取账号资产数据（限量分页，防内存溢出）"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    return _paginated_fetch(
        url, API_KEY,
        {"page_size": PAGE_SIZE},
        desc="单实例账号数据",
        max_pages=1,
    )


# ==================== 多实例聚合 ====================

def fetch_all_attack_logs(start_ts, end_ts):
    """遍历所有 HFish 实例，汇总攻击日志（按 attack_ip + create_time 去重）"""
    all_data = []
    seen = set()

    for inst in INSTANCES:
        url = f"{inst['url']}/api/v1/attack/detail"
        data = _paginated_fetch(
            url, inst["api_key"],
            {
                "start_time": int(start_ts.timestamp()),
                "end_time": int(end_ts.timestamp()),
                "page_size": PAGE_SIZE,
            },
        )
        for d in data:
            key = (d.get("attack_ip", ""), d.get("create_time", ""))
            if key not in seen:
                seen.add(key)
                all_data.append(d)
        print(f"  实例 [{inst['name']}]: {len(data)} 条（去重后累计 {len(all_data)} 条）")

    return all_data


def fetch_all_accounts():
    """遍历所有 HFish 实例，汇总账号资产数据（按 username + password 去重，限量分页）"""
    all_data = []
    seen = set()

    for inst in INSTANCES:
        url = f"{inst['url']}/api/v1/attack/account"
        data = _paginated_fetch(
            url, inst["api_key"],
            {"page_size": PAGE_SIZE},
            max_pages=1,
        )
        for d in data:
            key = (d.get("username", ""), d.get("password", ""))
            if key not in seen:
                seen.add(key)
                all_data.append(d)
        print(f"  实例 [{inst['name']}]: {len(data)} 条账号（去重后累计 {len(all_data)} 条）")

    return all_data
