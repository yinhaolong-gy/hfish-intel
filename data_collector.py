#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — 数据采集模块

从 HFish API 拉取攻击日志和账号资产数据。
"""

import requests
import urllib3

from config import HFISH_BASE_URL, API_KEY, PAGE_SIZE, REQUEST_TIMEOUT, INSTANCES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_attack_logs(start_ts, end_ts):
    """从 HFish API 拉取攻击日志"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/detail"
    try:
        r = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            params={"api_key": API_KEY},
            json={
                "start_time": int(start_ts.timestamp()),
                "end_time": int(end_ts.timestamp()),
                "page": 1,
                "page_size": PAGE_SIZE,
            },
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if r.json().get("response_code") == 0:
            return r.json().get("data", [])
    except Exception as e:
        print(f"API请求失败: {e}")
    return []


def fetch_accounts():
    """从 HFish API 拉取账号资产数据"""
    url = f"{HFISH_BASE_URL}/api/v1/attack/account"
    try:
        r = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            params={"api_key": API_KEY},
            json={
                "page": 1,
                "page_size": PAGE_SIZE,
            },
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if r.json().get("response_code") == 0:
            return r.json().get("data", [])
    except Exception as e:
        print(f"账号API请求失败: {e}")
    return []


# ==================== 多实例聚合 ====================

def fetch_all_attack_logs(start_ts, end_ts):
    """遍历所有 HFish 实例，汇总攻击日志（按 attack_ip + create_time 去重）"""
    all_data = []
    seen = set()

    for inst in INSTANCES:
        url = f"{inst['url']}/api/v1/attack/detail"
        try:
            r = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                params={"api_key": inst["api_key"]},
                json={
                    "start_time": int(start_ts.timestamp()),
                    "end_time": int(end_ts.timestamp()),
                    "page": 1,
                    "page_size": PAGE_SIZE,
                },
                verify=False,
                timeout=REQUEST_TIMEOUT,
            )
            if r.json().get("response_code") == 0:
                data = r.json().get("data", [])
                for d in data:
                    key = (d.get("attack_ip", ""), d.get("create_time", ""))
                    if key not in seen:
                        seen.add(key)
                        all_data.append(d)
                print(f"  实例 [{inst['name']}]: {len(data)} 条")
        except Exception as e:
            print(f"  实例 [{inst['name']}] 请求失败: {e}")

    return all_data


def fetch_all_accounts():
    """遍历所有 HFish 实例，汇总账号资产数据（按 username + password 去重）"""
    all_data = []
    seen = set()

    for inst in INSTANCES:
        url = f"{inst['url']}/api/v1/attack/account"
        try:
            r = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                params={"api_key": inst["api_key"]},
                json={"page": 1, "page_size": PAGE_SIZE},
                verify=False,
                timeout=REQUEST_TIMEOUT,
            )
            if r.json().get("response_code") == 0:
                data = r.json().get("data", [])
                for d in data:
                    key = (d.get("username", ""), d.get("password", ""))
                    if key not in seen:
                        seen.add(key)
                        all_data.append(d)
                print(f"  实例 [{inst['name']}]: {len(data)} 条账号")
        except Exception as e:
            print(f"  实例 [{inst['name']}] 请求失败: {e}")

    return all_data
