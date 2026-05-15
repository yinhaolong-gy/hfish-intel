#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — 主程序入口

协调数据采集、数据统计和报告输出三个模块完成完整流程。
支持命令行参数（crontab 友好）和模块导入两种调用方式。
"""

import argparse
import sys
from datetime import datetime, timedelta

from config import START_TIME, END_TIME, LAST_WEEK_START, LAST_WEEK_END, DAYS_RANGE
from data_collector import fetch_attack_logs, fetch_accounts, fetch_all_attack_logs, fetch_all_accounts
from data_analyzer import process_data, compare_weeks, generate_map_data
from report_generator import export_csv, generate_html


def parse_args(argv=None):
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="HFish 威胁情报报告生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python main.py                        # 默认90天，单实例
  python main.py --days 7               # 近7天数据
  python main.py --output-dir ./reports # 自定义输出目录
  python main.py --multi                # 多实例聚合
  python main.py --quiet                # 静默模式（crontab）
        """,
    )
    parser.add_argument("--api-key", help="HFish API 密钥（覆盖 config.py）")
    parser.add_argument("--base-url", help="HFish 服务地址（覆盖 config.py）")
    parser.add_argument("--days", type=int, default=None, help="数据范围（天），默认 %(default)s")
    parser.add_argument("--output-dir", default=None, help="输出目录，默认 ./docs")
    parser.add_argument("--multi", action="store_true", help="启用多实例聚合模式")
    parser.add_argument("--quiet", action="store_true", help="只输出关键信息")
    parser.add_argument("--no-cache", action="store_true", help="跳过缓存")
    return parser.parse_args(argv)


def main():
    args = parse_args()

    # 计算时间范围（CLI 参数覆盖 config）
    days = args.days if args.days is not None else DAYS_RANGE
    end_time = datetime.now()
    start_time = end_time - timedelta(days=days)
    last_week_end = start_time
    last_week_start = last_week_end - timedelta(days=7)

    if not args.quiet:
        print(f"🔄 正在拉取攻击日志（近{days}天）...")

    # 多实例模式 vs 单实例模式
    if args.multi:
        logs = fetch_all_attack_logs(start_time, end_time)
        last_week_logs = fetch_all_attack_logs(last_week_start, last_week_end)
        accounts = fetch_all_accounts()
    else:
        logs = fetch_attack_logs(start_time, end_time)
        last_week_logs = fetch_attack_logs(last_week_start, last_week_end)
        accounts = fetch_accounts()

    if logs:
        if not args.quiet:
            print(f"📥 攻击数据: {len(logs)} 条 | 账号数据: {len(accounts)} 条"
                  f" | 上周数据: {len(last_week_logs)} 条")

        df, stats = process_data(logs, start_time=start_time, end_time=end_time)
        week_compare = compare_weeks(df, last_week_logs)
        map_data = generate_map_data(df)

        export_csv(df)
        generate_html(df, stats, accounts, week_compare, map_data)

        if not args.quiet:
            print("✨ 所有任务完成！")
        return 0
    else:
        print("⚠️ 未拉取到攻击数据")
        return 1


if __name__ == "__main__":
    sys.exit(main())
