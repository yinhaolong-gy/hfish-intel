#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFish 威胁情报报告 — HTTP API 服务

提供 HTTP 接口触发报告生成，零外部依赖（基于 http.server）。
可配合 supervisor/systemd 管理进程生命周期。

用法:
  python api_server.py                  # 默认 0.0.0.0:8080
  python api_server.py --port 9090      # 自定义端口
  python api_server.py --host 127.0.0.1 # 仅本地访问
"""

import argparse
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

from config import DAYS_RANGE
from data_collector import fetch_attack_logs, fetch_accounts, fetch_all_attack_logs, fetch_all_accounts
from data_analyzer import process_data, compare_weeks, generate_map_data
from report_generator import export_csv, generate_html


class ReportAPIHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path.rstrip("/")

        if path == "/health":
            self._json_response({"status": "ok", "service": "hfish-report"})
        elif path == "/report":
            self._run_report(params)
        else:
            self._json_response({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/report":
            self._run_report({})
        else:
            self._json_response({"error": "not found"}, 404)

    def _run_report(self, params):
        """执行报告生成流程"""
        try:
            days = int(params.get("days", [DAYS_RANGE])[0])
            multi = params.get("multi", ["0"])[0] in ("1", "true")

            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            last_week_end = start_time
            last_week_start = last_week_end - timedelta(days=7)

            self.server.log_message("开始生成报告 (days=%d, multi=%s)", days, multi)

            if multi:
                logs = fetch_all_attack_logs(start_time, end_time)
                last_week_logs = fetch_all_attack_logs(last_week_start, last_week_end)
                accounts = fetch_all_accounts()
            else:
                logs = fetch_attack_logs(start_time, end_time)
                last_week_logs = fetch_attack_logs(last_week_start, last_week_end)
                accounts = fetch_accounts()

            if not logs:
                self._json_response({"success": False, "error": "未拉取到攻击数据"})
                return

            df, stats = process_data(logs, start_time=start_time, end_time=end_time)
            week_compare = compare_weeks(df, last_week_logs, end_time=end_time)
            map_data = generate_map_data(df)

            export_csv(df)
            generate_html(df, stats, accounts, week_compare, map_data)

            self._json_response({
                "success": True,
                "summary": {
                    "attacks": len(logs),
                    "accounts": len(accounts),
                    "days": days,
                },
                "output": "docs/index.html",
            })
        except Exception as e:
            self.server.log_message("报告生成失败: %s", str(e))
            self._json_response({"success": False, "error": str(e)}, 500)

    def _json_response(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            fmt % args,
        ))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="HFish 报告 API 服务")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    parser.add_argument("--port", type=int, default=8080, help="监听端口（默认 8080）")
    return parser.parse_args(argv)


def main():
    args = parse_args()
    server = HTTPServer((args.host, args.port), ReportAPIHandler)
    print(f"🚀 HFish 报告 API 服务已启动: http://{args.host}:{args.port}")
    print("   接口列表:")
    print("     GET  /health          — 健康检查")
    print("     GET  /report?days=7   — 触发报告生成")
    print("     POST /report          — 同上（POST 方式）")
    print("   按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
        server.server_close()


if __name__ == "__main__":
    main()
