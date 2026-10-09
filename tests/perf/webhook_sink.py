#!/usr/bin/env python3
# W5 D5 聚合降噪验证用 webhook 接收端。
# 用法: python3 tests/perf/webhook_sink.py <port> <out.jsonl>
# 每个 POST 把原始 JSON body 追加一行到 out 文件，回 200；计数/对账由调用方离线分析。
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    port = int(sys.argv[1])
    out_path = sys.argv[2]

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(n)
            with open(out_path, 'ab') as f:
                f.write(body + b'\n')
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()


if __name__ == '__main__':
    main()
