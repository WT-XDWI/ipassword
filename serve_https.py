#!/usr/bin/env python3
"""
iPassword 本地服务（HTTPS 版）

为什么需要服务而不是直接打开 index.html：
  Web Crypto API（crypto.getRandomValues）在 file:// 下可能受限，
  且多数浏览器要求「安全上下文」才完整支持。HTTPS 和 localhost 都满足。

为什么用 HTTPS 而不是 HTTP：
  密码在浏览器里生成后要显示给用户。若走 HTTP，局域网内任何人都能
  抓包看到页面内容和生成的密码。HTTPS 让整条链路加密。

自签证书的说明：
  证书是自己签的，浏览器首次访问会提示「不安全」。这是正常的，
  选择「继续访问」即可。想彻底消除提示需要受信任的 CA 证书（要域名）。
"""
import http.server
import socketserver
import ssl
import os
import socket
import sys

PORT = 8443
ROOT = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(ROOT, 'certs', 'server.crt')
KEY = os.path.join(ROOT, 'certs', 'server.key')


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = dict(http.server.SimpleHTTPRequestHandler.extensions_map)
    extensions_map['.html'] = 'text/html; charset=utf-8'
    extensions_map['.js'] = 'text/javascript; charset=utf-8'
    extensions_map['.css'] = 'text/css; charset=utf-8'
    extensions_map['.svg'] = 'image/svg+xml'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def send_head(self):
        # 只放出 index.html 与静态资源，不暴露服务脚本和私钥目录
        rel = self.path.split('?')[0].lstrip('/')
        if rel in ('', 'index.html'):
            return super().send_head()
        self.send_error(404, 'Not Found')
        return None

    def end_headers(self):
        # 密码生成器：禁止缓存，避免密码留在浏览器磁盘缓存里
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')

        # 安全响应头
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        # 禁止页面发起任何外部请求（这个页面本来就不需要联网）
        self.send_header('Content-Security-Policy',
                         "default-src 'self'; "
                         "script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; "
                         "connect-src 'none'; "
                         "form-action 'none'; "
                         "frame-ancestors 'none'")

        # HSTS：告诉浏览器以后只用 HTTPS（自签证书下浏览器仍会警告，但策略本身正确）
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        super().end_headers()

    def log_message(self, fmt, *args):
        # 不记录访问日志，避免把 URL 写进日志文件
        if args and str(args[1]).startswith(('4', '5')):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


def main():
    if not os.path.exists(CERT) or not os.path.exists(KEY):
        print('  找不到证书，请先生成：')
        print('  mkdir -p certs && openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \\')
        print('    -keyout certs/server.key -out certs/server.crt \\')
        print('    -subj "/CN=你的IP" -addext "subjectAltName=IP:你的IP"')
        sys.exit(1)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    port = PORT
    for _ in range(20):
        try:
            httpd = Server(('0.0.0.0', port), Handler)
            break
        except OSError:
            port += 1
    else:
        print('  端口被占用')
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)

    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    ip = local_ip()
    print()
    print('  ================================================')
    print('   iPassword  （HTTPS）')
    print('  ================================================')
    print()
    print(f'   本机访问：   https://127.0.0.1:{port}/index.html')
    if ip != '127.0.0.1':
        print(f'   局域网访问： https://{ip}:{port}/index.html')
    print()
    print('   首次访问会提示证书不受信任 —— 这是自签证书的正常现象，')
    print('   选择「高级」→「继续前往」即可。')
    print()
    print('   按 Ctrl+C 停止服务')
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\n  已停止')
        httpd.shutdown()


if __name__ == '__main__':
    main()
