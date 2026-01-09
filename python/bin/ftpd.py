#!/usr/bin/env python3
# ftpd.py  —— 带 UTF-8 文件名支持的“一键 FTP”
import os, sys
from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.filesystems import AbstractedFS

class UTF8FS(AbstractedFS):
    encoding = 'utf-8'          # 关键：路径用 UTF-8 编解码

class UTF8Handler(FTPHandler):
    filesystem = UTF8FS         # 1. 这里指向刚写好的 UTF8FS
    encoding = 'utf-8'          # 2. 同时把 handler 自身的编码也设成 utf-8

    # 下面照旧，支持客户端 OPTS UTF8 ON
    proto_cmds = FTPHandler.proto_cmds.copy()
    proto_cmds['OPTS'] = dict(perm='l', auth=False, arg=True,
                              help='OPTS UTF8 ON')

    def ftp_OPTS(self, line):
        if line.upper() == 'UTF8 ON':
            self.respond('200 UTF8 mode enabled.')
        else:
            self.respond('501 Unsupported option.')

if __name__ == '__main__':
    port  = int(sys.argv[1]) if len(sys.argv) > 1 else 2121
    user  = sys.argv[2] if len(sys.argv) > 2 else 'anonymous'
    pwd   = sys.argv[3] if len(sys.argv) > 3 else ''
    write = '-w' in sys.argv

    authorizer = UTF8Handler.authorizer
    if user != 'anonymous':
        authorizer.add_user(user, pwd, os.getcwd(), perm='elradfmwMT')
    else:
        authorizer.add_anonymous(os.getcwd(), perm='elr' + ('adfmwMT' if write else ''))

    server = FTPServer(('0.0.0.0', port), UTF8Handler)
    print(f'Serving UTF-8 FTP on 0.0.0.0:{port}  root={os.getcwd()}')
    server.serve_forever()
