#!usr/bin/env python  
# -*- coding:utf-8 -*-
""" 
@author: longofo
@file: test_httpserver.py 
@time: 2019/03/31 
"""
import unittest
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from pocsuite3.lib.core.common import get_host_ip, get_host_ipv6
from pocsuite3.lib.core.data import logger
from pocsuite3.modules.httpserver import PHTTPServer, BaseRequestHandler


class TestCase(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", InsecureRequestWarning)

    def tearDown(self):
        pass

    def test_singleton(self):
        logger.info("Test http server is singleton")
        httpd1 = PHTTPServer()
        httpd2 = PHTTPServer()
        self.assertEqual(id(httpd1), id(httpd2))

    def test_ipv4(self):
        logger.info('Test http server in ipv4')
        PHTTPServer._instance = None
        httpd = PHTTPServer(bind_ip='0.0.0.0', bind_port=666, requestHandler=BaseRequestHandler)
        httpd.start()
        try:
            url = '{}://{}:{}/'.format('http', get_host_ip(), 666)
            resp = requests.get(url)
            self.assertEqual(resp.status_code, 200)
        except Exception:
            assert False
        finally:
            httpd.stop()

    def test_ipv6(self):
        logger.info('Test http server in ipv6')
        PHTTPServer._instance = None
        httpd = PHTTPServer(bind_ip='::', bind_port=666, requestHandler=BaseRequestHandler)
        httpd.start()
        try:
            url = '{}://{}:{}/'.format('http', '[{}]'.format(get_host_ipv6(get_host_ip())), 666)
            resp = requests.get(url)
            self.assertEqual(resp.status_code, 200)
        except Exception:
            assert False
        finally:
            httpd.stop()

    def test_ipv4_https(self):
        logger.info('Test https server in ipv4')
        PHTTPServer._instance = None
        httpd = PHTTPServer(bind_ip='0.0.0.0', bind_port=666, use_https=True,
                            requestHandler=BaseRequestHandler)
        httpd.start()
        try:
            url = '{}://{}:{}/'.format('https', get_host_ip(), 666)
            requests.get(url)
        except requests.exceptions.SSLError:
            url = '{}://{}:{}/'.format('https', get_host_ip(), 666)
            resp = requests.get(url, verify=False)
            self.assertEqual(resp.status_code, 200)
        except Exception:
            assert False
        finally:
            httpd.stop()

    def test_ipv6_https(self):
        logger.info('Test https server in ipv6')
        PHTTPServer._instance = None
        httpd = PHTTPServer(bind_ip='::', bind_port=666, use_https=True,
                            requestHandler=BaseRequestHandler)
        httpd.start()
        try:
            url = '{}://{}:{}/'.format('https', '[{}]'.format(get_host_ipv6(get_host_ip())), 666)
            requests.get(url)
        except requests.exceptions.SSLError:
            url = '{}://{}:{}/'.format('https', '[{}]'.format(get_host_ipv6(get_host_ip())), 666)
            resp = requests.get(url, verify=False)
            self.assertEqual(resp.status_code, 200)
        except Exception:
            assert False
        finally:
            httpd.stop()
