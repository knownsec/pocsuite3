import os
import unittest
from pocsuite3.api import init_pocsuite
from pocsuite3.api import start_pocsuite
from pocsuite3.api import get_results
from pocsuite3.api import paths
import requests


class TestCase(unittest.TestCase):
    def setUp(self):
        self.proxy = "socks5://127.0.0.1:1080"

    def tearDown(self):
        pass

    def test_requests(self):
        resp = requests.get('https://www.google.com',
                            proxies=dict(http=self.proxy,
                                         https=self.proxy))
        print(resp.text)

    def test_socks5(self):
        proxy = "socks5://127.0.0.1:1080"
        proxy_cred = "username:password"
        config = {
            'url': ['https://www.baidu.com/'],
            'poc': [os.path.join(paths.POCSUITE_ROOT_PATH, "../tests/login_demo.py")],
            'username': "asd",
            'password': 'asdss',
            'verbose': 0,
            "timeout": 30,
            "proxy": proxy,
            "proxy_cred": proxy_cred
        }
        init_pocsuite(config)
        start_pocsuite()
        result = get_results().pop()
        self.assertTrue(result.status == 'success')
