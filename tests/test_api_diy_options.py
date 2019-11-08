import os
import unittest
from pocsuite3.api import init_pocsuite
from pocsuite3.api import start_pocsuite
from pocsuite3.api import get_results
from pocsuite3.api import paths


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def verify_result(self):
        config = {
            'url': ['https://www.baidu.com/'],
            'poc': [os.path.join(paths.POCSUITE_ROOT_PATH, "../tests/login_demo.py")],
            'username': "asd",
            'password': 'asdss',
            'verbose': 0,
            "timeout": 10,
        }
        init_pocsuite(config)
        start_pocsuite()
        result = get_results().pop()
        self.assertTrue(result.status == 'success')

    def test_cookie(self):
        config = {
            'url': ['http://httpbin.org/post'],
            'poc': [os.path.join(paths.POCSUITE_ROOT_PATH, "../tests/login_demo.py")],
            'username': "asd",
            'password': 'asdss',
            'cookie': 'test=1',
            'verbose': 0,
            "timeout": 10,
        }
        init_pocsuite(config)
        start_pocsuite()
        result = get_results().pop()
        self.assertTrue(result.status == 'success')

    def test_cookie_dict_params(self):
        config = {
            'url': ['http://httpbin.org/post'],
            'poc': [os.path.join(paths.POCSUITE_ROOT_PATH, "../tests/login_demo.py")],
            'username': "asd",
            'password': 'asdss',
            'cookie': {
                "test": '123'
            },
            'verbose': 0,
            "timeout": 10,
        }
        init_pocsuite(config)
        start_pocsuite()
        result = get_results().pop()
        self.assertTrue(result.status == 'success')

    def test_import_run(self):
        self.verify_result()
