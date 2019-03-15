import os
import unittest
from pocsuite3.api import init_pocsuite
from pocsuite3.api import start_pocsuite
from pocsuite3.api import get_results
from pocsuite3.api import paths


class TestCase(unittest.TestCase):
    def setUp(self):
        self.config = {
            'url': 'https://www.baidu.com/',
            'poc': os.path.join(paths.POCSUITE_ROOT_PATH, "../tests/login_demo.py"),
            'username': "asd",
            'password': 'asdss',
            'verbose': 0
        }
        init_pocsuite(self.config)

    def tearDown(self):
        pass

    def verify_result(self):
        result = get_results().pop()
        self.assertTrue(result.status == 'success')

    def test_import_run(self):
        start_pocsuite()
        self.verify_result()
