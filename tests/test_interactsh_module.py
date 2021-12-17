#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pocsuite3.api import Interactsh, requests


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @unittest.skip(reason='interactsh service is unstable')
    def test_interactsh(self):
        ISH = Interactsh(token="", server="")
        url, flag = ISH.build_request(method='https')
        requests.get(url, timeout=5, verify=False)
        self.assertTrue(ISH.verify(flag))


if __name__ == '__main__':
    unittest.main()
