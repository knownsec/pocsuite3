#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import unittest


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def verify_result(self):
        pass

    def test_cmd_run(self):
        command = 'pocsuite -r ecshop_rce.py --options'
        res = os.popen(command).read()
        self.assertTrue('You can select dict_keys' in res)
