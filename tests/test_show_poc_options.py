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
        pipeline = os.popen('pocsuite -k ecshop --options')

        # os.popen default encoding may not be utf-8
        res = pipeline.buffer.read().decode('utf-8')

        self.assertTrue('You can select dict_keys' in res)
