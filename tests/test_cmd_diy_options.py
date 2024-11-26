#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/2/26 4:34 PM
# @Author  : chenghs
# @File    : test_cmd_diy_options.py
import os
import unittest
import warnings

from urllib3.exceptions import InsecureRequestWarning


class TestCase(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", InsecureRequestWarning)

    def tearDown(self):
        pass

    def verify_result(self):
        pass

    def test_cmd_run(self):
        path = os.path.dirname(os.path.realpath(__file__))

        eval_path = os.path.join(path, "../pocsuite3/cli.py")
        poc_path = os.path.join(path, "login_demo.py")
        command = (
            f'python3 {eval_path} -u http://httpbin.org/post -r {poc_path} --verify -v 2  --password mypass123 '
            '--username "asd asd" --testt abctest'
        )
        pipeline = os.popen(command)
        res = pipeline.buffer.read().decode('utf-8')
        self.assertTrue('1 / 1' in res)
