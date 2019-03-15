#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/2/26 4:34 PM
# @Author  : chenghs
# @File    : test_cmd_diy_options.py
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
        path = os.path.dirname(os.path.realpath(__file__))

        eval_path = os.path.join(path, "../pocsuite3/cli.py")
        poc_path = os.path.join(path, "login_demo.py")
        command = '''python3 {0} -u http://www.baidu.com -r {1} --verify -v 2  --password mypass123 --username "asd asd" --testt abctest'''.format(
            eval_path, poc_path)
        pipeline = os.popen(command)
        self.assertTrue('1 / 1' in pipeline.read())
