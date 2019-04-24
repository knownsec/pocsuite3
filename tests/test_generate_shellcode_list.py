import unittest

from pocsuite3.lib.core.enums import OS, OS_ARCH
from pocsuite3.lib.utils import generate_shellcode_list


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_windows_shellcode(self):
        _list = generate_shellcode_list(listener_ip='127.0.0.1', listener_port=8088)
        self.assertTrue(len(_list) > 0)

    def test_linux_shellcode(self):
        _list = generate_shellcode_list(listener_ip='127.0.0.1', listener_port=8088, os_target=OS.LINUX,
                                        os_target_arch=OS_ARCH.X86)
        self.assertTrue(len(_list) > 0)
