import unittest
import os
from pocsuite3.api import OSShellcodes
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.enums import SHELLCODE_CONNECTION, OS, OS_ARCH


class TestCase(unittest.TestCase):
    def setUp(self):
        self.connect_back_ip = '127.0.0.1'
        self.bad_chars = ["\x00", "\x0a", "\x0d", "\x3b"]

        self.shellpath = os.path.join(paths.POCSUITE_TMP_PATH, "payload.jar")

    def tearDown(self):
        if os.path.exists(self.shellpath):
            os.unlink(self.shellpath)

    def test_win_x86_bind(self):
        os_target = OS.WINDOWS
        os_target_arch = OS_ARCH.X86
        dll_funcs = ["pcap_findalldevs", "pcap_close", "pcap_compile", "pcap_datalink",
                     "pcap_datalink_val_to_description",
                     "pcap_dump", "pcap_dump_close", "pcap_dump_open", "pcap_file", "pcap_freecode", "pcap_geterr",
                     "pcap_getevent", "pcap_lib_version", "pcap_lookupdev", "pcap_lookupnet", "pcap_loop",
                     "pcap_open_live",
                     "pcap_open_offline", "pcap_setfilter", "pcap_snapshot", "pcap_stats"]

        s = OSShellcodes(os_target, os_target_arch, self.connect_back_ip, 6666, self.bad_chars)
        connection_type = SHELLCODE_CONNECTION.BIND
        filename = 'osshell_x86_bind'
        filepath = os.path.join(paths.POCSUITE_TMP_PATH, filename) + '.exe'
        shellcode = s.create_shellcode(
            connection_type,
            encode='',
            make_exe=1,
            debug=0,
            # dll_inj_funcs=dll_funcs,
            filename=filename,
            # use_precompiled=False
        )

        self.assertTrue(os.path.exists(filepath))
        os.unlink(filepath)

    def test_win_x86_reverse(self):
        os_target = OS.WINDOWS
        os_target_arch = OS_ARCH.X86
        dll_funcs = ["pcap_findalldevs", "pcap_close", "pcap_compile", "pcap_datalink",
                     "pcap_datalink_val_to_description",
                     "pcap_dump", "pcap_dump_close", "pcap_dump_open", "pcap_file", "pcap_freecode", "pcap_geterr",
                     "pcap_getevent", "pcap_lib_version", "pcap_lookupdev", "pcap_lookupnet", "pcap_loop",
                     "pcap_open_live",
                     "pcap_open_offline", "pcap_setfilter", "pcap_snapshot", "pcap_stats"]

        s = OSShellcodes(os_target, os_target_arch, self.connect_back_ip, 6666, self.bad_chars)
        connection_type = SHELLCODE_CONNECTION.REVERSE
        filename = 'osshell_x86_reverse'
        filepath = os.path.join(paths.POCSUITE_TMP_PATH, filename) + '.exe'
        shellcode = s.create_shellcode(
            connection_type,
            encode='',
            make_exe=1,
            debug=0,
            # dll_inj_funcs=dll_funcs,
            filename=filename,
            # use_precompiled=False
        )

        self.assertTrue(os.path.exists(filepath))
        os.unlink(filepath)

    def test_win_x64_bind(self):
        pass

    def test_win_x64_reverse(self):
        pass

    def test_linux_x86_bind(self):
        pass

    def test_linux_x86_reverse(self):
        pass

    def test_linux_x64_bind(self):
        pass

    def test_linux_x64_reverse(self):
        pass
