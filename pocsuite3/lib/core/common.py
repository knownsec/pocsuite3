import base64
import hashlib
import inspect
import logging
import os
import re
import select
import shlex
import socket
import struct
import subprocess
import sys
import time
import collections
import chardet
import requests
from collections import OrderedDict
from functools import wraps
from ipaddress import ip_address, ip_network
from platform import machine
from subprocess import call, Popen, PIPE
from colorama.initialise import init as coloramainit
from termcolor import colored
from pocsuite3.lib.core.convert import stdout_encode
from pocsuite3.lib.core.data import conf
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.decorators import cachedmethod
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.core.exception import PocsuiteSystemException
from pocsuite3.lib.core.log import LOGGER_HANDLER
from pocsuite3.lib.core.settings import (
    BANNER, BOLD_PATTERNS, IS_WIN, URL_DOMAIN_REGEX, LOCAL_IP_ADDRESS_REGEX,
    IP_ADDRESS_WITH_PORT_REGEX, IPV6_URL_REGEX, TIMESTAMP, OS_SYSTEM)
from pocsuite3.lib.core.settings import IPV6_ADDRESS_REGEX
from pocsuite3.lib.core.settings import IP_ADDRESS_REGEX
from pocsuite3.lib.core.settings import OLD_VERSION_CHARACTER
from pocsuite3.lib.core.settings import POCSUITE_VERSION_CHARACTER
from pocsuite3.lib.core.settings import POC_NAME_REGEX
from pocsuite3.lib.core.settings import POC_REQUIRES_REGEX
from pocsuite3.lib.core.settings import UNICODE_ENCODING
from pocsuite3.lib.core.settings import URL_ADDRESS_REGEX


try:
    collectionsAbc = collections.abc
except AttributeError:
    collectionsAbc = collections


def read_binary(filename):
    content = ''
    with open(filename, 'rb') as f:
        content = f.read()
    return content


def check_path(path):
    return True if path and os.path.exists(path) else False


def check_file(filename):
    """
    @function Checks for file existence and readability
    """

    valid = True

    if filename is None or not os.path.isfile(filename):
        valid = False

    if valid:
        try:
            with open(filename, "rb"):
                pass
        except Exception:
            valid = False

    if not valid:
        raise PocsuiteSystemException("unable to read file '%s'" % filename)
    return valid


def set_paths(root_path):
    """
    Sets absolute paths for project directories and files
    """
    paths.POCSUITE_ROOT_PATH = root_path
    paths.POCSUITE_DATA_PATH = os.path.join(paths.POCSUITE_ROOT_PATH, "data")
    paths.POCSUITE_PLUGINS_PATH = os.path.join(paths.POCSUITE_ROOT_PATH, "plugins")
    paths.POCSUITE_POCS_PATH = os.path.join(paths.POCSUITE_ROOT_PATH, "pocs")
    paths.USER_POCS_PATH = None

    paths.WEAK_PASS = os.path.join(paths.POCSUITE_DATA_PATH, "password-top100.txt")

    paths.POCSUITE_HOME_PATH = os.path.expanduser("~")
    _ = os.path.join(paths.POCSUITE_HOME_PATH, ".pocsuite")

    paths.API_SHELL_HISTORY = os.path.join(_, "api.hst")
    paths.OS_SHELL_HISTORY = os.path.join(_, "os.hst")
    paths.SQL_SHELL_HISTORY = os.path.join(_, "sql.hst")
    paths.POCSUITE_SHELL_HISTORY = os.path.join(_, "pocsuite.hst")
    paths.POCSUITE_CONSOLE_HISTORY = os.path.join(_, "console.hst")

    paths.POCSUITE_TMP_PATH = os.path.join(_, "tmp")
    paths.POCSUITE_RC_PATH = os.path.join(paths.POCSUITE_HOME_PATH, ".pocsuiterc")
    paths.POCSUITE_OUTPUT_PATH = paths.get("POCSUITE_OUTPUT_PATH", os.path.join(_, "output"))
    paths.SHELLCODES_DEV_PATH = os.path.join(paths.POCSUITE_TMP_PATH, "tools")


def banner():
    """
    Function prints pocsuite banner with its version
    """
    _ = BANNER
    if not getattr(LOGGER_HANDLER, "is_tty", False):
        _ = clear_colors(_)
    elif IS_WIN:
        coloramainit()

    data_to_stdout(_)


def set_color(message, bold=False):
    if isinstance(message, bytes):
        message = message.decode(UNICODE_ENCODING)
    ret = message

    if message and getattr(LOGGER_HANDLER, "is_tty", False):  # colorizing handler
        if bold:
            ret = colored(message, color=None, on_color=None, attrs=("bold",))

    return ret


def clear_colors(message):
    ret = message
    if message:
        ret = re.sub(r"\x1b\[[\d;]+m", "", message)
    return ret


def boldify_message(message):
    ret = message

    if any(_ in message for _ in BOLD_PATTERNS):
        ret = set_color(message, bold=True)

    return ret


def data_to_stdout(data, bold=False):
    """
    Writes text to the stdout (console) stream
    """
    if 'quiet' not in conf or not conf.quiet:
        message = ""

        if isinstance(data, str):
            message = stdout_encode(data)
        else:
            message = data

        sys.stdout.write(set_color(message, bold))

        try:
            sys.stdout.flush()
        except IOError:
            pass
    return


@cachedmethod
def extract_regex_result(regex, content, flags=0):
    """
    Returns 'result' group value from a possible match with regex on a given
    content
    >>> extract_regex_result(r'a(?P<result>[^g]+)g', 'abcdefg')
    'bcdef'
    """

    ret = None

    if regex and content and "?P<result>" in regex:
        match = re.search(regex, content, flags)

        if match:
            ret = match.group("result")

    return ret


def get_latest_revision():
    """
    Retrieves latest revision from the offical repository
    """

    ret = None
    resp = requests.get(url="https://raw.githubusercontent.com/knownsec/pocsuite3/master/pocsuite3/__init__.py")
    try:
        content = resp.content
        ret = extract_regex_result(r"__version__\s*=\s*[\"'](?P<result>[\d.]+)", content)
    except Exception:
        pass

    return ret


def poll_process(process, suppress_errors=False):
    """
    Checks for process status (prints . if still running)
    """

    while True:
        data_to_stdout(".")
        time.sleep(1)

        return_code = process.poll()

        if return_code is not None:
            if not suppress_errors:
                if return_code == 0:
                    data_to_stdout(" done\n")
                elif return_code < 0:
                    data_to_stdout(" process terminated by signal {}\n".format(return_code))
                elif return_code > 0:
                    data_to_stdout(" quit unexpectedly with return code {}\n".format(return_code))

            break


def parse_target_url(url):
    """
    Parse target URL
    """
    ret = url

    if conf.ipv6 and is_ipv6_address_format(url):
        ret = "[" + ret + "]"

    if not re.search("^http[s]*://", ret, re.I) and not re.search("^ws[s]*://", ret, re.I):
        if re.search(":443[/]*$", ret):
            ret = "https://" + ret
        else:
            ret = "http://" + ret

    return ret


def is_url_format(value):
    if value and re.match(URL_ADDRESS_REGEX, value):
        return True
    else:
        return False


def is_domain_format(value):
    if value and re.match(URL_DOMAIN_REGEX, value):
        return True
    else:
        return False


def is_ip_address_format(value):
    if value and re.match(IP_ADDRESS_REGEX, value):
        return True
    else:
        return False


def is_ip_address_with_port_format(value):
    if value and re.match(IP_ADDRESS_WITH_PORT_REGEX, value):
        return True
    else:
        return False


def is_ipv6_address_format(value):
    if value and re.match(IPV6_ADDRESS_REGEX, value):
        return True
    else:
        return False


def is_ipv6_url_format(value):
    if value and re.match(IPV6_URL_REGEX, value):
        return True
    else:
        return False


def is_old_version_poc(poc_string):
    for _ in OLD_VERSION_CHARACTER:
        if _ in poc_string:
            return True
    return False


def is_pocsuite_poc(poc_string):
    for _ in POCSUITE_VERSION_CHARACTER:
        if _ in poc_string:
            return True
    return False


def is_pocsuite3_poc(poc_string):
    return True if "pocsuite3" in poc_string else False


def multiple_replace(text, adict):
    rx = re.compile("|".join(map(re.escape, adict)))

    def get_replace(match):
        return adict[match.group(0)]

    return rx.sub(get_replace, text)


def get_filename(filepath, with_ext=True):
    base_name = os.path.basename(filepath)
    return base_name if with_ext else os.path.splitext(base_name)[0]


def get_md5(value):
    if isinstance(value, str):
        value = value.encode(encoding='UTF-8')
    return hashlib.md5(value).hexdigest()


def extract_cookies(cookie):
    cookies = dict([l.split("=", 1) for l in cookie.split("; ")])
    return cookies


def get_file_items(filename, comment_prefix='#', unicode_=True, lowercase=False, unique=False):
    ret = list() if not unique else OrderedDict()

    check_file(filename)

    try:
        with open(filename, 'r') as f:
            for line in f.readlines():
                # xreadlines doesn't return unicode strings when codecs.open() is used
                if comment_prefix and line.find(comment_prefix) != -1:
                    line = line[:line.find(comment_prefix)]

                line = line.strip()

                if not unicode_:
                    try:
                        line = str.encode(line)
                    except UnicodeDecodeError:
                        continue

                if line:
                    if lowercase:
                        line = line.lower()

                    if unique and line in ret:
                        continue

                    if unique:
                        ret[line] = True

                    else:
                        ret.append(line)

    except (IOError, OSError, MemoryError) as ex:
        err_msg = "something went wrong while trying "
        err_msg += "to read the content of file '{0}' ('{1}')".format(filename, ex)
        raise PocsuiteSystemException(err_msg)

    return ret if not unique else ret.keys()


def parse_target(address):
    target = None
    if is_domain_format(address) \
            or is_url_format(address) \
            or is_ip_address_with_port_format(address):
        target = address

    elif is_ipv6_url_format(address):
        conf.ipv6 = True
        target = address

    elif is_ip_address_format(address):
        try:
            ip = ip_address(address)
            target = ip.exploded
        except ValueError:
            pass
    else:
        if is_ipv6_address_format(address):
            conf.ipv6 = True
            try:
                ip = ip_address(address)
                target = ip.exploded
            except ValueError:
                try:
                    network = ip_network(address, strict=False)
                    for host in network.hosts():
                        target = host.exploded
                except ValueError:
                    pass

    return target


def single_time_log_message(message, level=logging.INFO, flag=None):
    if flag is None:
        flag = hash(message)

    if flag not in kb.single_log_flags:
        kb.single_log_flags.add(flag)
        logger.log(level, message)


def single_time_debug_message(message):
    single_time_log_message(message, logging.DEBUG)


def single_time_warn_message(message):
    single_time_log_message(message, logging.WARN)


@cachedmethod
def get_public_type_members(type_, only_values=False):
    """
    Useful for getting members from types (e.g. in enums)
    """

    ret = []

    for name, value in inspect.getmembers(type_):
        if not name.startswith("__"):
            if not only_values:
                ret.append((name, value))
            else:
                ret.append(value)

    return ret


def is_local_ip(ip_string):
    ret = False
    if ip_string and isinstance(ip_string, str) and re.match(LOCAL_IP_ADDRESS_REGEX, ip_string):
        ret = True
    return ret


def get_local_ip(all=True):
    """Fetches all the local network address
    """
    ips = OrderedSet()
    wan_ipv4 = get_host_ip()
    ips.add(wan_ipv4)
    if not all:
        return list(ips)

    wan_ipv6 = get_host_ipv6()
    if wan_ipv6:
        ips.add(wan_ipv6)

    # fix https://github.com/BVLC/caffe/issues/861
    os.environ["MPLBACKEND"] = "Agg"

    # fix https://github.com/secdev/scapy/issues/3216
    logging.getLogger("scapy").setLevel(logging.ERROR)

    from scapy.all import WINDOWS, get_if_list, get_if_addr

    if WINDOWS:
        from scapy.all import IFACES
        for iface in sorted(IFACES):
            dev = IFACES[iface]
            ips.add(dev.ip)
    else:
        for iface in get_if_list():
            ipv4 = get_if_addr(iface)
            if ipv4 != '0.0.0.0':
                ips.add(ipv4)

    return list(ips)


def get_host_ip(dst='8.8.8.8'):
    """ Fetches source ipv4 address when connect to dst

    Args:
        dst <str>: target ip or domain

    Returns:
        <str>:  source ip address
    """

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()

    return ip


def has_poll():
    return hasattr(select, "poll")


def get_poc_requires(code):
    return extract_regex_result(POC_REQUIRES_REGEX, code)


def get_poc_name(code):
    return extract_regex_result(POC_NAME_REGEX, code)


def is_os_64bit():
    return machine().endswith('64')


def write_file(data, file_ext='', file_name=''):
    """
        Function to create file
    """

    if not file_ext.startswith('.'):
        file_ext = '.' + file_ext
    if not file_name:
        file_name = TIMESTAMP
    file_name += file_ext
    file_path = os.path.join(paths.POCSUITE_TMP_PATH, file_name)

    fd = open(file_path, 'wb+')
    fd.write(data)
    fd.close()

    return file_path


def search_file(filename, search_path):
    """
        Given a search path, find file
    """
    path = os.path.join(search_path, filename)
    if os.path.exists(path):
        return path
    return None


def get_objective_code(asm_file, target_arch, debug=0):
    """
        Get objective code (file: *.o)
    """
    if target_arch == OS_ARCH.X86:
        output_format = 'elf'
    elif target_arch == OS_ARCH.X64:
        output_format = 'elf64'
    else:
        print("Format for output objective file is not defined")
        return None

    if not asm_file:
        print("You must specify some params passed to function")
        return None

    obj_file = (asm_file.split('.'))[0] + ".o"

    app = 'nasm'  # Application that do magic for us
    if OS_SYSTEM == OS.WINDOWS:
        app += '.exe'
        find_app = search_file("%s" % app, paths.SHELLCODES_DEV_PATH)
        if find_app:
            if debug:
                print("app: '%s' found at %s" % (app, find_app))
        else:
            print("You must install app: '%s' and maybe edit environment variables path to it" % app)
            return None
    elif OS_SYSTEM == OS.LINUX:
        find_app = app
    else:
        print("Can't understand source os")
        return None

    command = "%s -f%s -o%s %s" % (find_app, output_format, obj_file, asm_file)
    if debug:
        print(command)
    res = call([find_app, "-f", output_format, "-o", obj_file, asm_file])
    if res == 0:
        if debug:
            print("Objective code has been created")
        return obj_file
    else:
        print("Something wrong while getting objective code")
        return None


def objdump(obj_file, os_target_arch, debug=0):
    """
        Get shellcode with objdump utility
    """

    res = ''
    if not obj_file:
        print("You must specify some params passed to function")
        return None
    else:
        app = 'objdump'
        if OS_SYSTEM == OS.WINDOWS:
            app += ".exe"

            find_app = search_file("%s" % app, paths.SHELLCODES_DEV_PATH)
            if find_app:
                if debug:
                    print("app: '%s' found at %s" % (app, find_app))
            else:
                print("You must install app: '%s' and maybe edit environment variables path to it" % app)
                return None
        elif OS_SYSTEM == OS.LINUX:
            find_app = app
        else:
            print("Can't understand source os")
            return None

        if os_target_arch == OS_ARCH.X86:
            p = Popen(['%s' % find_app, '-d', obj_file], stdout=PIPE, stderr=PIPE)
        elif os_target_arch == OS_ARCH.X64:
            p = Popen(['%s' % find_app, '-d', obj_file, '--disassembler-options=addr64'], stdout=PIPE, stderr=PIPE)
        else:
            print("OS TARGET ARCH '%s' is not supported" % os_target_arch)
            return

        (stdout, stderr) = p.communicate()
        if p.returncode == 0:
            for line in stdout.splitlines():
                cols = line.split('\t')
                if len(cols) >= 2:
                    for b in [b for b in cols[1].split(' ') if b != '']:
                        res = res + ('\\x%s' % b)
        else:
            raise ValueError(stderr)

    if res and debug:
        print("objdump is created")

    return res


def create_shellcode(asm_code, os_target, os_target_arch, make_exe=0, debug=0, filename="", dll_inj_funcs=[]):
    if os_target == OS.LINUX:
        dll_inj_funcs = []
    if not is_os_64bit() and os_target_arch == OS_ARCH.X64:
        print("ERR: can not create shellcode for this os_target_arch ({0}) on os_arch ({1})".format(os_target_arch,
                                                                                                    OS_ARCH.X64))
        return None
    asm_file = write_file(asm_code, '.asm', filename)
    obj_file = get_objective_code(asm_file, os_target_arch, debug)

    # stage_2:
    if obj_file:
        shellcode = objdump(obj_file, os_target_arch, debug)
        shellcode = shellcode.replace('\\x', '').decode('hex')
        # shellcode = extract_shell_from_obj(obj_file)
    else:
        return None
    if make_exe:
        make_binary_from_obj(obj_file, os_target, os_target_arch, debug)
    if dll_inj_funcs:
        generate_dll(os_target, os_target_arch, asm_code, filename, dll_inj_funcs, debug)
    return shellcode, asm_file.split(".")[0]


def generate_dll(os_target, os_target_arch, asm_code, filename, dll_inj_funcs, debug):
    asm_code = asm_code.replace("global _start", "").replace("_start:", "")
    additional_code = ""
    for func in dll_inj_funcs:
        additional_code += "global _{}\r\n".format(func)
    for func in dll_inj_funcs:
        additional_code += "_{}:\r\n".format(func)
    asm_code = additional_code + asm_code
    asm_file = write_file(asm_code, '.asm', filename)
    obj_file = get_objective_code(asm_file, os_target_arch, debug)
    make_binary_from_obj(obj_file, os_target, os_target_arch, debug, True)


def make_binary_from_obj(o_file, os_target, os_target_arch, debug=0, is_dll=False):
    """
        Function for test shellcode with app written on c-language
    """
    if is_dll and os_target == OS.LINUX:
        print('Dll can be generated only for WINDOWS OS')
        return None
    app = 'ld'
    find_app = ''
    if OS_SYSTEM == OS.WINDOWS:
        if os_target == OS.LINUX:
            app += '.gold'
        elif os_target == OS.WINDOWS and os_target_arch == OS_ARCH.X64:
            app += '64'
        app += '.exe'
        find_app = search_file("%s" % app, paths.SHELLCODES_DEV_PATH)
        if find_app:
            if debug:
                print("app: '%s' found at %s" % (app, find_app))
        else:
            print("You must install app: '%s' and maybe edit environment variables path to it" % app)
            return None
    elif OS_SYSTEM == OS.LINUX:
        find_app = app
    else:
        print("Can't understand source os: %s" % OS_SYSTEM)
        return None

    c_exe = (o_file.split('.'))[0]
    commands_list = [find_app, '-o', c_exe, o_file, '--strip-all']
    if OS_SYSTEM == OS.LINUX:
        if os_target == OS.WINDOWS:
            commands_list.append('-m')
            commands_list.append('i386pe')
        if is_dll:
            commands_list.append('-shared')
        p = Popen(commands_list)
        p.communicate()
    elif OS_SYSTEM == OS.WINDOWS:
        if is_dll:
            commands_list.append('-shared')
        p = Popen(commands_list)
        p.communicate()
    else:
        print("ERR: source os (%s) is not supported" % OS_SYSTEM)
    if os_target == OS.WINDOWS:
        newname = c_exe + '.dll' if is_dll else c_exe + '.exe'
        if os.path.exists(newname):
            os.remove(newname)
        os.rename(c_exe, newname)
    print("Complete. Now you can try to execute file: %s" % c_exe)


def extract_shell_from_obj(file):
    with open(file, 'rb') as f:
        contents = f.read()
    flag = contents[4]
    if flag == '\x01':
        length = struct.unpack('<H', contents[124:126])[0]
        contents = contents[272:272 + length]
    elif flag == '\x02':
        length = struct.unpack('<H', contents[160:162])[0]
        contents = contents[384:384 + length]
    else:
        raise Exception("Unknown architecture. Can't extract shellcode")
    print(', '.join('0x%02x' % ord(c) for c in contents))
    return contents


def replace_by_real_values(shellcode, kwargs):
    for key, value in kwargs.items():
        shellcode = shellcode.replace(key, value)
    return shellcode


def ip_to_hex(ip, is_big=True):
    parts = [int(part) for part in ip.split('.')]
    if is_big:
        return ''.join(chr(part) for part in parts).encode()
    return ''.join(chr(part) for part in reversed(parts)).encode()


def port_to_hex(port, is_big=True):
    if is_big:
        return struct.pack('>H', port)
    return struct.pack('<H', port)


def validate_ip_addr(addr):
    import socket
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def ip_to_dd(addr):
    return ''.join('%02x' % int(x) for x in reversed(addr.split('.'))).encode()


def port_to_dd(port):
    return ''.join('%02x' % x for x in struct.pack('<H', port)).encode()


def get_unicode(value):
    result = chardet.detect(value)
    charset = result['encoding'] or UNICODE_ENCODING
    return value.decode(charset)


def rtrim(text, char):
    """
    Delete the specified character on the right
    :param text: str
    :param char: character
    :return:
    """
    length = len(char)
    if length > len(text):
        return text
    if char == text[-length:]:
        text = text[:-length]
    return text


def ltrim(text, char):
    """
    Delete the specified character on the left
    :param text: str
    :param char: character
    :return:
    """
    length = len(char)
    if length > len(text):
        return text
    if char == text[:length]:
        text = text[length:]
    return text


def index_modules(modules_directory):
    """ Returns list of all exploits modules

    :param str modules_directory: path to modules directory
    :return list: list of found modules
    """

    modules = []
    for root, _, files in os.walk(modules_directory):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        modules.extend(map(lambda x: os.path.join(root, os.path.splitext(x)[0]), files))

    return modules


def humanize_path(path: str) -> str:
    """ Replace python dotted path to directory-like one.

    ex. foo.bar.baz -> foo/bar/baz

    :param str path: path to humanize
    :return str: humanized path
    """

    return path.replace(".", os.sep)


def pythonize_path(path: str) -> str:
    """ Replaces argument to valid python dotted notation.

    ex. foo/bar/baz -> foo.bar.baz

    :param str path: path to pythonize
    :return str: pythonized path
    """

    return path.replace(os.sep, ".")


def module_required(fn):
    """ Checks if module is loaded.

    Decorator that checks if any module is activated
    before executing command specific to modules (ex. 'run').
    """

    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not self.current_module:
            logger.error("You have to activate any module with 'use' command.")
            return
        return fn(self, *args, **kwargs)

    try:
        name = "module_required"
        wrapper.__decorators__.append(name)
    except AttributeError:
        wrapper.__decorators__ = [name]
    return wrapper


def stop_after(space_number):
    """ Decorator that determines when to stop tab-completion

    Decorator that tells command specific complete function
    (ex. "complete_use") when to stop tab-completion.
    Decorator counts number of spaces (' ') in line in order
    to determine when to stop.

        ex. "use exploits/dlink/specific_module " -> stop complete after 2 spaces
        "set rhost " -> stop completing after 2 spaces
        "run " -> stop after 1 space

    :param space_number: number of spaces (' ') after which tab-completion should stop
    :return:
    """

    def _outer_wrapper(wrapped_function):
        @wraps(wrapped_function)
        def _wrapper(self, *args, **kwargs):
            try:
                if args[1].count(" ") == space_number:
                    return []
            except Exception as err:
                logger.error(err)
            return wrapped_function(self, *args, **kwargs)

        return _wrapper

    return _outer_wrapper


def check_port(ip, port):
    res = socket.getaddrinfo(ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    af, sock_type, proto, canonname, sa = res[0]
    s = socket.socket(af, sock_type, proto)

    try:
        s.connect(sa)
        s.shutdown(2)
        return True
    except:
        return False
    finally:
        s.close()


def exec_cmd(cmd, raw_data=True):
    cmd = shlex.split(cmd)
    out_data = b''
    try:
        p = subprocess.Popen(
            cmd, shell=False, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        while p.poll() is None:
            line = p.stdout.read()
            out_data += line
    except Exception as ex:
        logger.error("Execute cmd error {}".format(str(ex)))

    encoding = chardet.detect(out_data).get('encoding')
    encoding = encoding if encoding else 'utf-8'
    if IS_WIN:
        out_data = out_data.split(b'\r\n\r\n')
    else:
        out_data = out_data.split(b'\n\n')
    if not raw_data:
        for i, data in enumerate(out_data):
            out_data[i] = data.decode(encoding, errors='ignore')

    return out_data


def desensitization(s):
    """ Hide sensitive information.
    """
    s = str(s)
    return (
            s[:len(s) // 4 if len(s) < 30 else 8] +
            '***' +
            s[len(s) * 3 // 4:]
    )


def encoder_bash_payload(cmd: str) -> str:
    ret = "bash -c '{echo,%s}|{base64,-d}|{bash,-i}'" % base64.b64encode(cmd.encode()).decode()
    return ret


def encoder_powershell_payload(powershell: str):
    command = "powershell -NonI -W Hidden -NoP -Exec Bypass -Enc " + base64.b64encode(
        '\x00'.join(list(powershell)).encode() + b'\x00').decode()
    return command


def get_host_ipv6(dst='2001:db8::'):
    """ Fetches source ipv6 address when connect to dst

    Args:
        dst <str>: target ip or domain

    Returns:
        <str>:  source ipv6 address
    """

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 1027))
    except socket.error:
        return None
    return s.getsockname()[0]


class OrderedSet(collections.OrderedDict, collectionsAbc.MutableSet):

    def add(self, e):
        self[e] = None

    def discard(self, e):
        self.pop(e, None)

    def __le__(self, other):
        return all(e in other for e in self)

    def __lt__(self, other):
        return self <= other and self != other

    def __ge__(self, other):
        return all(e in self for e in other)

    def __gt__(self, other):
        return self >= other and self != other

    def __repr__(self):
        return 'OrderedSet([%s])' % (', '.join(map(repr, self.keys())))

    def __str__(self):
        return '{%s}' % (', '.join(map(repr, self.keys())))


if __name__ == '__main__':
    cmd = 'ping baidu.com'
    res = exec_cmd(cmd=cmd)
    print(res)
