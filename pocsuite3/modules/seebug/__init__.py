import getpass
from configparser import ConfigParser

from pocsuite3.lib.request import requests
from pocsuite3.lib.core.data import logger, paths


class Seebug():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.url = 'https://www.seebug.org/api'
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.token = token
        self.pocs = []
        self.conf_path = conf_path

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get('Seebug', 'token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                self.headers['Authorization'] = f'Token {self.token}'
                resp = requests.get(f'{self.url}/user/poc_list', headers=self.headers)
                if resp and resp.status_code == 200:
                    self.pocs = resp.json()
                    return True
                else:
                    logger.info(resp.text)
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True

        while True:
            self.token = getpass.getpass('Seebug API token: (input will hidden)')
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error('The Seebug api token is incorrect, Please enter the correct api token.')

    def write_conf(self):
        if not self.parser.has_section('Seebug'):
            self.parser.add_section('Seebug')
        try:
            self.parser.set('Seebug', 'token', self.token)
            self.parser.write(open(self.conf_path, 'w'))
        except Exception as ex:
            logger.error(str(ex))

    def get_available_pocs(self):
        return self.pocs

    def search_poc(self, keyword):
        try:
            resp = requests.get(f'{self.url}/user/poc_list?q={keyword}', headers=self.headers)
            if resp and resp.status_code == 200:
                pocs = resp.json()
                return pocs
        except Exception as ex:
            logger.error(str(ex))
        return []

    def fetch_poc(self, ssvid):
        try:
            if ssvid and ssvid.startswith('ssvid-'):
                ssvid = ssvid.split('ssvid-')[-1]
            resp = requests.get(f'{self.url}/user/poc_detail?id={ssvid}', headers=self.headers)
            content = resp.json()
            if resp and resp.status_code == 200 and 'code' in content:
                poc = content['code']
                return poc
            elif resp.status_code == 200 and 'status' in content and content['status'] is False:
                if 'message' in content:
                    msg = content['message']
                    if msg == "没有权限访问此漏洞":
                        msg = "No permission to access the vulnerability PoC"
                else:
                    msg = "Unknown"
                msg = "[PLUGIN] Seebug:" + msg
                raise Exception(msg)
        except Exception as ex:
            logger.error(str(ex))
        return ''


if __name__ == "__main__":
    sb = Seebug()
    print(sb.search_poc('redis'))
    print(sb.get_available_pocs())
    print(sb.fetch_poc(ssvid='89715'))
