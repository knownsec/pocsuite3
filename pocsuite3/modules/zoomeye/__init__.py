import getpass
import time
from base64 import b64encode
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger, kb, paths
from pocsuite3.lib.core.common import is_ipv6_address_format
from pocsuite3.lib.request import requests


class ZoomEye():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.url = None
        self.headers = {
            'User-Agent': 'curl/7.80.0',
            "Content-Type": "application/json",
        }
        self.token = token
        self.points = None
        self.zoomeye_points = None
        self.plan = None
        self.conf_path = conf_path

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get('ZoomEye', 'token')
                self.url = self.url or self.parser.get('ZoomEye', 'url')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                self.headers['API-KEY'] = self.token
                resp = requests.post(f'{self.url}/v2/userinfo', headers=self.headers)
                if resp and resp.status_code == 200 and 'plan' in resp.text:
                    content = resp.json()
                    self.plan = content['data']['subscription']['plan']
                    self.points = content['data']['subscription']['points']
                    self.zoomeye_points = content['data']['subscription']['zoomeye_points']
                    return True
                else:
                    logger.info(resp.text)
                    return False
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token and self.url:
            if self.token_is_available():
                return True

        while True:
            logger.info("Users in mainland China should use https://api.zoomeye.org, "
                        "while other users should use https://api.zoomeye.ai.")
            self.url = input("ZoomEye Url:").rstrip('/')
            self.token = getpass.getpass("ZoomEye API token: (input will hidden)")
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The ZoomEye api token is incorrect, Please enter the correct api token.")

    def write_conf(self):
        if not self.parser.has_section("ZoomEye"):
            self.parser.add_section("ZoomEye")
        try:
            self.parser.set("ZoomEye", "token", self.token)
            self.parser.set("ZoomEye", "url", self.url)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def search(self, dork, pages=2, pagesize=20, search_type="v4"):
        search_result = set()
        if kb.comparison:
            kb.comparison.add_dork("Zoomeye", dork)
        try:
            for page in range(1, pages + 1):
                time.sleep(1)
                url = f'{self.url}/v2/search'
                data = {
                    "qbase64": b64encode(dork.encode('utf-8')).decode('utf-8'),
                    "page": page,
                    "pagesize": pagesize,
                    "sub_type": search_type,
                    "fields": "ip,port,domain,service,honeypot"
                }

                resp = requests.post(url, headers=self.headers, timeout=60, json=data)
                content = resp.json()
                if resp and resp.status_code == 200 and content.get("code", None) == 60000:

                    for match in content['data']:
                        if match['domain']:
                            url = match['domain']
                        else:
                            host = match['ip']
                            port = match['port']
                            url = f'[{host}]:{port}' if is_ipv6_address_format(host) else f'{host}:{port}'
                            scheme = ''
                            if match['service']:
                                scheme = str(match['service'].split('/')[-1])
                            if scheme:
                                url = f'{scheme}://{url}'

                        search_result.add(url)
                        if kb.comparison:
                            honeypot = False
                            if match['honeypot'] == 1:
                                honeypot = True
                            kb.comparison.add_ip(match['ip'], "Zoomeye", honeypot)
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    kb.comparison = False
    ze = ZoomEye()
    res = ze.search(dork='"<title>Vigor 300B</title>"', pages=1)
    print(res)
    res = ze.search(dork='domain="google.com"', pages=1, pagesize=100, search_type='all')
    print(res)
