import getpass
import urllib
import time
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger, kb, paths
from pocsuite3.lib.core.common import is_ipv6_address_format
from pocsuite3.lib.request import requests


class ZoomEye():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.url = 'https://api.zoomeye.org'
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.token = token
        self.resources = None
        self.plan = None
        self.conf_path = conf_path

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get('ZoomEye', 'token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                self.headers['API-KEY'] = self.token
                resp = requests.get(f'{self.url}/resources-info', headers=self.headers)
                if resp and resp.status_code == 200 and 'plan' in resp.text:
                    content = resp.json()
                    self.plan = content['plan']
                    self.resources = content['quota_info']['remain_total_quota']
                    return True
                else:
                    logger.info(resp.text)
                    return False
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        while True:
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
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def search(self, dork, pages=2, resource='host'):
        search_result = set()
        dork = urllib.parse.quote(dork)
        if kb.comparison:
            kb.comparison.add_dork("Zoomeye", dork)
        try:
            for page in range(1, pages + 1):
                time.sleep(1)
                url = f'{self.url}/{resource}/search?query={dork}&page={page}'
                resp = requests.get(url, headers=self.headers, timeout=60)
                if resp and resp.status_code == 200 and 'matches' in resp.text:
                    content = resp.json()

                    if resource == 'web':
                        for match in content["matches"]:
                            ans = match["site"]
                            search_result.add(ans)

                            if kb.comparison:
                                honeypot = False
                                if "honeypot" in content or "honeypot_lastupdate" in content:
                                    honeypot = True
                                kb.comparison.add_ip(ans, "Zoomeye", honeypot)
                    else:
                        for match in content['matches']:
                            host = match['ip']
                            port = str(match['portinfo']['port'])
                            url = f'[{host}]:{port}' if is_ipv6_address_format(host) else f'{host}:{port}'
                            scheme = ''

                            if 'service' in match['portinfo']:
                                scheme = str(match['portinfo']['service'].split('/')[-1])

                            if scheme:
                                url = f'{scheme}://{url}'
                            search_result.add(url)

                            if kb.comparison:
                                honeypot = False
                                if "honeypot" in match or "honeypot_lastupdate" in match:
                                    honeypot = True
                                kb.comparison.add_ip(host, "Zoomeye", honeypot)
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    kb.comparison = False
    ze = ZoomEye()
    res = ze.search(dork='"<title>Vigor 300B</title>"', pages=1)
    print(res)
    res = ze.search(dork='site:google.com', pages=1, resource='web')
    print(res)
