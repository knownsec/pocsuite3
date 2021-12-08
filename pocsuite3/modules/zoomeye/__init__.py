import getpass
import urllib

from configparser import ConfigParser
from pocsuite3.lib.core.data import logger, kb
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests


class ZoomEye():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, username=None, password=None):
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.token = None
        self.resources = None
        self.plan = None
        self.conf_path = conf_path
        self.username = username
        self.password = password

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.parser.get("Telnet404", 'Jwt token')
            except Exception:
                pass

        self.check_account()

    def token_is_available(self):
        if self.token:
            self.headers['Authorization'] = f'JWT {self.token}'
            try:
                resp = requests.get('https://api.zoomeye.org/resources-info', headers=self.headers)
                if resp and resp.status_code == 200 and "plan" in resp.text:
                    return True
                else:
                    logger.info(resp.text)
            except Exception as ex:
                logger.error(str(ex))
        return False

    def new_token(self):
        data = '{{"username": "{}", "password": "{}"}}'.format(self.username, self.password)
        try:
            resp = requests.post('https://api.zoomeye.org/user/login', data=data)
            if resp.status_code != 401 and "access_token" in resp.text:
                content = resp.json()
                self.token = content['access_token']
                self.headers['Authorization'] = f'JWT {self.token}'
                return True
            else:
                logger.info(resp.text)
        except Exception as ex:
            logger.error(str(ex))
        return False

    def check_account(self):
        if self.token_is_available():
            return True
        elif self.username and self.password:
            if self.new_token():
                self.write_conf()
                return True
        while True:
            username = input("Telnet404 email account: ")
            password = getpass.getpass("Telnet404 password: (input will hidden)")
            self.username = username
            self.password = password
            if self.new_token():
                self.write_conf()
                return True
            else:
                logger.error("The username or password is incorrect, "
                             "Please enter the correct username and password.")

    def write_conf(self):
        if not self.parser.has_section("Telnet404"):
            self.parser.add_section("Telnet404")
        try:
            self.parser.set("Telnet404", "Jwt token", self.token)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def get_resource_info(self):
        if self.check_account():
            try:
                resp = requests.get('https://api.zoomeye.org/resources-info', headers=self.headers)
                if resp and resp.status_code == 200 and 'plan' in resp.text:
                    content = resp.json()
                    self.plan = content['plan']
                    self.resources = content['resources']['search']
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def search(self, dork, pages=1, resource='web'):
        search_result = set()
        if kb.comparison:
            kb.comparison.add_dork("Zoomeye", dork)
        try:
            for page in range(1, pages + 1):
                url = (
                    "https://api.zoomeye.org/{}/search?query={}&page={}&facet=app,os"
                ).format(resource, urllib.parse.quote(dork), page)
                resp = requests.get(url, headers=self.headers)
                if resp and resp.status_code == 200 and "matches" in resp.text:
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
                            ans = match['ip']
                            if 'portinfo' in match:
                                ans += ':' + str(match['portinfo']['port'])
                            search_result.add(ans)
                            if kb.comparison:
                                honeypot = False
                                if "honeypot" in match or "honeypot_lastupdate" in match:
                                    honeypot = True
                                kb.comparison.add_ip(ans, "Zoomeye", honeypot)
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    ze = ZoomEye()
    ze.search('dedecms')
