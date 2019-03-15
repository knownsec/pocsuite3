import getpass
import urllib

from configparser import ConfigParser
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests


class ZoomEye():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, username=None, password=None):
        self.headers = None
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

    def token_is_available(self):
        if self.token:
            headers = {'Authorization': 'JWT %s' % self.token}
            try:
                resp = requests.get('https://api.zoomeye.org/resources-info', headers=headers)
                if resp and resp.status_code == 200 and "plan" in resp.json():
                    self.headers = headers
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def new_token(self):
        data = '{{"username": "{}", "password": "{}"}}'.format(self.username, self.password)
        try:
            resp = requests.post('https://api.zoomeye.org/user/login', data=data, )
            if resp.status_code != 401 and "access_token" in resp.json():
                content = resp.json()
                self.token = content['access_token']
                self.headers = {'Authorization': 'JWT %s' % self.token}
                return True
        except Exception as ex:
            logger.error(str(ex))
        return False

    def check_account(self):
        if self.token_is_available():
            return True
        else:
            if self.username and self.password:
                if self.new_token():
                    self.write_conf()
                    return True
            else:
                username = input("Telnet404 email account:")
                password = getpass.getpass("Telnet404 password:")
                self.username = username
                self.password = password
                if self.new_token():
                    self.write_conf()
                    return True
                else:
                    logger.error("The username or password is incorrect. "
                                 "Please enter the correct username and password.")
                    return False

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
                if resp and resp.status_code == 200 and 'plan' in resp.json():
                    content = resp.json()
                    self.plan = content['plan']
                    self.resources = content['resources']['search']
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def search(self, dork, pages=1, resource='web'):
        search_result = set()
        try:
            for page in range(1, pages + 1):
                url = "https://api.zoomeye.org/{}/search?query={}&page={}&facet=app,os".format(resource,
                                                                                               urllib.parse.quote(dork),
                                                                                               page)
                resp = requests.get(url, headers=self.headers)
                if resp and resp.status_code == 200 and "matches" in resp.json():
                    content = resp.json()
                    if resource == 'web':
                        search_result.update([match['site'] for match in content['matches']])
                    else:
                        for match in content['matches']:
                            ans = match['ip']
                            if 'portinfo' in match:
                                ans += ':' + str(match['portinfo']['port'])
                            search_result.add(ans)
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    ze = ZoomEye()
    ze.search('dedecms')
