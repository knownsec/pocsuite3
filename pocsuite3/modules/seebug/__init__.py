import getpass
import json
from configparser import ConfigParser

from pocsuite3.lib.request import requests
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths


class Seebug():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, username=None, password=None):
        self.headers = None
        self.token = None
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
                resp = requests.get('https://www.seebug.org/api/user/poc_list', headers=headers)
                if resp and resp.status_code == 200 and "id" in resp.json()[0]:
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

    def get_available_pocs(self):
        if self.check_account():
            try:
                resp = requests.get('https://www.seebug.org/api/user/poc_list', headers=self.headers)
                if resp and resp.status_code == 200:
                    pocs = resp.json()
                    return pocs
            except Exception as ex:
                logger.error(str(ex))
        else:
            return []

    def search_poc(self, keyword):
        if self.check_account():
            try:
                resp = requests.get('https://www.seebug.org/api/user/poc_list?q=%s' % keyword, headers=self.headers)
                if resp and resp.status_code == 200:
                    pocs = json.loads(resp.text)
                    return pocs
            except Exception as ex:
                logger.error(str(ex))
        else:
            return []

    def fetch_poc(self, ssvid):
        if self.check_account():
            try:
                if ssvid and ssvid.startswith('ssvid-'):
                    ssvid = ssvid.split('ssvid-')[-1]
                resp = requests.get('https://www.seebug.org/api/user/poc_detail?id=%s' % ssvid, headers=self.headers)
                if resp and resp.status_code == 200 and "code" in resp.json():
                    poc = resp.json()['code']
                    return poc
            except Exception as ex:
                logger.error(str(ex))
        else:
            return None


if __name__ == "__main__":
    sb = Seebug()
    sb.fetch_poc(ssvid='12345')
    sb.get_available_pocs()
    sb.search_poc('dedecms')
