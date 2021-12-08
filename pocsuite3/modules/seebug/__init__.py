import getpass
import json
from configparser import ConfigParser

from pocsuite3.lib.request import requests
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths


class Seebug():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, username=None, password=None):
        self.headers = {'User-Agent': 'curl/7.80.0'}
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

        self.check_account()

    def token_is_available(self):
        if self.token:
            self.headers['Authorization'] = f'JWT {self.token}'
            try:
                resp = requests.get('https://www.seebug.org/api/user/poc_list', headers=self.headers)
                if resp and resp.status_code == 200 and "name" in resp.text:
                    return True
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
                elif resp.status_code == 200 and "status" in resp.json() and resp.json()["status"] is False:
                    if "message" in resp.json():
                        msg = resp.json()["message"]
                        if msg == "没有权限访问此漏洞":
                            msg = "No permission to access the vulnerability POC"
                    else:
                        msg = "Unknown"
                    msg = "[PLUGIN] " + msg
                    raise Exception(msg)
            except Exception as ex:
                logger.error(str(ex))
        else:
            return None


if __name__ == "__main__":
    sb = Seebug()
    sb.fetch_poc(ssvid='12345')
    sb.get_available_pocs()
    sb.search_poc('dedecms')
