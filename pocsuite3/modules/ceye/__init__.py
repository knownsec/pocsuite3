import getpass
import json
import os
import time
import re
from configparser import ConfigParser

from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import get_middle_text, random_str


class CEye(object):
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, username=None, password=None, token=None):
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.token = token
        self.conf_path = conf_path
        self.username = username
        self.password = password

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get("Telnet404", 'Jwt token')
            except Exception:
                pass

        self.check_account()

    def token_is_available(self):
        if self.token:
            # distinguish Jwt Token & API Token
            self.headers['Authorization'] = self.token if len(self.token) < 48 else f'JWT {self.token}'
            try:
                resp = requests.get('http://api.ceye.io/v1/identify', headers=self.headers)
                if resp and resp.status_code == 200 and "identify" in resp.text:
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

    def verify_request(self, flag, type="request"):
        """
        Check whether the ceye interface has data

        :param flag: Input flag
        :param type: Request type (dns|request), the default is request
        :return: Boolean
        """
        ret_val = False
        counts = 3
        url = (
            "http://api.ceye.io/v1/records?token={token}&type={type}&filter={flag}"
        ).format(token=self.token, type=type, flag=flag)
        while counts:
            try:
                time.sleep(1)
                resp = requests.get(url)
                if resp and resp.status_code == 200 and flag in resp.text:
                    ret_val = True
                    break
            except Exception as ex:
                logger.warn(ex)
                time.sleep(1)
            counts -= 1
        return ret_val

    def exact_request(self, flag, type="request"):
        """
        Obtain relevant data by accessing the ceye interface

        :param flag: Input flag
        :param type: Request type (dns|request), the default is request
        :return: Return the acquired data
        """
        counts = 3
        url = (
            "http://api.ceye.io/v1/records?token={token}&type={type}&filter={flag}"
        ).format(token=self.token, type=type, flag=flag)
        while counts:
            try:
                time.sleep(1)
                resp = requests.get(url)
                if resp and resp.status_code == 200 and flag in resp.text:
                    data = json.loads(resp.text)
                    for item in data["data"]:
                        name = item.get("name", '')
                        pro = flag
                        suffix = flag
                        t = get_middle_text(name, pro, suffix, 0)
                        if t:
                            return t
                    break
            except Exception as ex:
                logger.warn(ex)
                time.sleep(1)
            counts -= 1
        return False

    def build_request(self, value, type="request"):
        """
        Generate the sent string

        :param value: Enter the message to be sent
        :param type: Request type (dns|request), the default is request
        :return: dict { url: Return the received domain name,flag: Return a random flag }
        Example:
          {
            'url': 'http://htCb.jwm77k.ceye.io/htCbpingaaahtCb',
            'flag': 'htCb'
          }

        """
        ranstr = random_str(4)
        domain = self.getsubdomain()
        url = ""
        if type == "request":
            url = "http://{}.{}/{}{}{}".format(ranstr, domain, ranstr, value, ranstr)
        elif type == "dns":
            url = "{}{}{}.{}".format(ranstr, re.sub("\W", "", value), ranstr, domain)
        return {"url": url, "flag": ranstr}

    def getsubdomain(self):
        """
        Obtain subdomains through ceye token
        :return: Return the obtained domain name
        """
        r = requests.get("http://api.ceye.io/v1/identify", headers=self.headers).json()
        suffix = ".ceye.io"
        try:
            indetify = r["data"]["identify"]
        except KeyError:
            return None
        return indetify + suffix


if __name__ == "__main__":
    ce = CEye()
    # http record
    # Auxiliary generation of flag string
    flag = ce.build_request("HelloWorld3")
    print(flag)
    # Simulate requests with requests
    try:
        r = requests.get(flag["url"])
    except Exception:
        pass
    time.sleep(1)
    print("request over")
    # Get the requested data
    info = ce.exact_request(flag["flag"], )
    print(info)

    # dns record
    # Auxiliary generation of flag string
    flag = ce.build_request("HelloWor1d", type='dns')
    print(flag)
    # Simulate request with requests
    # r = requests.get(flag["url"])
    os.system("ping -nc 2 " + flag["url"])
    time.sleep(1)
    print("ping over")
    # Get the requested data
    info = ce.exact_request(flag["flag"], type="dns")
    print(info)
