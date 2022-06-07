import getpass
import json
import os
import time
import re
from configparser import ConfigParser

from pocsuite3.api import conf
from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import get_middle_text, random_str


class CEye(object):
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.url = 'http://api.ceye.io/v1'
        self.identify = ''
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.token = token
        if 'ceye_token' in conf:
            self.token = self.token or conf.ceye_token
        self.conf_path = conf_path

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get('CEye', 'token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                self.headers['Authorization'] = self.token
                resp = requests.get(f'{self.url}/identify', headers=self.headers)
                if resp and resp.status_code == 200 and 'identify' in resp.text:
                    self.identify = resp.json()['data']['identify']
                    return True
                else:
                    logger.info(resp.text)
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_account(self):
        return self.check_token()

    def check_token(self):
        if self.token_is_available():
            return True

        while True:
            self.token = getpass.getpass('CEye API token: (input will hidden)')
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error('The CEye api token is incorrect, Please enter the correct api token.')

    def write_conf(self):
        if not self.parser.has_section('CEye'):
            self.parser.add_section('CEye')
        try:
            self.parser.set('CEye', 'token', self.token)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def verify_request(self, flag, type='request'):
        """
        Check whether the ceye interface has data

        :param flag: Input flag
        :param type: Request type (dns|request), the default is request
        :return: Boolean
        """
        ret_val = False
        counts = 3
        url = f'{self.url}/records?token={self.token}&type={type}&filter={flag}'
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
        url = f'{self.url}/records?token={self.token}&type={type}&filter={flag}'
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
        if type in ["request", 'http']:
            url = "http://{}.{}/{}{}{}".format(ranstr, domain, ranstr, value, ranstr)
        elif type == "dns":
            url = "{}{}{}.{}".format(ranstr, re.sub(r"\W", "", value), ranstr, domain)
        return {"url": url, "flag": ranstr}

    def getsubdomain(self):
        """
        :return: Return the obtained domain name
        """
        return f'{self.identify}.ceye.io'


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
