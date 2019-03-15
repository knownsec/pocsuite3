import getpass
import json
import time
from configparser import ConfigParser

from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import get_middle_text, random_str


class CEye(object):
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
                resp = requests.get('http://api.ceye.io/v1/identify', headers=headers)
                if resp and resp.status_code == 200 and "data" in resp.json():
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

    def verify_request(self, flag, type="request"):
        """
        校验ceye接口是否有数据

        :param flag: 输入的flag
        :param type: 请求类型(dns|request),默认是request
        :return: Boolean
        """
        if not self.check_account():
            return False
        ret_val = False
        counts = 3
        url = "http://api.ceye.io/v1/records?token={token}&type={type}&filter={flag}".format(token=self.token,
                                                                                             type=type, flag=flag)
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
        通过访问ceye接口获取相关数据

        :param flag: 输入的flag
        :param type: 请求类型(dns|request),默认是request
        :return:返回获取的数据
        """
        if not self.check_account():
            return ""
        counts = 3
        url = "http://api.ceye.io/v1/records?token={token}&type={type}&filter={flag}".format(token=self.token,
                                                                                             type=type, flag=flag)
        while counts:
            try:
                time.sleep(1)
                resp = requests.get(url)
                if resp and resp.status_code == 200 and flag in resp.text:
                    data = json.loads(resp.text)
                    for item in data["data"]:
                        name = item.get("name", '')
                        pro = "/" + flag
                        suffix = flag
                        t = get_middle_text(name, pro, suffix, 7 + len(flag))
                        if t:
                            return t
                    break
            except Exception as ex:
                logger.warn(ex)
                time.sleep(1)
            counts -= 1
        return False

    def build_request(self, value):
        """
        生成发送的字符串

        :param value: 输入的要发送的信息
        :return: dict { url:返回接收的域名,flag:返回随机的flag }
        Example:
          {
            'url': 'http://htCb.jwm77k.ceye.io/htCbpingaaahtCb',
            'flag': 'htCb'
          }

        """
        if not self.check_account():
            return {"url": "", "flag": ""}
        ranstr = random_str(4)
        domain = self.getsubdomain()
        url = "http://{}.{}/{}{}{}".format(ranstr, domain, ranstr, value, ranstr)
        return {"url": url, "flag": ranstr}

    def getsubdomain(self):
        """
        通过ceye token获取子域名
        :return:返回获取的域名
        """
        r = requests.get("http://api.ceye.io/v1/identify", headers=self.headers).json()
        suffix = ".ceye.io"
        indetify = r["data"]["identify"]
        return indetify + suffix


if __name__ == "__main__":
    ce = CEye()
    # 辅助生成flag字符串
    flag = ce.build_request("HelloWorld!")
    print(flag)
    # 用requests模拟请求
    r = requests.get(flag["url"])
    time.sleep(1)
    print("request over")
    # 获取请求的数据
    info = ce.exact_request(flag["flag"])
    print(info)
