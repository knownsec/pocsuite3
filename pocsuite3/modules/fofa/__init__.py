import getpass
import time
from base64 import b64encode
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.core.common import is_ipv6_address_format
from pocsuite3.lib.request import requests


class Fofa():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, user=None, token=None):
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.credits = 0
        self.conf_path = conf_path
        self.user = user
        self.token = token
        self.api_url = 'https://fofa.info/api/v1'

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.user = self.user or self.parser.get("Fofa", 'user')
                self.token = self.token or self.parser.get("Fofa", 'token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token and self.user:
            try:
                resp = requests.get(
                    f'{self.api_url}/info/my?email={self.user}&key={self.token}',
                    headers=self.headers)
                logger.info(resp.text)
                if resp and resp.status_code == 200 and "username" in resp.json():
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True

        while True:
            user = input("Fofa user email: ")
            new_token = getpass.getpass("Fofa api key: (input will hidden) ")
            self.token = new_token
            self.user = user
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The Fofa user email or api key are incorrect, Please enter the correct one.")

    def write_conf(self):
        if not self.parser.has_section("Fofa"):
            self.parser.add_section("Fofa")
        try:
            self.parser.set("Fofa", "Token", self.token)
            self.parser.set("Fofa", "User", self.user)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def search(self, dork, pages=1, resource='host'):
        if resource == 'host':
            resource = 'protocol,ip,port'
        else:
            resource = 'protocol,host'

        dork = b64encode(dork.encode()).decode()
        search_result = set()

        try:
            for page in range(1, pages + 1):
                time.sleep(1)
                url = (
                    f"{self.api_url}/search/all?email={self.user}&key={self.token}&qbase64={dork}&"
                    f"fields={resource}&page={page}"
                )
                resp = requests.get(url, headers=self.headers, timeout=60)
                if resp and resp.status_code == 200 and "results" in resp.json():
                    content = resp.json()
                    for match in content['results']:
                        if resource == "protocol,ip,port":
                            ip = match[1]
                            if is_ipv6_address_format(ip):
                                ip = f'[{ip}]'
                            search_result.add("%s://%s:%s" % (match[0], ip, match[2]))
                        else:
                            if '://' not in match[1]:
                                search_result.add("%s://%s" % (match[0], match[1]))
                            else:
                                search_result.add(match[1])
                else:
                    logger.error("[PLUGIN] Fofa:{}".format(resp.text))
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    fa = Fofa()
    z = fa.search('body="thinkphp"', pages=2)
    print(z)
    z = fa.search('body="thinkphp"', resource='web')
    print(z)
