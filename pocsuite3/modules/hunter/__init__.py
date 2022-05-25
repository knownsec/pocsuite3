import getpass
import time
import base64
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger, paths
from pocsuite3.lib.request import requests


class Hunter():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.url = 'https://hunter.qianxin.com/openApi/search'
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.credits = 0
        self.conf_path = conf_path
        self.token = token

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get("Hunter", 'token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                resp = requests.get(
                    f'{self.url}?api-key={self.token}&search=aXA9IjI1NS4yNTUuMjU1LjI1NSI=&page=1&page_size=1',
                    headers=self.headers)

                if 'rest_quota' not in resp.text:
                    logger.info(resp.text)
                    return False

                self.credits = resp.json()['data']['rest_quota']
                return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        while True:
            new_token = getpass.getpass("Hunter API token: (input will hidden)")
            self.token = new_token
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The Hunter api token is incorrect. "
                             "Please enter the correct one.")

    def write_conf(self):
        if not self.parser.has_section("Hunter"):
            self.parser.add_section("Hunter")
        try:
            self.parser.set("Hunter", "Token", self.token)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def search(self, dork, pages=2):
        search_result = set()
        search = base64.urlsafe_b64encode(dork.encode("utf-8")).decode()
        try:
            for page in range(1, pages + 1):
                time.sleep(1)
                resp = requests.get(
                    f'{self.url}?api-key={self.token}&search={search}&page={page}&page_size=20&is_web=3',
                    headers=self.headers, timeout=60)
                if resp and resp.status_code == 200 and resp.json()['code'] == 200:
                    content = resp.json()
                    for i in content['data']['arr']:
                        search_result.add(i['url'])
                else:
                    logger.error("[PLUGIN] Hunter: {}".format(resp.text))
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    ht = Hunter(token="")
    z = ht.search('web.title="Vigor 2960"')
    print(z)
