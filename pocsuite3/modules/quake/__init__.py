import getpass
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests


class Quake():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.headers = {'User-Agent': 'curl/7.80.0', 'Content-Type': 'application/json'}
        self.credits = 0
        self.conf_path = conf_path
        self.token = token

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get("Quake", 'token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                self.headers['X-QuakeToken'] = self.token
                resp = requests.get(
                    'https://quake.360.cn/api/v3/user/info', headers=self.headers)

                if 'month_remaining_credit' not in resp.text:
                    logger.info(resp.text)

                if resp and resp.status_code == 200 and resp.json()['code'] == 0:
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        while True:
            new_token = getpass.getpass("Quake API token: (input will hidden)")
            self.token = new_token
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The Quake api token is incorrect. "
                             "Please enter the correct api token.")

    def write_conf(self):
        if not self.parser.has_section("Quake"):
            self.parser.add_section("Quake")
        try:
            self.parser.set("Quake", "Token", self.token)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def search(self, dork, pages=2):
        search_result = set()
        data = {"query": dork, "size": 10,
                "ignore_cache": "false", "start": 1}
        try:
            for page in range(1, pages + 1):
                data['start'] = page
                url = "https://quake.360.cn/api/v3/search/quake_service"
                resp = requests.post(
                    url, json=data, headers=self.headers, timeout=80)
                if resp and resp.status_code == 200 and resp.json()['code'] == 0:
                    content = resp.json()
                    for match in content['data']:
                        search_result.add("%s:%s" %
                                          (match['ip'], match['port']))
                else:
                    logger.error("[PLUGIN] Quake:{}".format(resp.text))
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    qk = Quake(token="")
    z = qk.search('app:"F5_BIG-IP"')
    print(z)
