import json
from configparser import ConfigParser

import requests

from pocsuite3.lib.core.data import paths, logger


class Censys():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, uid='', secret=''):
        self.uid = uid
        self.secret = secret
        self.conf_path = conf_path
        self.credits = 0
        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            if not (self.secret or self.uid):
                try:
                    self.secret = self.parser.get("Censys", "secret")
                    self.uid = self.parser.get("Censys", "uid")
                except Exception:
                    pass

    def token_is_available(self):
        if self.secret and self.uid:
            try:
                resp = requests.get("https://censys.io/api/v1/account", auth=(self.uid, self.secret))
                if resp.status_code == 200 and "email" in resp.json():
                    logger.info("[PLUGIN] Censys login success email:{}".format(resp.json()["email"]))
                    self.credits = resp.json()["quota"]["allowance"] - resp.json()["quota"]["used"]
                    return True
            except Exception as ex:
                logger.error(ex)
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        else:
            new_UID = input("Censys API UID:")
            new_secret = input("Censys API SECRET")
            self.uid = new_UID
            self.secret = new_secret
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The shodan api token is incorrect. "
                             "Please enter the correct api token.")
                self.check_token()

    def write_conf(self):
        if not self.parser.has_section("Censys"):
            self.parser.add_section("Censys")
        try:
            self.parser.set("Censys", "secret", self.secret)
            self.parser.set("Censys", "uid", self.uid)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def get_resource_info(self):
        if self.check_token():
            return True
        return False

    def search(self, dork, pages=1, resource='ipv4'):
        search_result = set()
        try:
            for page in range(1, pages + 1):
                url = "https://censys.io/api/v1/search/{}".format(resource)
                data = {
                    "query": dork,  # 搜索的关键字,
                    "fields": ["ip"],
                    "page": page
                }
                resp = requests.post(url, data=json.dumps(data), auth=(self.uid, self.secret))
                if resp and resp.status_code == 200 and "results" in resp.json():
                    content = resp.json()["results"]
                    for match in content:
                        ans = match["ip"]
                        search_result.add(ans)
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == '__main__':
    c = Censys()
    ret = c.search("apache")
