import getpass
from configparser import ConfigParser
from pocsuite3.lib.core.data import paths, logger
from pocsuite3.api import requests


class Censys():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, uid='', secret=''):
        self.headers = {'User-Agent': 'curl/7.80.0', 'Accept': 'application/json'}
        self.uid = uid
        self.secret = secret
        self.conf_path = conf_path
        self.credits = 0
        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.uid = self.uid or self.parser.get("Censys", "uid")
                self.secret = self.secret or self.parser.get("Censys", "secret")
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.secret and self.uid:
            try:
                resp = requests.get("https://search.censys.io/api/v1/account", auth=(self.uid, self.secret),
                                    headers=self.headers)
                if resp.status_code == 200 and 'allowance' in resp.text:
                    js = resp.json()
                    logger.info("[PLUGIN] Censys login success, email: {}".format(js["email"]))
                    self.credits = js["quota"]["allowance"] - js["quota"]["used"]
                    return True
                else:
                    logger.info(resp.text)
            except Exception as ex:
                logger.error(ex)
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        while True:
            new_UID = input("Censys API ID: ")
            new_secret = getpass.getpass("Censys API SECRET: (input will hidden)")
            self.uid = new_UID
            self.secret = new_secret
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The censys api id or secret are incorrect, "
                             "Please enter a correct one.")

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
            cursor = ''
            for page in range(1, pages + 1):
                url = "https://search.censys.io/api/v2/hosts/search"
                data = {
                    "q": dork,  # Search keywords
                    "per_page": 50,
                    "virtual_hosts": "EXCLUDE"
                }
                if cursor:
                    data['cursor'] = cursor
                resp = requests.get(url, params=data, auth=(self.uid, self.secret), headers=self.headers)
                if resp and resp.status_code == 200 and 'result' in resp.json():
                    results = resp.json()['result']['hits']
                    cursor = resp.json()['result']['links']['next']
                    for i in results:
                        ip = i['ip']
                        for j in i['services']:
                            port = j['port']
                            search_result.add(f'{ip}:{port}')
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == '__main__':
    c = Censys()
    ret = c.search("thinkphp", pages=2)
    for i in ret:
        print(i)
