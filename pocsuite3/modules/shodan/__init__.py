import urllib
import getpass
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests


class Shodan():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, token=None):
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.credits = 0
        self.conf_path = conf_path
        self.token = token

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.token or self.parser.get("Shodan", 'Token')
            except Exception:
                pass

        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                resp = requests.get(
                    'https://api.shodan.io/account/profile?key={0}'.format(self.token), headers=self.headers)
                logger.info(resp.text)
                if resp and resp.status_code == 200 and "member" in resp.json():
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True

        while True:
            new_token = getpass.getpass("Shodan API Token: (input will hidden)")
            self.token = new_token
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The shodan api token is incorrect. "
                             "Please enter the correct api token.")

    def write_conf(self):
        if not self.parser.has_section("Shodan"):
            self.parser.add_section("Shodan")
        try:
            self.parser.set("Shodan", "Token", self.token)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def get_resource_info(self):
        try:
            resp = requests.get(
                'https://api.shodan.io/account/profile?key={0}'.format(self.token), headers=self.headers)
            if resp and resp.status_code == 200 and 'credits' in resp.json():
                content = resp.json()
                self.credits = content['credits']
                return True
        except Exception as ex:
            logger.error(str(ex))
        return False

    def search(self, dork, pages=1, resource='host'):
        # shodan rest api only support host search
        resource = 'host'
        search_result = set()
        try:
            for page in range(1, pages + 1):
                url = (
                    "https://api.shodan.io/shodan/{0}/search?key={1}&query={2}&page={3}"
                ).format(resource, self.token, urllib.parse.quote(dork), page)
                resp = requests.get(url, headers=self.headers)
                if resp and resp.status_code == 200 and "total" in resp.json():
                    content = resp.json()
                    for match in content['matches']:
                        ans = match['ip_str']
                        if 'port' in match:
                            ans += ':' + str(match['port'])
                        search_result.add(ans)
                else:
                    logger.error("[PLUGIN] Shodan:{}".format(resp.text))
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    sd = Shodan()
    sd.search('dedecms')
