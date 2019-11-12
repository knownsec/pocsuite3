import urllib
import getpass
from base64 import b64encode
from configparser import ConfigParser
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.request import requests


class Fofa():
    def __init__(self, conf_path=paths.POCSUITE_RC_PATH, user=None, token=None):
        self.headers = None
        self.credits = 0
        self.conf_path = conf_path

        if self.conf_path:
            self.parser = ConfigParser()
            self.parser.read(self.conf_path)
            try:
                self.token = self.parser.get("Fofa", 'token')
                self.user = self.parser.get("Fofa", 'user')
            except Exception:
                pass

        if token or user:
            self.user = user
            self.token = token
        self.check_token()

    def token_is_available(self):
        if self.token and self.user:
            try:
                resp = requests.get(
                    'https://fofa.so/api/v1/info/my?email={user}&key={token}'.format(user=self.user, token=self.token))
                if resp and resp.status_code == 200 and "username" in resp.json():
                    return True
            except Exception as ex:
                logger.error(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        else:

            user = input("Fofa API user:")
            new_token = getpass.getpass("Fofa API  token:")
            self.token = new_token
            self.user = user
            if self.token_is_available():
                self.write_conf()
                return True
            else:
                logger.error("The Fofa api token is incorrect. "
                             "Please enter the correct api token.")
                self.check_token()

    def write_conf(self):
        if not self.parser.has_section("Fofa"):
            self.parser.add_section("Fofa")
        try:
            self.parser.set("Fofa", "Token", self.token)
            self.parser.set("Fofa", "User", self.user)
            self.parser.write(open(self.conf_path, "w"))
        except Exception as ex:
            logger.error(str(ex))

    def search(self, dork, pages=1, resource='ip,port'):
        if resource == 'host':
            resource = 'ip,port'
        else:
            resource="web"
        search_result = set()
        try:
            for page in range(1, pages + 1):
                url = "https://fofa.so/api/v1/search/all?email={user}&key={token}&qbase64={dork}&fields={resource}&page={page}".format(
                    user=self.user, token=self.token, dork=b64encode(dork.encode()).decode(), resource=resource, page=page)
                resp = requests.get(url,timeout=80)
                if resp and resp.status_code == 200 and "results" in resp.json():
                    content = resp.json()
                    for match in content['results']:
                        if resource == "ip,port":
                            search_result.add("%s:%s"%(match[0],match[1]))
                        else:
                            if not  match.startswith("https://"):
                                search_result.add("http://"+match)
                            else:
                                search_result.add(match)
                else:
                    logger.error("[PLUGIN] Fofa:{}".format(resp.text))
        except Exception as ex:
            logger.error(str(ex))
        return search_result


if __name__ == "__main__":
    fa = Fofa()
    z = fa.search('body="thinkphp"')
    print(z)
