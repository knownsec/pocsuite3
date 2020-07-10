import pychrome

# from configparser import ConfigParser
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import paths


class Google():
    def __init__(self):
        pass

    def search(self, dork):
        search_result = set()
        # create a browser instance
        browser = pychrome.Browser(url="http://127.0.0.1:9222")
        # create a tab
        tab = browser.new_tab()
        # start the tab
        tab.start()
        tab.Page.enable()
        # call method
        tab.Network.enable()
        tab.Runtime.enable()
        start = 1000

        for step in range(0, start+10, 10):

            url = "https://www.google.com/search?q={}".format(dork)
            url = url+"&start={}".format(step)
            # stepinfo="step:"+str(step)
            # logger.info(stepinfo)

            try:
                # call method with timeout
                tab.Page.navigate(url=url, _timeout=5)
                tab.wait(5)

                exp = 'document.getElementsByClassName("r").length'
                length = tab.Runtime.evaluate(expression=exp)
                # google就看报不报错，报错了的话document.getElementsByClassName("r").length是为0的
                if length['result']['value'] == 0:
                    logger.warn("[PLUGIN] Google Dork get 0, Exit")
                    break

                # 从每一页上抓取url
                for l in range(0, length['result']['value']):
                    # tab.wait(1)
                    exp1 = 'document.getElementsByClassName("r")[{}].getElementsByTagName("a")[0].href'.format(
                        l)
                    res1 = tab.Runtime.evaluate(expression=exp1)
                    logger.info(res1['result']['value'])
                    search_result.add(res1['result']['value'])
            except Exception as ex:
                logger.error(str(ex))

        tab.stop()
        browser.close_tab(tab)
        return search_result


if __name__ == "__main__":
    go = Google()
    print(go.search('site:i.mi.com'))
