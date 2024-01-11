import hmac
import hashlib
import base64
import urllib.parse
import requests
import time

from pocsuite3.api import PLUGIN_TYPE, get_results
from pocsuite3.api import PluginBase
from pocsuite3.api import logger
from pocsuite3.api import register_plugin, conf

DINGTALK_TOKEN = ""
DINGTALK_SECRET = ""
WX_WORK_KEY = ""


def dingding_send(msg, access_token, secret, msgtype="markdown", title="pocsuite3消息推送"):
    ding_url = "https://oapi.dingtalk.com/robot/send?access_token={}".format(access_token)
    timestamp = str(round(time.time() * 1000))
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    param = "&timestamp={}&sign={}".format(timestamp, sign)
    ding_url = ding_url + param
    send_json = {
        "msgtype": msgtype,
        "markdown": {
            "title": title,
            "text": "# pocsuite3消息推送\n\n" + msg
        }
    }
    requests.post(ding_url, json=send_json)


def wx_work_send(msg, key):
    webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + key
    send_data = {
        "msgtype": "markdown",
        "markdown": {
            "content": "# pocsuite3消息推送\n\n" + msg
        }
    }
    requests.post(webhook_url, json=send_data)


def web_hook_send(msg):
    dingtalk_token = conf.dingtalk_token or DINGTALK_TOKEN
    dingtalk_secret = conf.dingtalk_secret or DINGTALK_SECRET
    wx_work_key = conf.wx_work_key or WX_WORK_KEY
    if dingtalk_token and dingtalk_secret:
        dingding_send(msg, dingtalk_token, dingtalk_secret)
    if wx_work_key:
        wx_work_send(msg, wx_work_key)


class WebHook(PluginBase):
    category = PLUGIN_TYPE.RESULTS

    def init(self):
        debug_msg = "[PLUGIN] web hook plugin init..."
        logger.debug(debug_msg)

    def start(self):
        push_info = ""
        for result in get_results():
            if result.status == "success":
                poc_name = result.get("poc_name")
                target = result.get("target")
                push_info += "- {} found vuln: {}".format(target, poc_name)
        web_hook_send(push_info)


register_plugin(WebHook)
