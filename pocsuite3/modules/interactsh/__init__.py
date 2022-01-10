#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import random
import time
from uuid import uuid4
from base64 import b64encode
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from pocsuite3.api import requests, logger, random_str


class Interactsh:
    def __init__(self, token='', server=''):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server.lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, verify=False)
        if 'success' not in res.text:
            logger.error(res.text)

    def poll(self):
        count = 3
        result = []
        while count:

            try:
                url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
                res = self.session.get(url, headers=self.headers, verify=False).json()
                aes_key, data_list = res['aes_key'], res['data']
                for i in data_list:
                    decrypt_data = self.decrypt_data(aes_key, i)
                    result.append(decrypt_data)
                return result
            except Exception as e:
                logger.debug(e)
                count -= 1
                time.sleep(1)
                continue
        return []

    def decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def build_request(self, length=10, method='https'):
        """
        Generate the url and flag for verification

        :param length: The flag length
        :param method: Request type (dns|https|http), the default is https
        :return: dict { url: Return the request url, flag: Return a random flag }
        Example:
          {
            'url': 'http://hqlbbwmo8u.7735s13s04hp4eu19s4q8n963n73jw6hr.interactsh.com',
            'flag': 'hqlbbwmo8u'
          }

        """
        flag = random_str(length).lower()
        url = f'{flag}.{self.domain}'
        if method.startswith('http'):
            url = f'{method}://{url}'
        return url, flag

    def verify(self, flag, get_result=False):
        """
        Check the flag

        :param flag: The flag to verify
        :param get_result: Whether to return detailed results
        :return: Boolean
        """
        result = self.poll()
        for item in result:
            if flag.lower() in item['full-id'].lower():
                return (True, result) if get_result else True
        return (False, result) if get_result else False


if __name__ == "__main__":
    ISH = Interactsh(token="", server="")
    url, flag = ISH.build_request()
    requests.get(url, timeout=5, verify=False)
    print(ISH.verify(flag, get_result=True))
