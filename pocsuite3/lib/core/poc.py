# pylint: disable=E1101
import time
import re
import traceback
import inspect
from collections import OrderedDict

from requests.exceptions import ConnectTimeout, ConnectionError, HTTPError, TooManyRedirects
from pocsuite3.lib.core.common import mosaic, check_port, OrderedSet, get_host_ip
from pocsuite3.lib.core.data import conf, logger
from pocsuite3.lib.core.enums import OUTPUT_STATUS, CUSTOM_LOGGING, ERROR_TYPE_ID, POC_CATEGORY
from pocsuite3.lib.core.exception import PocsuiteValidationException
from pocsuite3.lib.core.interpreter_option import OptString, OptInteger, OptPort
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import urlparse


class POCBase(object):
    def __init__(self):
        # PoC attributes
        self.vulID = getattr(self, 'vulID', '0')
        self.version = getattr(self, 'version', '1')
        self.author = getattr(self, 'author', '')
        self.vulDate = getattr(self, 'vulDate', '')
        self.createDate = getattr(self, 'createDate', '')
        self.updateDate = getattr(self, 'updateDate', '')
        self.references = getattr(self, 'references', [])
        self.name = getattr(self, 'name', '')
        self.appPowerLink = getattr(self, 'appPowerLink', '')
        self.appName = getattr(self, 'appName', '')
        self.appVersion = getattr(self, 'appVersion', '')
        self.vulType = getattr(self, 'vulType', '')
        self.desc = getattr(self, 'desc', '')
        self.samples = getattr(self, 'samples', [])
        self.install_requires = getattr(self, 'install_requires', [])
        self.dork = getattr(self, 'dork', {})
        self.suricata_request = getattr(self, 'suricata_request', '')
        self.suricata_response = getattr(self, 'suricata_response', '')
        #
        self.type = None
        self.target = None
        self.headers = None
        self.url = None
        self.scheme = None
        self.rhost = None
        self.rport = None
        self.netloc = None
        self.mode = None
        self.params = None
        self.verbose = None
        self.expt = (0, 'None')
        self.current_protocol = getattr(self, "protocol", POC_CATEGORY.PROTOCOL.HTTP)
        self.current_protocol_port = getattr(self, "protocol_default_port", 0)
        self.pocDesc = getattr(self, "pocDesc", "Poc的作者好懒呀！")
        self.host_ip = get_host_ip(check_private=False)

        # gloabl options init
        self.global_options = OrderedDict()
        if self.current_protocol == POC_CATEGORY.PROTOCOL.HTTP:
            self.global_options["target"] = OptString("",
                                                      "Target HTTP, IPv4, IPv6 address or file with ip:port (file://)",
                                                      require=True)
            self.global_options["referer"] = OptString("", "HTTP Referer header value")
            self.global_options["agent"] = OptString("", "HTTP User-Agent header value")
            self.global_options["proxy"] = OptString(
                "", "Use a proxy to connect to the target URL (protocol://host:port)")
            self.global_options["timeout"] = OptInteger(10, "Seconds to wait before timeout connection (default 10)")
        else:
            self.global_options["rhost"] = OptString('', 'The target host', require=True)
            self.global_options["rport"] = OptPort('', 'The target port', require=True)

        # payload options for exploit
        self.payload_options = OrderedDict()
        if hasattr(self, "_shell"):
            self.payload_options["lhost"] = OptString(self.host_ip, "The listen address")
            self.payload_options["lport"] = OptPort(6666, "The listen port")

        self.options = OrderedDict()
        # module options init
        if hasattr(self, "_options"):
            self.options.update(self._options())

    def get_options(self):
        tmp = OrderedDict()
        for k, v in self.options.items():
            tmp[k] = v
        for k, v in self.payload_options.items():
            tmp[k] = v
        for k, v in self.global_options.items():
            tmp[k] = v
        return tmp
        # return self.options.update(self.global_options).update(self.payload_options)

    def get_option(self, name):
        if name not in self.options:
            raise PocsuiteValidationException
        # 处理options中的payload, 将Payload的IP和端口转换
        value = self.options[name].value
        flag = re.search(r'\{0\}.+\{1\}', str(value))
        if flag:
            value = value.format(conf.connect_back_host, conf.connect_back_port)
        return value

    def get_infos(self):
        '''
        得到Poc的信息，返回dict
        :return:
        '''
        fields = ["name", "VulID", "version", "author", "vulDate", "createDate", "updateDate", "references",
                  "appPowerLink", "appName", "appVersion", "vulType", "desc", "pocDesc", "current_protocol"]
        data = {
        }

        for field in fields:
            value = getattr(self, field, None)
            if value:
                data[field] = value

        return data

    def getg_option(self, name):
        if name not in self.global_options:
            raise PocsuiteValidationException
        r = self.global_options[name].value if self.global_options[name].value != "" else 0
        return r

    def getp_option(self, name):
        if name not in self.payload_options:
            raise PocsuiteValidationException
        return self.payload_options[name].value

    def get_category(self):
        return self.category if hasattr(self, 'category') else 'Unknown'

    def set_options(self, kwargs):
        if hasattr(self, 'options'):
            self.options.update(kwargs)
        else:
            self.options = kwargs

    def set_option(self, key, value):
        # if not hasattr(self, 'options'):
        #     self.options = {}
        if key not in self.options:
            raise PocsuiteValidationException("No key " + key)
        self.options[key].__set__("", value)

    def setg_option(self, key, value):
        if key not in self.global_options:
            raise PocsuiteValidationException("No key " + key)
        self.global_options[key].__set__("", value)

    def setp_option(self, key, value):
        if key not in self.payload_options:
            raise PocsuiteValidationException("No key " + key)
        self.payload_options[key].__set__("", value)

    def check_requirement(self, *args):
        for option in args:
            for k, v in option.items():
                if v.require and v.value == "":
                    raise PocsuiteValidationException(
                        "'{key}' must be set, please using command 'set {key}'".format(key=k))
        return True

    def build_url(self, target=''):
        if not target:
            target = self.target
        # https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
        protocol_default_port_map = {
            POC_CATEGORY.PROTOCOL.FTP: 21,
            POC_CATEGORY.PROTOCOL.SSH: 22,
            POC_CATEGORY.PROTOCOL.TELNET: 23,
            POC_CATEGORY.PROTOCOL.REDIS: 6379,
            POC_CATEGORY.PROTOCOL.SMTP: 25,
            POC_CATEGORY.PROTOCOL.DNS: 53,
            POC_CATEGORY.PROTOCOL.SNMP: 161,
            POC_CATEGORY.PROTOCOL.SMB: 445,
            POC_CATEGORY.PROTOCOL.MQTT: 1883,
            POC_CATEGORY.PROTOCOL.MYSQL: 3306,
            POC_CATEGORY.PROTOCOL.RDP: 3389,
            POC_CATEGORY.PROTOCOL.UPNP: 1900,
            POC_CATEGORY.PROTOCOL.AJP: 8009,
            POC_CATEGORY.PROTOCOL.XMPP: 5222,
            POC_CATEGORY.PROTOCOL.WINBOX: 8291,
            POC_CATEGORY.PROTOCOL.MEMCACHED: 11211,
            POC_CATEGORY.PROTOCOL.BACNET: 47808,
            POC_CATEGORY.PROTOCOL.T3: 7001,
        }

        if self.current_protocol_port:
            protocol_default_port_map[self.current_protocol] = self.current_protocol_port

        try:
            pr = urlparse(target)
            is_ipv6 = pr.netloc.startswith('[')
            self.scheme = pr.scheme
            self.rhost = pr.hostname
            self.rport = pr.port or self.current_protocol_port

            # if protocol is not provided and the port endswith 443, we adjust the protocol to https
            if (self.current_protocol not in protocol_default_port_map or
                    self.current_protocol == POC_CATEGORY.PROTOCOL.HTTP):
                if self.scheme not in ['http', 'https']:
                    self.scheme = 'https' if str(self.rport).endswith('443') else 'http'
                self.rport = self.rport if self.rport else 443 if self.scheme == 'https' else 80

            else:
                # adjust protocol
                self.scheme = self.current_protocol.lower()
                # adjust port
                if not self.rport:
                    self.rport = protocol_default_port_map[self.current_protocol]
            self.netloc = f'[{self.rhost}]:{self.rport}' if is_ipv6 else f'{self.rhost}:{self.rport}'
            pr = pr._replace(scheme=self.scheme)
            pr = pr._replace(netloc=self.netloc)
            target = pr.geturl()
        except ValueError:
            pass
        if self.target and self.current_protocol != POC_CATEGORY.PROTOCOL.HTTP and not conf.console_mode:
            self.setg_option("rhost", self.rhost)
            self.setg_option("rport", self.rport)
        return target.rstrip('/')

    def _execute(self):
        if self.mode == 'shell':
            if not hasattr(self, "_shell"):
                raise NotImplementedError
            output = self._shell()
        elif self.mode == 'attack':
            output = self._attack()
        else:
            output = self._verify()

        return output

    def execute(self, target, headers=None, params=None, mode='verify', verbose=True):
        self.target = target
        self.url = self.build_url()
        if self.url != self.target:
            logger.debug(f'auto correct url: {mosaic(self.target)} -> {mosaic(self.url)}')
        # TODO: Thread safe problem in self.headers
        # https://github.com/knownsec/pocsuite3/issues/262
        # The value should not be modified in PoC Plugin !!!
        # Some PoC use this bug as a feature, For the purpose of PoC plugin compatibility, it will not be fixed
        self.headers = headers
        if isinstance(params, dict) or isinstance(params, str):
            self.params = params
        else:
            self.params = {}
        self.mode = mode
        self.verbose = verbose
        self.expt = (0, 'None')
        # TODO
        output = None

        try:
            output = self._execute()

        except NotImplementedError as e:
            self.expt = (ERROR_TYPE_ID.NOTIMPLEMENTEDERROR, e)
            logger.log(CUSTOM_LOGGING.ERROR, 'POC: {0} not defined "{1}" mode'.format(self.name, self.mode))
            output = Output(self)

        except ConnectTimeout as e:
            self.expt = (ERROR_TYPE_ID.CONNECTTIMEOUT, e)
            while conf.retry > 0:
                logger.debug('connect target {0} timeout, retry it.'.format(mosaic(target)))
                try:
                    output = self._execute()
                    break
                except Exception:
                    logger.debug('target {0} retry failed!'.format(mosaic(target)))
                conf.retry -= 1
            if output is None:
                msg = "connect target '{0}' failed!".format(mosaic(target))
                logger.error(msg)
                output = Output(self)

        except HTTPError as e:
            self.expt = (ERROR_TYPE_ID.HTTPERROR, e)
            logger.warn('target {0} HTTPError occurs.'.format(mosaic(target)))
            output = Output(self)

        except ConnectionError as e:
            self.expt = (ERROR_TYPE_ID.CONNECTIONERROR, e)
            msg = "connect target '{0}' failed!".format(mosaic(target))
            logger.error(msg)
            output = Output(self)

        except TooManyRedirects as e:
            self.expt = (ERROR_TYPE_ID.TOOMANYREDIRECTS, e)
            logger.debug(str(e))
            output = Output(self)

        except BaseException as e:
            self.expt = (ERROR_TYPE_ID.OTHER, e)
            logger.error("PoC has raised a exception")
            logger.error(str(traceback.format_exc()))
            # logger.exception(e)
            output = Output(self)
        if output:
            output.params = self.params
        return output

    def _check(self, dork='', allow_redirects=False, return_obj=False, is_http=True, honeypot_check=True):
        if conf.get('no_check', False):
            return True

        u = urlparse(self.url)
        # the port closed
        if u.port and not check_port(u.hostname, u.port):
            logger.debug(f'{mosaic(self.url)}, the port is closed.')
            return False

        if is_http is False or self.current_protocol != POC_CATEGORY.PROTOCOL.HTTP:
            return True

        res = None
        # this only covers most cases
        redirect_https_keyword = [
            # https://www.zoomeye.org/searchResult?q=%22request%20was%20sent%20to%20HTTPS%20port%22
            'request was sent to https port',
            # https://www.zoomeye.org/searchResult?q=%22running%20in%20SSL%20mode.%20Try%22
            'running in ssl mode. try'
        ]
        redirect_https_keyword_found = False
        origin_url = self.url
        netloc = self.url.split('://', 1)[-1]
        urls = OrderedSet()
        urls.add(self.url)
        urls.add(f'http://{netloc}')

        # The user has not provided a port in URL, dynamically switching to HTTPS's default port 443
        pr = urlparse(self.url)
        is_ipv6 = pr.netloc.startswith('[')
        if ':' not in self.target.split('://')[-1] and pr.port == 80:
            pr = pr._replace(scheme='https')
            pr = pr._replace(netloc=f'[{pr.hostname}]:443' if is_ipv6 else f'{pr.hostname}:443')
            urls.add(pr.geturl())
        else:
            urls.add(f'https://{netloc}')

        for url in urls:
            try:
                time.sleep(0.1)
                res = requests.get(url, allow_redirects=allow_redirects)
                """
                https://github.com/knownsec/pocsuite3/issues/330
                https://github.com/knownsec/pocsuite3/issues/356
                status_code:
                    - 20x
                    - 30x
                    - 40x
                    - 50x
                """

                # if HTTPS handshake is successful, return directly
                if url.startswith('https://'):
                    break

                # if we send an HTTP request to an HTTPS service, but the server may return 20x
                for k in redirect_https_keyword:
                    if k.lower() in res.text.lower():
                        redirect_https_keyword_found = True
                        break
                if redirect_https_keyword_found:
                    continue

                # if we send an HTTP request to an HTTPS service, the server may return 30x, 40x, or 50x...
                if not str(res.status_code).startswith('20'):
                    continue

                break
            except requests.RequestException:
                pass

        if not isinstance(res, requests.Response):
            return False

        self.url = res.request.url.rstrip('/')
        if res.history:
            self.url = res.history[0].request.url.rstrip('/')

        if self.url.split('://')[0] != self.scheme:
            self.url = self.build_url(self.url)
            logger.warn(f'auto correct url: {mosaic(origin_url)} -> {mosaic(self.url)}')

        if return_obj:
            return res

        content = str(res.headers).lower() + res.text.lower()
        dork = dork.lower()

        if dork not in content:
            return False

        if not honeypot_check:
            return True

        is_honeypot = False

        # detect honeypot
        # https://www.zoomeye.org/searchResult?q=%22GoAhead-Webs%22%20%2B%22Apache-Coyote%22
        keyword = [
            'goahead-webs',
            'apache-coyote',
            'upnp/',
            'openresty',
            'tomcat'
        ]

        sin = 0
        for k in keyword:
            if k in content:
                sin += 1

        if sin >= 3:
            logger.debug(f'honeypot: sin({sin}) >= 3')
            is_honeypot = True

        # maybe some false positives
        elif len(re.findall('<title>(.*)</title>', content)) > 5:
            logger.debug('honeypot: too many title')
            is_honeypot = True

        elif len(re.findall('basic realm=', content)) > 5:
            logger.debug('honeypot: too many www-auth')
            is_honeypot = True

        elif len(re.findall('server: ', content)) > 5:
            logger.debug('honeypot: too many server')
            is_honeypot = True

        if is_honeypot:
            logger.warn(f'{mosaic(self.url)} is a honeypot.')

        return not is_honeypot

    def _shell(self):
        """
        @function   以Poc的shell模式对urls进行检测(具有危险性)
                    需要在用户自定义的Poc中进行重写
                    返回一个Output类实例
        """
        raise NotImplementedError

    def _attack(self):
        """
        @function   以Poc的attack模式对urls进行检测(可能具有危险性)
                    需要在用户自定义的Poc中进行重写
                    返回一个Output类实例
        """
        raise NotImplementedError

    def _verify(self):
        """
        @function   以Poc的verify模式对urls进行检测(可能具有危险性)
                    需要在用户自定义的Poc中进行重写
                    返回一个Output类实例
        """
        raise NotImplementedError

    def parse_output(self, result={}):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

    def _run(self):
        """
        @function   以Poc的GUI模式对url进行检测(可能具有危险性)
                    需要在用户自定义的Poc中进行重写
                    返回一个Output类实例
        """
        raise NotImplementedError


class Output(object):
    def __init__(self, poc=None):
        self.error_msg = tuple()
        self.result = {}
        self.params = {}
        self.status = OUTPUT_STATUS.FAILED
        if poc:
            self.url = poc.url
            self.mode = poc.mode
            self.vul_id = poc.vulID
            self.name = poc.name
            self.app_name = poc.appName
            self.app_version = poc.appVersion
            self.error_msg = poc.expt
            self.poc_attrs = {}
            for i in inspect.getmembers(poc):
                if not i[0].startswith('_') and type(i[1]) in [str, list, dict]:
                    self.poc_attrs[i[0]] = i[1]

    def is_success(self):
        return bool(True and self.status)

    def success(self, result):
        assert isinstance(result, dict)
        self.status = OUTPUT_STATUS.SUCCESS
        self.result = result

    def fail(self, error=""):
        assert isinstance(error, str)
        self.status = OUTPUT_STATUS.FAILED
        self.error_msg = (0, error)

    def error(self, error=""):
        self.expt = (ERROR_TYPE_ID.OTHER, error)
        self.error_msg = (0, error)

    def show_result(self):
        if self.status == OUTPUT_STATUS.SUCCESS:
            for k, v in self.result.items():
                if isinstance(v, dict):
                    for kk, vv in v.items():
                        if (kk == "URL" or kk == "IP"):
                            vv = mosaic(vv)
                        logger.log(CUSTOM_LOGGING.SUCCESS, "%s : %s" % (kk, vv))
                else:
                    if (k == "URL" or k == "IP"):
                        v = mosaic(v)
                    logger.log(CUSTOM_LOGGING.SUCCESS, "%s : %s" % (k, v))

    def to_dict(self):
        return self.__dict__
