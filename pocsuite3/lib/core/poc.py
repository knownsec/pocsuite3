import re
import traceback
from collections import OrderedDict
from urllib.parse import urlparse

from requests.exceptions import ConnectTimeout
from requests.exceptions import ConnectionError
from requests.exceptions import HTTPError
from requests.exceptions import TooManyRedirects

from pocsuite3.lib.core.common import parse_target_url, desensitization
from pocsuite3.lib.core.data import conf
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.enums import OUTPUT_STATUS, CUSTOM_LOGGING, ERROR_TYPE_ID, POC_CATEGORY
from pocsuite3.lib.core.exception import PocsuiteValidationException
from pocsuite3.lib.core.interpreter_option import OptString, OptInteger, OptIP, OptPort, OptBool
from pocsuite3.lib.utils import str_to_dict
# for pocsuite 2.x
from pocsuite3.lib.core.register import register_poc as register


class POCBase(object):
    def __init__(self):
        self.type = None
        self.target = None
        self.headers = None
        self.url = None
        self.mode = None
        self.params = None
        self.verbose = None
        self.expt = (0, 'None')
        self.current_protocol = getattr(self, "protocol", POC_CATEGORY.PROTOCOL.HTTP)
        self.pocDesc = getattr(self, "pocDesc", "Poc的作者好懒呀！")

        # gloabl options init
        self.global_options = OrderedDict()
        if self.current_protocol == POC_CATEGORY.PROTOCOL.HTTP:
            self.global_options["target"] = OptString("",
                                                      "Target HTTP, IPv4, IPv6 address or file with ip:port (file://)",
                                                      require=True)
            self.global_options["referer"] = OptString("", "HTTP Referer header value")
            self.global_options["agent"] = OptString("", "HTTP User-Agent header value")
            self.global_options["proxy"] = OptString("", "Use a proxy to connect to the target URL")
            self.global_options["timeout"] = OptInteger(30, "Seconds to wait before timeout connection (default 30)")
        else:
            self.global_options["rhost"] = OptString('', require=True)
            self.global_options["rport"] = OptPort('', require=True)
            self.global_options["ssl"] = OptBool(default=False)

        # payload options for exploit
        self.payload_options = OrderedDict()
        if hasattr(self, "_shell"):
            self.payload_options["lhost"] = OptString('', "Connect back ip", require=True)
            self.payload_options["lport"] = OptPort(10086, "Connect back port")

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
        # 处理options中的payload,将Payload的IP和端口转换
        value = self.options[name].value
        flag = re.search('\{0\}.+\{1\}', str(value))
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
                        "'{key}' must be set,please using command 'set {key}'".format(key=k))
        return True

    def build_url(self):
        if self.target and not conf.console_mode:
            pr = urlparse(parse_target_url(self.target))
            rport = pr.port if pr.port else 0
            rhost = pr.hostname
            ssl = False
            if pr.scheme == 'https':
                ssl = True
            self.setg_option("rport", rport)
            self.setg_option("rhost", rhost)
            self.setg_option("ssl", ssl)
        return parse_target_url(self.target)

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
        self.url = parse_target_url(target) if self.current_protocol == POC_CATEGORY.PROTOCOL.HTTP else self.build_url()
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
                logger.debug('POC: {0} timeout, start it over.'.format(self.name))
                try:
                    output = self._execute()
                    break
                except ConnectTimeout:
                    logger.debug('POC: {0} time-out retry failed!'.format(self.name))
                conf.retry -= 1
            else:
                msg = "connect target '{0}' failed!".format(desensitization(target) if conf.ppt else target)
                logger.error(msg)
                output = Output(self)

        except HTTPError as e:
            self.expt = (ERROR_TYPE_ID.HTTPERROR, e)
            logger.warn('POC: {0} HTTPError occurs, start it over.'.format(self.name))
            output = Output(self)

        except ConnectionError as e:
            self.expt = (ERROR_TYPE_ID.CONNECTIONERROR, e)
            msg = "connect target '{0}' failed!".format(desensitization(target) if conf.ppt else target)
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
        output.params = self.params
        return output

    # def _shell(self):
    #     """
    #     @function   以Poc的shell模式对urls进行检测(具有危险性)
    #                 需要在用户自定义的Poc中进行重写
    #                 返回一个Output类实例
    #     """
    #     raise NotImplementedError

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
                        if (kk == "URL" or kk == "IP") and conf.ppt:
                            vv = desensitization(vv)
                        logger.log(CUSTOM_LOGGING.SUCCESS, "%s : %s" % (kk, vv))
                else:
                    if (k == "URL" or k == "IP") and conf.ppt:
                        v = desensitization(v)
                    logger.log(CUSTOM_LOGGING.SUCCESS, "%s : %s" % (k, v))

    def to_dict(self):
        return self.__dict__
