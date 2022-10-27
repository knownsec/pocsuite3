import re
from collections import OrderedDict

import dacite
import yaml
from requests_toolbelt.utils import dump

from pocsuite3.lib.core.common import urlparse
from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.yaml.nuclei.model import Severify
from pocsuite3.lib.yaml.nuclei.operators import ExtractorType, MatcherType
from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import Evaluate
from pocsuite3.lib.yaml.nuclei.protocols.http import (AttackType, HttpExtract,
                                                      HttpMatch, HTTPMethod,
                                                      HttpRequest,
                                                      httpRequestGenerator)
from pocsuite3.lib.yaml.nuclei.templates import Template


def hyphen_to_underscore(dictionary):
    """
    Takes an Array or dictionary and replace all the hyphen('-') in any of its keys with a underscore('_')
    :param dictionary:
    :return: the same object with all hyphens replaced by underscore
    """
    # By default return the same object
    final_dict = dictionary

    # for Array perform this method on every object
    if isinstance(dictionary, list):
        final_dict = []
        for item in dictionary:
            final_dict.append(hyphen_to_underscore(item))

    # for dictionary traverse all the keys and replace hyphen with underscore
    elif isinstance(dictionary, dict):
        final_dict = {}
        for k, v in dictionary.items():
            # If there is a sub dictionary or an array perform this method of it recursively
            if isinstance(dictionary[k], (dict, list)):
                value = hyphen_to_underscore(v)
                final_dict[k.replace('-', '_')] = value
            else:
                final_dict[k.replace('-', '_')] = v

    return final_dict


def expand_preprocessors(data: str) -> str:
    """
    Certain pre-processors can be specified globally anywhere in the template that run as soon as
    the template is loaded to achieve things like random ids generated for each template run.

    randstr can be suffixed by a number, and new random ids will be created for those names too.
    Ex. {{randstr_1}} which will remain same across the template.
    randstr is also supported within matchers and can be used to match the inputs.
    """
    randstr_to_replace = set(m[0] for m in re.findall(r'({{randstr(_\w+)?}})', data))
    for s in randstr_to_replace:
        data = data.replace(s, random_str(27))

    return data


class Nuclei():
    def __init__(self, template, target=''):
        self.yaml_template = template
        self.json_template = yaml.safe_load(expand_preprocessors(self.yaml_template))
        self.template = dacite.from_dict(
            Template, hyphen_to_underscore(self.json_template),
            config=dacite.Config(cast=[Severify, ExtractorType, MatcherType, HTTPMethod, AttackType]))

        self.target = target

        self.execute_options = OrderedDict()
        self.execute_options['stop_at_first_match'] = self.template.stop_at_first_match
        self.execute_options['variables'] = self.template.variables
        self.execute_options['interactsh'] = None

        self.requests = self.template.requests

        self.dynamic_values = OrderedDict()

    def execute_request(self, request: HttpRequest) -> dict:
        results = []
        with requests.Session() as session:
            try:
                for (method, url, kwargs) in httpRequestGenerator(request, self.dynamic_values):
                    try:
                        """
                        Redirection conditions can be specified per each template. By default, redirects are not followed.
                        However, if desired, they can be enabled with redirects: true in request details.
                        10 redirects are followed at maximum by default which should be good enough for most use cases.
                        More fine grained control can be exercised over number of redirects followed by using max-redirects
                        field.
                        """
                        if request.max_redirects:
                            session.max_redirects = request.max_redirects
                        else:
                            session.max_redirects = 10
                        response = session.request(method=method, url=url, **kwargs)
                        logger.debug(dump.dump_all(response).decode('utf-8'))
                    except Exception as e1:
                        logger.debug(str(e1))
                        response = None
                    match_res = HttpMatch(request, response, self.execute_options['interactsh'])
                    extractor_res = HttpExtract(request, response)
                    if match_res and extractor_res:
                        match_res = str(dict(extractor_res[0]))
                    if match_res and request.stop_at_first_match:
                        return match_res
                    results.append(match_res)
                    if response:
                        response.close()
            except Exception as e:
                logger.debug(str(e))
        return results and any(results)

    def execute_template(self):
        '''
        Dynamic variables can be placed in the path to modify its behavior on runtime.
        Variables start with {{ and end with }} and are case-sensitive.
        '''

        u = urlparse(self.target)
        self.dynamic_values['BaseURL'] = self.target
        self.dynamic_values['RootURL'] = f'{u.scheme}://{u.netloc}'
        self.dynamic_values['Hostname'] = u.netloc
        self.dynamic_values['Scheme'] = u.scheme
        self.dynamic_values['Host'] = u.hostname
        self.dynamic_values['Port'] = u.port
        self.dynamic_values['Path'] = '/'.join(u.path.split('/')[0:-1])
        self.dynamic_values['File'] = u.path.split('/')[-1]

        """
        Variables can be used to declare some values which remain constant throughout the template.
        The value of the variable once calculated does not change.
        Variables can be either simple strings or DSL helper functions. If the variable is a helper function,
        it is enclosed in double-curly brackets {{<expression>}}. Variables are declared at template level.

        Example variables:

        variables:
            a1: "test" # A string variable
            a2: "{{to_lower(rand_base(5))}}" # A DSL function variable
        """
        for k, v in self.execute_options['variables'].items():
            self.dynamic_values[k] = Evaluate(v)

        """
        Since release of Nuclei v2.3.6, Nuclei supports using the interact.sh API to achieve OOB based vulnerability scanning
        with automatic Request correlation built in. It's as easy as writing {{interactsh-url}} anywhere in the request.
        """
        if '{{interactsh-url}}' in self.yaml_template or '§interactsh-url§' in self.yaml_template:
            from pocsuite3.lib.yaml.nuclei.protocols.common.interactsh import InteractshClient
            self.execute_options['interactsh'] = InteractshClient()
            self.dynamic_values['interactsh-url'] = self.execute_options['interactsh'].client.domain

        results = []
        for request in self.requests:
            res = self.execute_request(request)
            results.append(res)
            if self.execute_options['stop_at_first_match'] and res:
                return res
        return all(results)

    def run(self):
        return self.execute_template()

    def __str__(self):
        '''
        Convert nuclei template to pocsuite3
        '''
        info = []
        key_convert = {
            'description': 'desc',
            'reference': 'references'
        }
        for k, v in self.json_template['info'].items():
            if k in key_convert:
                k = key_convert.get(k)
            if type(v) in [str]:
                v = f'\'{v.strip()}\''
            if k == 'desc':
                v = f'\'\'{v}\'\''

            info.append(f'    {k} = {v}')

        poc_code = [
            'from pocsuite3.api import POCBase, Nuclei, register_poc\n',
            '\n',
            '\n',
            'class TestPOC(POCBase):\n',
            '\n'.join(info),
            '\n',
            '    def _verify(self):\n',
            '        result = {}\n',
            '        if not self._check():\n',
            '            return self.parse_output(result)\n',
            "        template = '''%s'''\n" % self.yaml_template,
            '        res = Nuclei(template, self.url).run()\n',
            '        if res:\n',
            '            result["VerifyInfo"] = {}\n',
            '            result["VerifyInfo"]["URL"] = self.url\n',
            '            result["VerifyInfo"]["Info"] = {}\n',
            '            result["VerifyInfo"]["Info"]["Severity"] = "%s"\n' % self.template.info.severity.value,
            '            if not isinstance(res, bool):\n'
            '               result["VerifyInfo"]["Info"]["Result"] = {}\n',
            '        return self.parse_output(result)\n',
            '\n',
            '\n',
            'register_poc(TestPOC)\n'
        ]
        return ''.join(poc_code)
