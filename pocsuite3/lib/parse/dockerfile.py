import re
from pocsuite3.lib.core.data import conf
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.common import get_file_text


def parse_dockerfile(file):
        regx_rules = [
            "name = '(.*)'",
            "vulID = '(.*)'",
            r"dockerfile = '''([\s\S]*?)'''",
        ]
        result = {
            "name": 0,
            "vulID": 1,
            "dockerfile": 2,
        }
        st = get_file_text(file)
        for k, v in result.items():
            pattern = re.compile(regx_rules[v])
            match = pattern.findall(st)
            if match is not None:
                result[k] = match[0]

        return result


