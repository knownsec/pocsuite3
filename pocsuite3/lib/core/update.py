import sys
from pocsuite3.lib.core.data import logger, conf
from six.moves.xmlrpc_client import ServerProxy
from pkg_resources import parse_version
from pocsuite3 import __version__


def update():
    if not conf.update_all:
        return
    logger.info('Checking the latest version number of pocsuite3 on pypi')
    client = ServerProxy('https://pypi.python.org/pypi')
    versions = client.package_releases('pocsuite3', True)
    upstream_version = max(map(parse_version, versions))
    current_version = parse_version(__version__)
    logger.info(f'Current upstream version: {upstream_version}')
    if current_version < upstream_version:
        logger.info(''
                    '----[ 1.1 - Installtion & Upgrade Methods\n'
                    '\n'
                    'Python pip\n'
                    '\n'
                    '    $ pip3 install -U pocsuite3\n'
                    '\n'
                    '    $ use other pypi mirror\n'
                    '    $ pip3 install -U -i https://pypi.tuna.tsinghua.edu.cn/simple pocsuite3\n'
                    '\n'
                    'MacOS\n'
                    '\n'
                    '    $ brew install pocsuite3\n'
                    '\n'
                    'Kali, Ubuntu 22.04, Debian\n'
                    '\n'
                    '    $ sudo apt-get install pocsuite3\n'
                    '\n'
                    'Docker\n'
                    '\n'
                    '    $ docker run -it pocsuite3/pocsuite3\n'
                    '\n'
                    'ArchLinux\n'
                    '\n'
                    '    $ yay pocsuite3\n'
                    '\n'
                    'Install from source code\n'
                    '\n'
                    '    $ wget https://github.com/knownsec/pocsuite3/archive/master.zip\n'
                    '    $ unzip master.zip\n'
                    '    $ cd pocsuite3-master\n'
                    '    $ pip3 install -r requirements.txt\n'
                    '    $ python3 setup.py install\n')
    sys.exit(-1)
