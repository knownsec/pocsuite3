# pocsuite3

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/knownsec/Pocsuite/master/docs/COPYING) [![Twitter](https://img.shields.io/badge/twitter-@seebug-blue.svg)](https://twitter.com/seebug_team) [![build](https://api.travis-ci.org/knownsec/pocsuite3.svg)](https://travis-ci.org/knownsec/pocsuite3)

## Legal Disclaimer
Usage of pocsuite3 for attacking targets without prior mutual consent is illegal.
pocsuite3 is for security testing purposes only

## 法律免责声明
未经事先双方同意，使用 pocsuite3 攻击目标是非法的。
pocsuite3 仅用于安全测试目的

## Overview

pocsuite3 is an open-sourced remote vulnerability testing and proof-of-concept development framework developed by the [**Knownsec 404 Team**](http://www.knownsec.com/). 
It comes with a powerful proof-of-concept engine, many nice features for the ultimate penetration testers and security researchers.

## Features
* PoC scripts can running with `verify`, `attack`, `shell` mode in different way
* Plugin ecosystem
* Dynamic loading PoC script from any where (local file, redis, database, Seebug ...)
* Load multi-target from any where (CIDR, local file, redis, database, Zoomeye, Shodan ...)
* Results can be easily exported
* Dynamic patch and hook requests 
* Both command line tool and python package import to use
* IPV6 support
* Global HTTP/HTTPS/SOCKS proxy support
* Simple spider API for PoC script to use
* Integrate with [Seebug](https://www.seebug.org) (for load PoC from Seebug website)
* Integrate with [ZoomEye](https://www.zoomeye.org) (for load target from ZoomEye `Dork`)
* Integrate with [Shodan](https://www.shodan.io) (for load target from Shodan `Dork`)
* Integrate with [Fofa](https://fofa.info) (for load target from Fofa `Dork`)
* Integrate with [Quake](https://quake.360.cn)(for load target from Quake `Dork`)
* Integrate with [Hunter](https://hunter.qianxin.com) (for load target from Hunter `Dork`)
* Integrate with [Censys](https://censys.io) (for load target from Censys `Dork`)
* Integrate with [Ceye](http://ceye.io/) (for verify blind DNS and HTTP request)
* Integrate with [Interactsh](https://github.com/projectdiscovery/interactsh) (for verify blind DNS and HTTP request)
* Friendly debug PoC scripts with IDEs
* More ...

## Screenshots

### pocsuite3 console mode
[![asciicast](https://asciinema.org/a/219356.png)](https://asciinema.org/a/219356)

### pocsuite3 shell mode
[![asciicast](https://asciinema.org/a/203101.png)](https://asciinema.org/a/203101)

### pocsuite3 load PoC from Seebug 
[![asciicast](https://asciinema.org/a/207350.png)](https://asciinema.org/a/207350)

### pocsuite3 load multi-target from ZoomEye
[![asciicast](https://asciinema.org/a/133344.png)](https://asciinema.org/a/133344)

### pocsuite3 load multi-target from Shodan
[![asciicast](https://asciinema.org/a/207349.png)](https://asciinema.org/a/207349)

## Requirements

- Python 3.7+
- Works on Linux, Windows, Mac OSX, BSD, etc.

## Installation

Paste at a terminal prompt:

### Python pip

``` bash
pip3 install pocsuite3

# use other pypi mirror
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple pocsuite3
```

### MacOS

``` bash
brew update
brew info pocsuite3
brew install pocsuite3
```

### [Debian](https://tracker.debian.org/pkg/pocsuite3), [Ubuntu](https://launchpad.net/ubuntu/+source/pocsuite3), [Kali](http://pkg.kali.org/pkg/pocsuite3)

``` bash
sudo apt update
sudo apt install pocsuite3
```

### Docker

```
docker run -it pocsuite3/pocsuite3
```

### ArchLinux

``` bash
yay pocsuite3
```

###

Or click [here](https://github.com/knownsec/pocsuite3/archive/master.zip) to download the latest source zip package and extract

``` bash
wget https://github.com/knownsec/pocsuite3/archive/master.zip
unzip master.zip
cd pocsuite3-master
pip3 install -r requirements.txt
python3 setup.py install
```


The latest version of this software is available at: https://pocsuite.org

## Documentation

Documentation is available in the [```docs```](./docs) directory.

## Usage

```
cli mode

	# basic usage, use -v to set the log level
	pocsuite -u http://example.com -r example.py -v 2

	# run poc with shell mode
	pocsuite -u http://example.com -r example.py -v 2 --shell

	# search for the target of redis service from ZoomEye and perform batch detection of vulnerabilities. The thread is set to 20
	pocsuite -r redis.py --dork service:redis --threads 20

	# load all poc in the poc directory and save the result as html
	pocsuite -u http://example.com --plugins poc_from_pocs,html_report

	# load the target from the file, and use the poc under the poc directory to scan
	pocsuite -f batch.txt --plugins poc_from_pocs,html_report

	# load CIDR target
	pocsuite -u 10.0.0.0/24 -r example.py --plugins target_from_cidr

	# the custom parameters `command` is implemented in ecshop poc, which can be set from command line options
	pocsuite -u http://example.com -r ecshop_rce.py --attack --command "whoami"

console mode
    poc-console
```

## How to Contribute

1. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
2. Fork [the repository](https://github.com/knownsec/pocsuite3) on GitHub to start making your changes to the **dev** branch (or branch off of it).
3. Write a test which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug the maintainer until it gets merged and published. Make sure to add yourself to [THANKS](./docs/THANKS.md).


## Links

* [Contributors](./CONTRIBUTORS.md)
* [Change Log](./CHANGELOG.md)
* [Bug tracking](https://github.com/knownsec/pocsuite3/issues)
* [Copyright](./COPYING)
* [Pocsuite](https://pocsuite.org)
* [Seebug](https://www.seebug.org)
* [ZoomEye](https://www.zoomeye.org)
* [Knownsec](https://www.knownsec.com)
