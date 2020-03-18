#!usr/bin/env python  
# -*- coding:utf-8 -*-
""" 
@author: longofo
@file: war.py 
@time: 2020/03/18 
"""
import os

from pocsuite3.lib.helper.archieve.memoryzip import InMemoryZip
from pocsuite3.lib.helper.archieve.zip import Zip


class InMemoryWar(InMemoryZip):
    def __init__(self, use_default_template=False):
        InMemoryZip.__init__(self)
        self.create_archieve(use_default_template)

    def create_archieve(self, use_default_template):
        if use_default_template:
            base_web_xml = '<?xml version="1.0" encoding="UTF-8"?>' + '\n' + \
                           '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"' + '\n' + \
                           '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' + '\n' + \
                           '         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"' + '\n' + \
                           '         version="4.0">' + '\n' + \
                           '<welcome-file-list> ' + '\n' + \
                           '    <welcome-file>index.jsp</welcome-file> ' + '\n' + \
                           '    <welcome-file>index.html</welcome-file> ' + '\n' + \
                           '</welcome-file-list> ' + '\n' + \
                           '</web-app>'
            self.add_file("WEB-INF/web.xml", base_web_xml)
            self.add_file("index.html", "index page")


class War(Zip):
    def __init__(self, filename='', use_default_template=False):
        super().__init__(filename)

        if use_default_template:
            self.create_template()

    def create_template(self):
        base_web_xml = '<?xml version="1.0" encoding="UTF-8"?>' + '\n' + \
                       '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"' + '\n' + \
                       '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' + '\n' + \
                       '         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"' + '\n' + \
                       '         version="4.0">' + '\n' + \
                       '<welcome-file-list> ' + '\n' + \
                       '    <welcome-file>index.jsp</welcome-file> ' + '\n' + \
                       '    <welcome-file>index.html</welcome-file> ' + '\n' + \
                       '</welcome-file-list> ' + '\n' + \
                       '</web-app>'
        self.add_file("WEB-INF/web.xml", base_web_xml)
        self.add_file("index.html", "index page")

    def get_raw(self, remove_temp=False):
        if not self.name:
            print('You should create war file before get raw content')
        with open(self.name, 'rb') as f:
            content = f.read()
        if remove_temp:
            os.remove(self.name)
        return content

    def get_war(self):
        return self.name


if __name__ == '__main__':
    memory_war = InMemoryWar(use_default_template=True)
    memory_war.add_file("classes/my.class", b"43535assd")
    memory_war.add_file("shell.jsp", "shell jsp")
    memory_war.write_to_file("../../../../mymemory_war.war")
    memory_war_context = memory_war.read()
    print(memory_war_context)

    war = War("../../../../mywar.war", use_default_template=True)
    war.add_file("classes/my.class", b"43535assd")
    war.add_file("shell.jsp", "shell jsp")
    war_context = war.get_raw()
    print(war_context)
