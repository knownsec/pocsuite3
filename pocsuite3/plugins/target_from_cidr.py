#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/1/15 2:32 PM
# @Author  : chenghs
# @File    : target_from_cidr.py
import os
from ipaddress import ip_network

from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import PluginBase
from pocsuite3.api import logger
from pocsuite3.api import register_plugin, conf


class TargetFromCIDR(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init(self):

        info_msg = "[PLUGIN] try fetch targets from CIDR..."
        logger.info(info_msg)
        cidr_set = set()
        if "CIDR" in os.environ:
            cidr_set.add(os.environ.get("CIDR"))
        elif conf.url:
            for i in conf.url:
                cidr_set.add(i)
            conf.url = []
        else:
            cidr_text = input("Please input CIDR address:")
            cidr_set.add(cidr_text)
        count = 0
        for i in cidr_set:
            try:
                network = ip_network(i, strict=False)
                for host in network.hosts():
                    self.add_target(host.exploded)
                    count += 1
            except ValueError:
                logger.error("[PLUGIN] error format from " + i)
        info_msg = "[PLUGIN] get {0} target(s) from CIDR".format(count)
        logger.info(info_msg)


register_plugin(TargetFromCIDR)
