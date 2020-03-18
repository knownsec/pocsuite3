#!usr/bin/env python  
# -*- coding:utf-8 -*-
""" 
@author: longofo
@file: memoryzip.py 
@time: 2020/03/18 
"""
import zipfile
from io import BytesIO


class InMemoryZip(object):
    def __init__(self):
        self.in_memory_zip = BytesIO()

    def add_file(self, filename_in_zip, file_contents):
        zf = zipfile.ZipFile(self.in_memory_zip, "a", zipfile.ZIP_DEFLATED)

        zf.writestr(filename_in_zip, file_contents)

        return self

    def read(self):
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()

    def write_to_file(self, filename):
        with open(filename, "wb") as f:
            f.write(self.read())
