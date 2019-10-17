import os
import unittest

from pocsuite3.api import init_pocsuite
from pocsuite3.api import load_file_to_module, paths


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_info(self):
        init_pocsuite({})
        poc_filename = os.path.join(paths.POCSUITE_POCS_PATH, '20190404_WEB_Confluence_path_traversal.py')
        mod = load_file_to_module(poc_filename)
        print(mod.get_infos())
        self.assertTrue(len(mod.get_infos()) > 0)
