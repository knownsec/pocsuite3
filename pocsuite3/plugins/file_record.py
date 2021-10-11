import os
import time
import json
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import PluginBase
from pocsuite3.api import logger
from pocsuite3.api import register_plugin, paths


class FileRecord(PluginBase):
    category = PLUGIN_TYPE.RESULTS
    filename = os.path.join(paths.POCSUITE_OUTPUT_PATH, "{}.txt".format(int(time.time())))
    file = None

    def init(self):
        debug_msg = "[PLUGIN] file_record plugin init..."
        logger.debug(debug_msg)
        logger.info("[PLUGIN] The data will be recorded in {}".format(self.filename))
        if os.path.exists(self.filename):
            raise Exception("The {} has existed".format(self.filename))
        self.file = open(self.filename, 'a+')

    def handle(self, output):
        status = output.get("status")
        if status and status == "success":
            poc_name = output.get("poc_name")
            target = output.get("target")
            created = output.get("created")
            msg = {"target": target, "poc_name": poc_name, "created_time": created}
            self.file.write(json.dumps(msg) + '\n')

    def start(self):
        self.file.close()
        msg = "[PLUGIN] File saved in {}".format(self.filename)
        logger.info(msg)


register_plugin(FileRecord)
