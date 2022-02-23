import logging
import os
import plistlib

from pegasus_false_positive.db import Files
from pegasus_false_positive.ioc.baseioc import BaseIOC

RELATIVE_PATH = "Library/Caches/locationd/clients.plist"
logger = logging.getLogger('pegasus-false-positive')


class Process(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Process")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.parse_plist()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
            logger.info('Suspicious Process %s data inserted', self.data['bundle'])
        except Exception as er:
            logger.error("Inserting Process %s: %s", self.data['bundle'], er)

    def parse_plist(self):
        with open(self.filename, "rb") as f:
            plist_data = plistlib.load(f, fmt=plistlib.FMT_BINARY)

        plist_data[self.data['bundle']] = plist_data['com.apple.weather']

        with open(self.filename, "wb") as f:
            f.write(plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY))
