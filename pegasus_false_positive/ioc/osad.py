import logging
import os
import plistlib
from urllib.parse import urlparse

from pegasus_false_positive import db
from pegasus_false_positive.db import Files
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = 'Library/Preferences/com.apple.osanalytics.addaily.plist'
logger = logging.getLogger('pegasus-false-positive')


class Osad(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = False
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Osad")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_osad()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
            logger.info('Suspicious Os Analytics of %s data inserted', self.data['app'])
        except Exception as er:
            logger.info("Modifying Os Analytics %s: %s", self.data['app'], er)

    def update_osad(self):
        with open(self.filename, "rb") as f:
            plist_data = plistlib.load(f, fmt=plistlib.FMT_BINARY)

        plist_data['netUsageBaseline'][self.data['app']] = [utils.convert_timestamp_from_iso(self.data['time']),
                                                            float(self.data['wifi_in']), float(self.data['wifi_out']),
                                                            float(self.data['wwan_in']),
                                                            float(self.data['wwan_out'])]

        with open(self.filename, "wb") as f:
            f.write(plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY))
