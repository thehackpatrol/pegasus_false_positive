import logging
from urllib.parse import urlparse

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, Urls
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = "Library/Application Support/Google/Chrome/Default/History"
logger = logging.getLogger('pegasus-false-positive')


class ChromeHistory(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Chrome")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_chrome_history()
            self.crypt_if_needed()
            logger.info('Suspicious %s domain inserted in chrome history', self.data['domain'])
        except Exception as er:
            logger.error("Inserting Chrome URL %s: %s", self.data['domain'], er)

    def update_chrome_history(self):
        last_visit_time = utils.date_from_webkit(utils.convert_timestamp_from_iso(self.data['last_visit_time']))
        with db.open_chrome(self.filename):
            url = Urls.get_last()
            domain = urlparse(self.data['domain']).netloc

            url.id = None
            url.title = domain
            url.url = self.data['domain']
            url.last_visit_time = last_visit_time
            url.save(force_insert=True)
