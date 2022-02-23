import logging
from urllib.parse import urlparse

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, Urls, Favicons, IconMapping, FaviconBitmaps
from .baseioc import BaseIOC
from ..utils import utils

RELATIVE_PATH = "Library/Application Support/Google/Chrome/Default/Favicons"
logger = logging.getLogger('pegasus-false-positive')


class ChromeFavicon(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Chrome Favicon")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_chrome_favicon()
            self.crypt_if_needed()
            logger.info('Suspicious %s domain inserted in chrome favicon', self.data['url'])
        except Exception as er:
            logger.error("Inserting Chrome favicon URL %s: %s", self.data['url'], er)

    def update_chrome_favicon(self):
        last_updated = utils.date_from_webkit(utils.convert_timestamp_from_iso(self.data['last_updated']))
        with db.open_chrome_favicon(self.filename):
            favicon = Favicons(url=self.data['url_ico'], type=self.data['type'])
            favicon.save(force_insert=True)

            icon_mapping = IconMapping(page_url=self.data['url'], icon_id=favicon.id)
            icon_mapping.save(force_insert=True)

            favicon_bitmaps = FaviconBitmaps(icon_id=favicon.id, last_updated=last_updated, image_data=None, width=0, height=0, last_requested=0)
            favicon_bitmaps.save(force_insert=True)
