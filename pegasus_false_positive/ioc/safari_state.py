import logging
import os
import plistlib
import uuid

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, Tabs, BrowserWindows, TabSession
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = 'Library/Safari/BrowserState.db'
logger = logging.getLogger('pegasus-false-positive')


class SafariState(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Safari State")
            self.init = False
        except FileNotFoundError:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_safari_state()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
        except Exception as er:
            logger.error("Inserting Safari URL %s in Safari State: %s", self.data['url'], er)

    def update_safari_state(self):
        last_viewed_time = utils.convert_timestamp_to_mac(
            utils.convert_timestamp_from_iso(self.data['last_viewed_time']))
        with db.open_safari_state(self.filename):
            browser_window = BrowserWindows.get_last()
            if browser_window is None:
                logger.info("No tab")
                return
            order_index = self.data["order_index"]
            Tabs.update_order_index(order_index)

            tab_uuid = str(uuid.uuid4())

            tab = Tabs(
                uuid=tab_uuid,
                title=self.data["title"],
                url=self.data["url"],
                user_visible_url=self.data["user_visible_url"],
                order_index=order_index,
                last_viewed_time=last_viewed_time,
                browser_window_uuid=browser_window.uuid,
                browser_window_id=browser_window.id
            )
            tab.save(force_insert=True)

            session_data = self.create_plist()
            data_size = len(session_data)

            tab_session = TabSession (
                tab_uuid=tab_uuid,
                uncompressed_session_data_size=data_size,
                session_data=session_data
            )

            tab_session.save(force_insert=True)

            logger.info('Suspicious %s domain inserted in Safari state', self.data['url'])

    def create_plist(self):
        plist_data = {"RenderTreeSize": 415, "IsAppInitiated": False, "SessionHistory": {}}

        data_entry = {"SessionHistoryEntryData": b'', "SessionHistoryEntryTitle": self.data["title"],
                      "SessionHistoryEntryShouldOpenExternalURLsPolicyKey": (2,),
                      "SessionHistoryEntryURL": (self.data["url"],),
                      "SessionHistoryEntryOriginalURL": self.data["user_visible_url"]}
        plist_data["SessionHistory"]["SessionHistoryEntries"] = [data_entry]

        plist_data["SessionHistory"]["SessionHistoryCurrentIndex"] = 0
        plist_data["SessionHistory"]["SessionHistoryVersion"] = 1

        return b'\00' * 4 + plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)
