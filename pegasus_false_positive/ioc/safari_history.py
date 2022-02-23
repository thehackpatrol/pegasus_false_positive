import json
import logging
import os
from urllib.parse import urlparse

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, HistoryItems, HistoryVisits
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = 'Library/Safari/History.db'
logger = logging.getLogger('pegasus-false-positive')


class SafariHistory(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Safari")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_safari_history()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
            logger.info('Suspicious %s domain inserted in Safari history', self.data['domain'])
        except Exception as er:
            logger.error("Inserting Safari URL %s: %s", self.data['url'], er)

    def update_safari_history(self):
        timestamp = utils.convert_timestamp_to_mac(utils.convert_timestamp_from_iso(self.data['time']))
        with db.open_safari(self.filename):
            history_item = HistoryItems(
                url=self.data['url'],
                domain_expansion=self.data['domain'],
                visit_count=1,
                daily_visit_counts='d',
                weekly_visit_counts=None,
                autocomplete_triggers=None,
                should_recompute_derived_visit_counts=0,
                visit_count_score=self.data['score'],
                status_code=302)
            history_item.save(force_insert=True)

            history_visit = HistoryVisits(
                visit_time=timestamp,
                title=self.data['title'],
                load_successful=1,
                history_item=history_item.id,
                http_non_get=0,
                synthesized=0,
                redirect_source=None,
                redirect_destination=None,
                origin=0,
                generation=0,
                attributes=0,
                score=self.data['score'])
            history_visit.save()
