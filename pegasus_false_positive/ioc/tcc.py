import logging
import os
from urllib.parse import urlparse

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, Access
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = 'Library/TCC/TCC.db'
logger = logging.getLogger('pegasus-false-positive')


class Tcc(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No Tcc")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_tcc()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
        except Exception as er:
            logger.error("Inserting Tcc %s-%s: %s", self.data['service'], self.data['client'], er)

    def update_tcc(self):
        timestamp = utils.convert_timestamp_to_unix(utils.convert_timestamp_from_iso(self.data['time']))
        with db.open_tcc(self.filename):
            access = Access.get_or_none(Access.service == self.data['service'], Access.client == self.data['client'],
                                        Access.client_type == 0, Access.indirect_object_identifier_type == 0)
            if access is not None:
                logger.info("Suspicious TCC data %s-%s previously inserted", self.data['service'], self.data['client'])
                return
            access = Access(service=self.data['service'],
                            client=self.data['client'],
                            client_type=0,
                            auth_value=2,
                            auth_reason=4,
                            auth_version=1,
                            csreq=None,
                            policy_id=None,
                            indirect_object_identifier_type=0,
                            indirect_object_identifier="UNUSED",
                            indirect_object_code_identity=None,
                            flags=0,
                            last_modified=timestamp)

            access.save(force_insert=True)
            logger.info('Suspicious TCC data %s-%s inserted', self.data['service'], self.data['client'])
