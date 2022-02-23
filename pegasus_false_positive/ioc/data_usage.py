import logging
import os

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, ZProcess, ZLiveUsage
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = 'Library/Databases/DataUsage.sqlite'
logger = logging.getLogger('pegasus-false-positive')


class DataUsage(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No data usage")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.update_data_usage()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
            logger.info('Suspicious %s Data_usage process inserted', self.data['process'])
        except Exception as er:
            logger.error("Inserting Data_usage process %s: %s", self.data['process'], er)

    def update_data_usage(self):
        with db.open_data_usage(self.filename):
            timestamp = utils.convert_timestamp_to_mac(utils.convert_timestamp_from_iso(self.data['time']))
            zprocess = ZProcess.get_or_none(ZBUNDLENAME=self.data['bundle'], ZPROCNAME=self.data['process'])
            if zprocess is not None:
                zprocess.update(ZTIMESTAMP=timestamp).where(ZProcess.ZTIMESTAMP < timestamp).execute()
                zprocess.update(ZFIRSTTIMESTAMP=timestamp).where(ZProcess.ZFIRSTTIMESTAMP > timestamp).execute()
            else:
                zprocess = ZProcess(Z_ENT=7,
                                    Z_OPT=3,
                                    ZFIRSTTIMESTAMP=timestamp,
                                    ZTIMESTAMP=timestamp,
                                    ZBUNDLENAME=self.data['bundle'],
                                    ZPROCNAME=self.data['process'])
                zprocess.save(force_insert=True)

            z_live_usage = ZLiveUsage(Z_ENT=5,
                                    Z_OPT=3,
                                    ZKIND=0,
                                    ZMETADATA=0,
                                    ZTAG=1,
                                    ZHASPROCESS=zprocess.Z_PK,
                                    ZBILLCYCLEEND=None,
                                    ZTIMESTAMP=timestamp,
                                    ZWIFIIN=self.data['wifi_in'],
                                    ZWIFIOUT=self.data['wifi_out'],
                                    ZWWANIN=self.data['wwan_in'],
                                    ZWWANOUT=self.data['wwan_out'])
            z_live_usage.save(force_insert=True)

            ZProcess.delete().where(ZProcess.ZBUNDLENAME=="", ZProcess.ZPROCNAME=="").execute()
