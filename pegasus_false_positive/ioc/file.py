import logging
import os
import pathlib
import plistlib
import shutil
import struct
from datetime import datetime

from pegasus_false_positive.db import Files
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import fileutils
from pegasus_false_positive.utils.utils import convert_timestamp_to_unix

MANIFEST = "Manifest.db"
logger = logging.getLogger('pegasus-false-positive')


class File(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        if file_locator is None:
            self.init = False
            logger.info("File is not inserted. Backup is not encrypted")
            return
        try:
            self.data = super().params_file_to_dict(config_file)
        except Files.DoesNotExist:
            logger.info("No File")
            self.init = False
        except FileNotFoundError:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.upload_file(pathlib.Path("examples") / self.data['file'])
            size = os.path.getsize(self.filename)
            super().update_manifest_file(self.data['path'], self.filename, size)
            logger.info('Suspicious File %s inserted', self.data['file'])
        except Exception as er:
            logger.error("Inserting File %s: %s", self.data['file'], er)

    def upload_file(self, file):
        file_id = fileutils.get_file_id(self.data['domain'], self.data['path'])
        self.filename = fileutils.get_file_path_from_id(self.backup_path, file_id)
        self.filename.parent.mkdir(exist_ok=True)
        self.get_or_create_manifest_attributes(file_id, self.data['domain'], self.data['path'])
        shutil.copy(file, self.filename)
        self.file_locator.encrypt_file(self.filename, self.attrs)

    def get_or_create_manifest_attributes(self, file_id, domain, path):
        attrs = Files.get_file_attributes_by_file_id(file_id)
        if not attrs:
            now = convert_timestamp_to_unix(datetime.now())
            file_data = {
                '$class': None,
                'Birth': now,
                'Digest': plistlib.UID(3),
                'Flags': 0,
                'GroupID': 0,
                'InodeNumber': 7875410,
                'LastModified': now,
                'LastStatusChange': now,
                'Mode': 33152,
                'ProtectionClass': 4,
                'RelativePath': plistlib.UID(2),
                'Size': 0,
                'UserID': 0
            }
            extra_attrs = self._create_extra_attributes(file_data)
            file_data['$class'] = plistlib.UID(4 + len(extra_attrs))

            attrs = {'$archiver': 'NSKeyedArchiver', '$objects': []}
            attrs['$objects'].append('$null')
            attrs['$objects'].append(file_data)
            attrs['$objects'].append(path)
            attrs['$objects'].append(b'')
            attrs['$objects'] += extra_attrs
            attrs['$objects'].append({
                '$classes': ['MBFile', 'NSObject'],
                '$classname': 'MBFile'
            })
            attrs['$top'] = {'root': plistlib.UID(1)}
            attrs['$version'] = 100000
            file_metadata = Files(fileID=file_id, domain=domain, relativePath=path, flags=1,
                                  file=plistlib.dumps(attrs, fmt=plistlib.FMT_BINARY))
            file_metadata.save(force_insert=True)

        self.attrs = attrs

    def _create_extra_attributes(self, file_data):
        file_data['EncryptionKey'] = plistlib.UID(4)
        file_data['ProtectionClass'] = 4
        enc_key = struct.pack('<l', file_data['ProtectionClass']) + self.file_locator.crypt.create_key(file_data['ProtectionClass'])
        return [
            {
                '$class': plistlib.UID(5),
                'NS.data': enc_key
            },
            {
                '$classes': ['NSMutableData', 'NSData', 'NSObject'],
                '$classname': 'NSMutableData'
            }
        ]
