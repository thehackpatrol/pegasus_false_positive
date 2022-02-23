import binascii
import hashlib
import json
import logging
import os.path
import pathlib
import plistlib
from io import BytesIO

from pegasus_false_positive import db
from pegasus_false_positive.db import Files

MANIFEST = "Manifest.db"

logger = logging.getLogger('pegasus-false-positive')


def calculate_digest(filename):
    m = hashlib.sha1()
    with open(filename, "rb") as f:
        m.update(f.read())
    return m.digest()


class BaseIOC:

    def __init__(self, backup_path, file_locator):
        self.backup_path = backup_path
        self.file_locator = file_locator
        self.filename = None
        self.attrs = None

    @staticmethod
    def params_file_to_dict(filename):
        with open(filename) as json_file:
            return json.load(json_file)

    def get_file_name(self, relative_path):
        return pathlib.Path(self.backup_path) / Files.full_path(relative_path)

    @staticmethod
    def update_manifest_file(relative_path, filename, size):
        f = Files.get(Files.relativePath == relative_path)
        if f is not None:
            plist_data = plistlib.load(BytesIO(f.file), fmt=plistlib.FMT_BINARY)
            logger.debug(binascii.hexlify(plist_data['$objects'][3]))
            plist_data['$objects'][3] = calculate_digest(filename)
            plist_data['$objects'][1]['Size'] = size
            logger.debug(binascii.hexlify(plist_data['$objects'][3]))
            f.file = plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)
            f.save()

            logger.debug('Updated digest of %s in Manifest.db', filename.name)

    def decrypt_if_needed(self):
        if self.file_locator is not None:
            self.file_locator.decrypt_file(self.filename, self.attrs)

    def crypt_if_needed(self):
        if self.file_locator is not None:
            self.file_locator.encrypt_file(self.filename, self.attrs)
