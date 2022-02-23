import hashlib
import logging
import pathlib
import plistlib

from pegasus_false_positive.utils import iosbackupcrypt

MANIFEST_DB_PATH = 'Manifest.db'
MANIFEST_PLIST_PATH = 'Manifest.plist'
BUF_SIZE = 65536

logger = logging.getLogger('pegasus-false-positive')

def hash_file(file):
    sha1 = hashlib.sha1()

    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)
    return sha1.digest()


def open_manifest_plist(backup_path):
    manifest_file = pathlib.Path(backup_path) / MANIFEST_PLIST_PATH
    try:
        with open(manifest_file, 'rb') as manifest_file:
            manifest = plistlib.load(manifest_file)
            manifest['manifestVersion'] = manifest['Lockdown']['ProductVersion']
            if manifest['IsEncrypted']:
                logger.info('Found encrypted backup for iOS %s', manifest['manifestVersion'])
            else:
                logger.info('Found unencrypted backup for iOS %s', manifest['manifestVersion'])
            return manifest

    except FileNotFoundError as e:
        logger.error("Manifest.plist does not exist in this path: %s", manifest_file)


def create_file_locator(manifest, base, password=None):
    if manifest['IsEncrypted']:
        return FileLocatorBackupEncrypted(base, manifest, password=password)


def get_file_id(domain, path):
    sha1 = hashlib.sha1()
    sha1.update((domain + '-' + path).encode('ascii'))
    return sha1.digest().hex()


def get_file_path_from_id(backup_path, file_id):
    return pathlib.Path(backup_path) / file_id[0:2] / file_id


def get_encryption_key(attrs):
    file_data = attrs['$objects'][1]
    if 'EncryptionKey' in file_data:
        encryption_key = attrs['$objects'][file_data['EncryptionKey'].data]['NS.data'][4:]
        protection_class = file_data['ProtectionClass']
        return protection_class, encryption_key
    else:
        return None


class FileLocatorBackupEncrypted:
    def __init__(self, backup_path, manifest, password):
        self.backup_path = backup_path
        self.crypt = iosbackupcrypt.CryptUtil(manifest, password)

    def decrypt_file(self, file, attrs):
        with open(file, 'rb') as f:
            data = f.read()

        enc_key = get_encryption_key(attrs)

        if enc_key:
            with open(file, 'wb') as f:
                f.write(self.crypt.decrypt(data, enc_key))

    def encrypt_file(self, file, attrs):
        with open(file, 'rb') as f:
            data = f.read()

        enc_key = get_encryption_key(attrs)

        if enc_key:
            with open(file, 'wb') as f:
                f.write(self.crypt.encrypt(data, enc_key))

    def decrypt_manifest(self):
        with open(pathlib.Path(self.backup_path) / MANIFEST_DB_PATH, 'rb') as f:
            encrypted_db = f.read()

        decrypted_data = self.crypt.decrypt_manifest(encrypted_db)

        with open(pathlib.Path(self.backup_path) / MANIFEST_DB_PATH, 'wb') as f:
            f.write(decrypted_data)

    def encrypt_manifest(self):
        with open(pathlib.Path(self.backup_path) / MANIFEST_DB_PATH, 'rb') as f:
            unencrypted_db = f.read()

        encrypted_data = self.crypt.encrypt_manifest(unencrypted_db)

        with open(pathlib.Path(self.backup_path) / MANIFEST_DB_PATH, 'wb') as f:
            f.write(encrypted_data)
