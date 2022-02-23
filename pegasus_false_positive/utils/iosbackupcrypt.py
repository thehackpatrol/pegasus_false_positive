import hashlib as hlib
import logging
import os
import struct

from Crypto.Cipher import AES

QUAD = struct.Struct('>Q')
logger = logging.getLogger('pegasus-false-positive')


# See https://github.com/avibrazil/iOSbackup

def unpack64bit(s):
    return struct.unpack(">Q", s)[0]


def pack64bit(s):
    return struct.pack(">Q", s)


def aes_unwrap_key_and_iv(kek, wrapped):
    n = (len(wrapped) >> 3) - 1

    # NOTE: R[0] is never accessed, left in for consistency with RFC indixes
    r = [None] + [wrapped[i * 8:i * 8 + 8] for i in range(1, n + 1)]
    a = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek, AES.MODE_ECB).decrypt
    for j in range(5, -1, -1):  # counting down
        for i in range(n, 0, -1):  # (n, n-1, ..., 1)
            ciphertext = QUAD.pack(a ^ (n * j + i)) + r[i]
            b = decrypt(ciphertext)
            a = QUAD.unpack(b[:8])[0]
            r[i] = b[8:]
    return b''.join(r[1:]), a


def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    """
    key wrapping as defined in RFC 3394
    http://www.ietf.org/rfc/rfc3394.txt
    """
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError("Integrity Check Failed: " + hex(key_iv) + " (expected " + hex(iv) + ")")
    return key


def aes_unwrap_key_withpad(kek, wrapped):
    """
    Switch initial value for AES key wrapping, as defined in RFC 5649
    section 3
    http://www.ietf.org/rfc/rfc5649.txt
    """
    if len(wrapped) == 16:
        plaintext = AES.new(kek, AES.MODE_ECB).decrypt(wrapped)
        key, key_iv = plaintext[:8], plaintext[8:]
    else:
        key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    key_iv = "{0:016X}".format(key_iv)
    if key_iv[:8] != "A65959A6":
        raise ValueError("Integrity Check Failed: " + key_iv[:8] + " (expected A65959A6)")
    key_len = int(key_iv[8:], 16)
    return key[:key_len]


def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext) >> 3
    r = [None] + [plaintext[i * 8:i * 8 + 8] for i in range(0, n)]
    a = iv
    encrypt = AES.new(kek, AES.MODE_ECB).encrypt
    for j in range(6):
        for i in range(1, n + 1):
            b = encrypt(QUAD.pack(a) + r[i])
            a = QUAD.unpack(b[:8])[0] ^ (n * j + i)
            r[i] = b[8:]
    return QUAD.pack(a) + b''.join(r[1:])


def aes_wrap_key_withpad(kek, plaintext):
    iv = 0xA65959A600000000 + len(plaintext)
    plaintext = plaintext + b"\0" * ((8 - len(plaintext)) % 8)
    if len(plaintext) == 8:
        return AES.new(kek, AES.MODE_ECB).encrypt(QUAD.pack[iv] + plaintext)
    return aes_wrap_key(kek, plaintext, iv)


class CryptUtil:
    def __init__(self, manifest, password):
        self.manifest = manifest
        self.attrs = {}
        self.uuid = None
        self.wrap = None
        self.WRAP_PASSCODE = 2
        self.CLASSKEY_TAGS = [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"]  # UUID
        self.classKeys = {}
        self.__load_keys()
        if password:
            self.decryptionKey = self.__derive_key_from_password(password.encode('utf-8'))
        else:
            raise Exception("Password required")
        self.__unlock_keys()

    def __load_keys(self):
        backup_key_bag = self.manifest['BackupKeyBag']
        current_class_key = None

        for tag, data in self.__loop_tlv_blocks(backup_key_bag):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == b"TYPE":
                self.type = data
                if self.type > 3:
                    logger.error("FAIL: keybag type > 3 : %d" % self.type)
            elif tag == b"UUID" and self.uuid is None:
                self.uuid = data
            elif tag == b"WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == b"UUID":
                if current_class_key:
                    self.classKeys[current_class_key[b"CLAS"]] = current_class_key
                current_class_key = {b"UUID": data}
            elif tag in self.CLASSKEY_TAGS:
                current_class_key[tag] = data
            else:
                self.attrs[tag] = data
        if current_class_key:
            self.classKeys[current_class_key[b"CLAS"]] = current_class_key

    def __derive_key_from_password(self, clean_password=None):
        # Try to use fastpbkdf2.pbkdf2_hmac().
        # Fallback to Pythons default hashlib.pbkdf2_hmac() if not found.
        # If ios version is older than 10.2, the stage with the DPSL and DPIC are not used in the key derivation
        if self.__is_older_than_ios_10_2(self.manifest['Lockdown']['ProductVersion']):
            temp = clean_password
        else:
            temp = hlib.pbkdf2_hmac('sha256', clean_password,
                                    self.attrs[b"DPSL"],
                                    self.attrs[b"DPIC"], 32)

        decryption_key = hlib.pbkdf2_hmac('sha1', temp,
                                          self.attrs[b"SALT"],
                                          self.attrs[b"ITER"], 32)

        return decryption_key

    @staticmethod
    def __aes_decrypt_cbc(data, key, iv=b'\x00' * 16, padding=False):
        todec = data

        if len(data) % 16:
            todec = data[0:(len(data) / 16) * 16]

        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(todec)

        if padding:
            dec = CryptUtil.__remove_padding(16, dec)

        return dec

    @staticmethod
    def __aes_encrypt_cbc(data, key, iv=b'\x00' * 16, padding=False):
        if padding:
            padding = 16 - (len(data) % 16)
            data = data + padding.to_bytes(1, 'little') * padding

        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    @staticmethod
    def __remove_padding(blocksize, s):
        """Remove RFC1423 padding from string."""

        n = s[-1]  # last byte contains number of padding bytes

        if n > blocksize or n > len(s):
            raise Exception('invalid padding')

        return s[:-n]

    @staticmethod
    def __loop_tlv_blocks(blob):
        i = 0
        while i + 8 <= len(blob):
            tag = blob[i:i + 4]
            length = struct.unpack(">L", blob[i + 4:i + 8])[0]
            data = blob[i + 8:i + 8 + length]
            yield tag, data
            i += 8 + length

    def __unlock_keys(self):
        for class_key in self.classKeys.values():
            if b"WPKY" not in class_key:
                continue

            if class_key[b"WRAP"] & self.WRAP_PASSCODE:
                k = aes_unwrap_key(self.decryptionKey, class_key[b"WPKY"])

                if not k:
                    raise Exception(
                        'Failed decrypting backup. Try to start over with a clear text decrypting password on parameter "cleartextpassword".')

                class_key[b"KEY"] = k

        return True

    def __wrap_key_for_class(self, protection_class, key):
        if len(key) != 0x20:
            raise Exception("Invalid key length")

        ck = self.classKeys[protection_class][b"KEY"]

        return aes_wrap_key(ck, key)

    def __unwrap_key_for_class(self, protection_class, persistent_key):
        if len(persistent_key) != 0x28:
            raise Exception("Invalid key length")

        ck = self.classKeys[protection_class][b"KEY"]

        return aes_unwrap_key(ck, persistent_key)

    @staticmethod
    def __is_older_than_ios_10_2(version):
        versions = version.split('.')
        if int(versions[0]) < 10:
            return True
        if int(versions[0]) > 10:
            return False
        if int(versions[0]) == 10:
            if len(versions) == 1:  # str is iOS 10 only
                return True
            if int(versions[1]) < 2:
                return True
            else:
                return False

    def __get_manifest_key(self):
        manifest_class = struct.unpack('<l', self.manifest['ManifestKey'][:4])[0]
        manifest_key = self.manifest['ManifestKey'][4:]

        return self.__unwrap_key_for_class(manifest_class, manifest_key)

    def encrypt_manifest(self, data):
        if self.__is_older_than_ios_10_2(self.manifest['Lockdown']['ProductVersion']):
            return data
        else:
            return self.__aes_encrypt_cbc(data, self.__get_manifest_key())

    def decrypt_manifest(self, data):
        if self.__is_older_than_ios_10_2(self.manifest['Lockdown']['ProductVersion']):
            return data
        else:
            return self.__aes_decrypt_cbc(data, self.__get_manifest_key())

    def decrypt(self, data, enc_key_params):
        key = self.__unwrap_key_for_class(enc_key_params[0], enc_key_params[1])

        # See https://github.com/avibrazil/iOSbackup/issues/1
        return self.__aes_decrypt_cbc(data, key, padding=True)

    def encrypt(self, data, enc_key_params):
        key = self.__unwrap_key_for_class(enc_key_params[0], enc_key_params[1])

        # See https://github.com/avibrazil/iOSbackup/issues/1
        return self.__aes_encrypt_cbc(data, key, padding=True)

    def create_key(self, protection_class):
        return self.__wrap_key_for_class(protection_class, os.urandom(32))
