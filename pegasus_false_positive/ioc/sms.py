import logging
import os
import plistlib
import re
import uuid
from random import randint

from pegasus_false_positive import db
from pegasus_false_positive.db import Files, ChatHandleJoin, Message, Chat, Handle, ChatMessageJoin
from pegasus_false_positive.ioc.baseioc import BaseIOC
from pegasus_false_positive.utils import utils

RELATIVE_PATH = "Library/SMS/sms.db"
logger = logging.getLogger('pegasus-false-positive')


class Sms(BaseIOC):
    def __init__(self, backup_path, file_locator, config_file):
        super().__init__(backup_path, file_locator)
        self.init = True
        try:
            self.data = super().params_file_to_dict(config_file)
            self.filename = super().get_file_name(RELATIVE_PATH)
            self.attrs = Files.get_file_attributes_by_relative_path(RELATIVE_PATH)
        except Files.DoesNotExist:
            logger.info("No sms")
            self.init = False
        except FileNotFoundError as e:
            logger.error("Parsing %s", config_file)
            self.init = False

    def run(self):
        try:
            self.decrypt_if_needed()
            self.insert_conversation()
            size = os.path.getsize(self.filename)
            self.crypt_if_needed()
            super().update_manifest_file(RELATIVE_PATH, self.filename, size)
            logger.info('Suspicious %s domain inserted in SMS list', self.data['url'])
        except Exception as er:
            logger.error("Inserting Sms URL %s: %s", self.data['url'], er)

    def insert_conversation(self):
        with db.open_sms(self.filename):
            if 'phoneNumber' in self.data:
                phone_number = self.data['phoneNumber']
            else:
                phone_number = "+42" + str(randint(000000000, 999999999))

            chat = Chat.get_or_none(Chat.guid == "SMS;-;" + phone_number)
            if chat is None:
                chat = Chat.get_last()
                chat.ROWID = None
                chat.guid = "SMS;-;" + phone_number
                chat.chat_identifier = phone_number
                chat.group_id = str(uuid.uuid4()).upper()
                chat.is_filtered = 1
                chat.original_group_id = str(uuid.uuid4()).upper()
                chat.save(force_insert=True)

            handle = Handle.get_or_none(Handle.id == phone_number)
            if handle is None:
                handle = Handle.get_last()
                handle.ROWID = None
                handle.id = phone_number
                handle.uncanonicalized_id = phone_number
                handle.save(force_insert=True)
                ChatHandleJoin.create(chat_id=chat.ROWID, handle_id=handle.ROWID)

            message = Message.get_last()
            message.ROWID = None
            message.handle_id = handle.ROWID
            message.guid = uuid.uuid4()
            message.text = self.data['text']

            message.date = utils.get_macos_nanoseconds(utils.convert_timestamp_from_iso(self.data['receivedDate']))
            message.date_read = utils.get_macos_nanoseconds(utils.convert_timestamp_from_iso(self.data['readDate']))
            message.attributedBody = self.generate_attributed_body()
            message.save(force_insert=True)

            ChatMessageJoin.create(chat_id=chat.ROWID, message_id=message.ROWID, message_date=message.date)

    def generate_attributed_body(self):

        url = self.data['url']

        with open("pegasus_false_positive/resources/sms-bplist-template.xml", 'rb') as f_template:
            plist_data = plistlib.load(f_template, fmt=plistlib.FMT_XML)
            plist_data['$objects'][6] = url
            plist_data['$objects'][3] = len(url)

        with open("pegasus_false_positive/resources/sms-template.bin", 'rb') as f_template:
            sms = f_template.read()

        if b"SMS_BPLIST" in sms:
            logger.debug("SMS_PLIST found")
            bplist = plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)
            sms = sms.replace(b"SMS_BPLIST", bplist)

        if b"SMS_TEXT" in sms:
            logger.debug("SMS_TEXT found")
            sms = sms.replace(b"SMS_TEXT", bytes(self.data['text'], 'utf-8'))
            # Check how length is inserted
        if b"SMS_LENGTH" in sms:
            logger.debug("SMS_LENGTH found")
            logger.debug("sms_length %s", str(len(self.data['text'])))
            sms = sms.replace(b"SMS_LENGTH", len(self.data['text']).to_bytes(1, 'big'))
            # Check how length is inserted
        if b"LINK_LENGTH" in sms:
            logger.debug("LINK_LENGTH found")
            sms = sms.replace(b"LINK_LENGTH", len(url).to_bytes(1, 'big'))
        if b"LINK" in sms:
            logger.debug("LINK found")
            sms = sms.replace(b"LINK", bytes(url, 'utf-8'))

        bplist_length = len(bplist)
        if b"BPLIST_LENGTH" in sms:
            logger.debug("BPLIST_LENGTH found")
            sms = sms.replace(b"BPLIST_LENGTH", bytes(str(bplist_length), 'utf-8'))
        if b"BINARY_LENGTH" in sms:
            logger.debug("BINARY_LENGTH found")
            sms = sms.replace(b"BINARY_LENGTH", bplist_length.to_bytes(2, 'little'))

        return sms
