import logging

import peewee
from peewee import SqliteDatabase

from .items import Files, Message, Chat, Handle, ChatHandleJoin, ChatMessageJoin, Urls, HistoryItems, ZProcess, \
    ZLiveUsage, Access, HistoryVisits, Tabs, TabSession, BrowserWindows, IconMapping, FaviconBitmaps, Favicons

__all__ = [
    'open_manifest',
    'Files',
    'open_sms',
    'Message',
    'Chat',
    'Handle',
    'ChatHandleJoin',
    'ChatMessageJoin',
    'open_chrome',
    'Urls',
    'open_chrome_favicon',
    'IconMapping',
    'Favicons',
    'FaviconBitmaps',
    'open_safari',
    'HistoryItems',
    'HistoryVisits',
    'open_data_usage',
    'ZProcess',
    'ZLiveUsage',
    'open_tcc',
    'Access',
    'open_safari_state',
    'Tabs',
    'TabSession',
    'BrowserWindows'
]

db_sms = None
db_chrome = None
db_chrome_favicon = None
db_safari = None
db_data_usage = None
db_manifest = None
db_tcc = None
db_safari_state = None

logger = logging.getLogger('pegasus-false-positive')


def open_manifest(database):
    try:
        db_manifest = SqliteDatabase(database)
        db_manifest.bind([Files])
        db_manifest.create_tables([Files])
        return db_manifest.connection_context()
    except peewee.DatabaseError as e:
        logger.error("Opening Manifest.db: %s", e)
        exit()


def open_sms(database):
    db_sms = SqliteDatabase(database)
    db_sms.bind([Message, Chat, Handle, ChatMessageJoin, ChatHandleJoin])
    db_sms.create_tables([Message, Chat, Handle, ChatMessageJoin, ChatHandleJoin])
    return db_sms.connection_context()


def open_chrome(database):
    db_chrome = SqliteDatabase(database)
    db_chrome.bind([Urls])
    db_chrome.create_tables([Urls])
    return db_chrome.connection_context()


def open_safari(database):
    db_safari = SqliteDatabase(database)
    db_safari.bind([HistoryItems, HistoryVisits])
    db_safari.create_tables([HistoryItems, HistoryVisits])
    return db_safari.connection_context()


def open_data_usage(database):
    db_data_usage = SqliteDatabase(database)
    db_data_usage.bind([ZProcess, ZLiveUsage])
    db_data_usage.create_tables([ZProcess, ZLiveUsage])
    return db_data_usage.connection_context()


def open_tcc(database):
    db_tcc = SqliteDatabase(database)
    db_tcc.bind([Access])
    db_tcc.create_tables([Access])
    return db_tcc.connection_context()


def open_safari_state(database):
    db_safari_state = SqliteDatabase(database)
    db_safari_state.bind([Tabs, TabSession, BrowserWindows])
    db_safari_state.create_tables([Tabs, TabSession, BrowserWindows])
    return db_safari_state.connection_context()


def open_chrome_favicon(database):
    db_chrome_favicon = SqliteDatabase(database)
    db_chrome_favicon.bind([IconMapping, Favicons, FaviconBitmaps])
    db_chrome_favicon.create_tables([IconMapping, Favicons, FaviconBitmaps])
    return db_chrome_favicon.connection_context()
