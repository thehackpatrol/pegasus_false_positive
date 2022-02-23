import argparse
import logging
import pathlib

from ioc.chrome_history import ChromeHistory
from ioc.data_usage import DataUsage
from ioc.file import File
from ioc.osad import Osad
from ioc.process import Process
from ioc.safari_history import SafariHistory
from ioc.sms import Sms
from pegasus_false_positive import db
from pegasus_false_positive.ioc.chrome_favicon import ChromeFavicon
from pegasus_false_positive.ioc.safari_state import SafariState
from pegasus_false_positive.ioc.tcc import Tcc
from pegasus_false_positive.utils import fileutils

# 3d0d7e5fb2ce288813306e4d4636395e047a3d28 --> Library/SMS/sms.db
# 1a0e7afc19d307da602ccdcece51af33afe92c53 --> Library/Safari/History.db
# faf971ce92c3ac508c018dce1bef2a8b8e9838f1 --> Library/Application Support/Google/Chrome/Default/History
# a690d7769cce8904ca2b67320b107c8fe5f79412 --> Library/Caches/locationd/clients.plist
# 0d609c54856a9bb2d56729df1d68f2958a88426b --> Library/Databases/DataUsage.sqlite
# 64d0019cb3d46bfc8cce545a8ba54b93e7ea9347 --> Library/TCC/TCC.db
# f65b5fafc69bbd3c60be019c6e938e146825fa83 --> Library/Preferences/com.apple.osanalytics.addaily.plist
# 3a47b0981ed7c10f3e2800aa66bac96a3b5db28e --> Library/Safari/BrowserState.db

logger = logging.getLogger("pegasus-false-positive")
logger.setLevel(logging.DEBUG)
log_handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s - %(message)s')
log_handler.setFormatter(formatter)

MANIFEST_DB = "Manifest.db"


def main():
    parser = argparse.ArgumentParser(prog="pegasus-false-positive", description='', exit_on_error=False)
    parser.add_argument('--debug', action='store_true', help='activate debug mode')
    parser.add_argument('--insert-sms', default="examples/sms.json", type=str, help='json file with sms properties')
    parser.add_argument('--insert-chrome', default="examples/chrome.json", type=str,
                        help='json file with chrome properties')
    parser.add_argument('--insert-chrome-favicon', default="examples/chrome_favicon.json", type=str,
                        help='json file with chrome favicon properties')
    parser.add_argument('--insert-safari', default="examples/safari.json", type=str,
                        help='json file with safari properties')
    parser.add_argument('--insert-safari-state', default="examples/safari_state.json", type=str,
                        help='json file with safari state properties')
    parser.add_argument('--insert-process', default="examples/process.json", type=str,
                        help='json file with process properties')
    parser.add_argument('--insert-data-usage', default="examples/data_usage.json", type=str,
                        help='json file with data usage properties')
    parser.add_argument('--insert-tcc', default="examples/tcc.json", type=str, help='json file with tcc properties')
    parser.add_argument('--insert-file', default="examples/file.json", type=str, help='json file with file properties')
    parser.add_argument('--insert-osad', default="examples/osad.json", type=str,
                        help='json file with osanalytics addaily properties')
    parser.add_argument('--password', type=str, help='Backup Password')
    parser.add_argument('backup', type=str, help='iPhone backup folder')

    # Retrieve arguments
    args = parser.parse_args()

    if not args.debug:
        log_handler.setLevel(logging.INFO)

    logger.addHandler(log_handler)

    backup_path = args.backup

    manifest_plist = fileutils.open_manifest_plist(backup_path)

    if manifest_plist is None:
        exit()

    file_locator = None
    if manifest_plist['IsEncrypted']:
        file_locator = fileutils.create_file_locator(manifest_plist, backup_path, password=args.password)
        file_locator.decrypt_manifest()

    if not pathlib.Path(backup_path).is_dir():
        logger.error("Backup is not a folder: %s", backup_path)

    with db.open_manifest(pathlib.Path(backup_path) / MANIFEST_DB):

        if args.insert_sms:
            sms = Sms(backup_path, file_locator, args.insert_sms)
            if sms.init:
                sms.run()

        if args.insert_osad:
            osad = Osad(backup_path, file_locator, args.insert_osad)
            if osad.init:
                osad.run()

        if args.insert_tcc:
            tcc = Tcc(backup_path, file_locator, args.insert_tcc)
            if tcc.init:
                tcc.run()

        if args.insert_file:
            file = File(backup_path, file_locator, args.insert_file)
            if file.init:
                file.run()

        if args.insert_data_usage:
            data_usage = DataUsage(backup_path, file_locator, args.insert_data_usage)
            if data_usage.init:
                data_usage.run()

        if args.insert_safari:
            safari = SafariHistory(backup_path, file_locator, args.insert_safari)
            if safari.init:
                safari.run()

        if args.insert_safari_state:
            safari_state = SafariState(backup_path, file_locator, args.insert_safari_state)
            if safari_state.init:
                safari_state.run()

        if args.insert_chrome:
            chrome = ChromeHistory(backup_path, file_locator, args.insert_chrome)
            if chrome.init:
                chrome.run()

        if args.insert_chrome_favicon:
            chrome_favicon = ChromeFavicon(backup_path, file_locator, args.insert_chrome_favicon)
            if chrome_favicon.init:
                chrome_favicon.run()

        if args.insert_process:
            process = Process(backup_path, file_locator, args.insert_process)
            if hasattr(process, 'data'):
                process.run()

    if manifest_plist['IsEncrypted']:
        file_locator.encrypt_manifest()


if __name__ == '__main__':
    main()
