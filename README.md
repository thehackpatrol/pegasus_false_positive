## pegasus-false-positive

* Tool to inject Pegasus iocs on iOS devices. Based on the indicators of compromise available at `https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2` from mvt tool `https://github.com/mvt-project/mvt`

* It can inject Pegasus iocs in iOS backups (encrypted or not) and the backups can be restored properly.

# Indicators of compromise available
* All backups
  + chrome history
  + chrome favicon
  + sms
  + process
  + data usage
  + tcc
  + os analytics
* Only on encrypted backups
    + safari browser state
    + safari history
    + file

# Installation
* python -m pip install -r requirements.txt

# Usage
* python3 main.py [-h] [-debug] [--insert-sms INSERT_SMS] [--insert-chrome INSERT_CHROME] [--insert-safari INSERT_SAFARI] [--insert-process INSERT_PROCESS] [--insert-data-usage INSERT_DATA_USAGE] [--insert-tcc INSERT_TCC] [--insert-file INSERT_FILE] [--insert-osad INSERT_OSAD] [--password PASSWORD] backup
    + -h, --help    help
    + --debug       debug mode
    + --insert-sms INSERT_SMS       injects sms with suspicious domain
    + --insert-chrome INSERT_CHROME     injects suspicious domain in chrome history
    + --insert-safari INSERT_SAFARI     injects suspicious domain in chrome history
    + --insert-safari-state INSERT_SAFARI_STATE injects suspicious url in the `safari_browser_state` database
    + --insert-process INSERT_PROCESS   injects suspicious process in process list
    + --insert-data-usage INSERT_DATA_USAGE injects suspicious process data usage
    + --insert-tcc INSERT_TCC       injects suspicious process in the `tcc` database, which contains the authorizations given to apps
    + --insert-file INSERT_FILE     injects new file in the backup
    + --insert-osad INSERT_OSAD     injects suspicious process in the `os_analytics_ad_daily` database, which contains traffic data
    + --password     password to decrypt the iOS backup
    + backup    backup directory

* If a parameter is not given it will try to take the json file from  examples directory

# How to test it
* Generate an iPhone backup by `Finder` on macOS
* Use mvt tool to check that there is not any Pegasus ioc in the device
* Run pegasus-false-positive
* Use mvt tool with the modified backup
    + iocs appear
* Optional: restore the modified backup
    + Check iocs: browsers history, new sms with suspicious domain, etc.

# Disclaimer
You should copy the original backup in a safe location in case you need to restore your device with the original content.

# References
* Vimeo Video
    + https://vimeo.com/696991504
    
* Bitchute Video
    + https://www.bitchute.com/video/YI8cjoKzNcUL/
    
* Backup encryption and decryption
    + https://github.com/avibrazil/iOSbackup

* MVT tool
    + https://github.com/mvt-project/mvt
