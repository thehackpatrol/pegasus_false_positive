from datetime import datetime, timezone
from random import randint


def get_macos_nanoseconds(dt=None):
    if dt is None:
        dt = datetime.now(tz=timezone.utc)
    dt = dt.replace(tzinfo=timezone.utc)
    mac_timedelta = dt - datetime(2001, 1, 1, tzinfo=timezone.utc)
    mac_nano = int(mac_timedelta.total_seconds()) * 1_000_000_000  # Nanoseconds
    return mac_nano + randint(0, 999_999_999)


def convert_timestamp_to_mac(dt):
    epoch = datetime.utcfromtimestamp(978307200)
    return (dt - epoch).total_seconds()


def convert_timestamp_from_iso(isostr):
    return datetime.strptime(isostr, "%Y-%m-%d %H:%M:%S.%f")


def convert_timestamp_to_unix(dt):
    epoch = datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds()


def date_from_webkit(dt):
    epoch_start = datetime(1601, 1, 1)
    return int((dt - epoch_start).total_seconds() * 1000000)
