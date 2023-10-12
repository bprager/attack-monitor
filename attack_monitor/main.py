#!/usr/bin/env python3
import locale
import logging
import sqlite3
import geoip2.database
import os
import subprocess
import re
from datetime import datetime

from .mode import Mode

DATABASE = "../attack.db"
GEO_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

locale.setlocale(locale.LC_ALL, "")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(funcName)s:%(lineno)d: %(message)s",
    handlers=[logging.FileHandler(f"{SCRIPT_DIR}/attack_monitor.log")],
    datefmt="%Y-%m-%d %H:%M:%S",
)


def location(ip: str) -> str:
    country = ""
    city = ""
    with geoip2.database.Reader(GEO_DB) as reader:
        try:
            response = reader.city(ip)
            country = (
                "Unknow" if response.country.name == None else response.country.name
            )
            city = "Unknown" if response.city.name == None else response.city.name
        except geoip2.errors.AddressNotFoundError:
            country = "Unknow"
            city = "Unknown"

    return f"{city} ({country})"


class Record:
    ip: str
    location: str
    last: datetime
    blocked: bool
    avg: float
    num: int

    def __init__(
        self,
        ip: str = "",
        location: str = "",
        last: datetime = datetime.now(),
        blocked: bool = False,
        avg: float = 0.0,
        num: int = 0,
    ):
        self.ip = ip
        self.location = location
        self.last = last
        self.blocked = blocked
        self.avg = avg
        self.num = num

    def __repr__(self):
        return f"ip:{self.ip} location:{self.location} blocked: {self.blocked} last: {self.last} avg: {self.avg} num: {self.num} "


class Data:
    total: int
    since: datetime
    last: datetime
    records: list[Record]

    def __init__(
        self,
        total: int = 0,
        since: datetime = datetime.now(),
        last: datetime = datetime.now(),
        records: list[Record] = Record(),
    ):
        self.total = total
        self.since = since
        self.last = last
        self.records = records

    def __repr__(self) -> str:
        return f"total: {self.total} since: {self.since} last: {self.last} records: {self.records}"


class Source:
    db_string: str
    refresh: int
    mode: Mode
    data: Data

    def __init__(self, db: str) -> None:
        print(1)
        self.db_string = db
        print(2)
        self.mode = Mode.TIME
        print(3)
        self.data = Data()

    def get(self, mode: Mode, rows: int) -> Data:
        self.mode = mode
        # Get blocked IP addresses
        output = subprocess.getoutput("sudo ipset save -o plain")
        blocked = re.findall(r"[\w:.]+", output)
        if "Members:" in blocked:
            start = blocked.index("Members:")
        blocked = blocked[start + 1 :]
        loggging.debug(f"blocked: {blocked}")
        with sqlite3.connect(database=self.db_string) as con:
            cur = con.cursor()
            # stats
            cur.execute("SELECT sum(numbers), max(last), min(first) FROM attacks")
            self.data.total, tstamp_last, tstamp_first = cur.fetchone()
            self.data.last = datetime.fromtimestamp(tstamp_last)
            self.data.first = datetime.fromtimestamp(tstamp_first)
            # records
            self.data.records = []
            sort_by = ["last", "avg", "numbers"][mode.value]
            if sort_by == "avg":
                cur.execute(
                    f"SELECT ip, last, avg, numbers FROM attacks WHERE avg IS NOT NULL AND avg > 0 ORDER BY avg ASC NULLS LAST LIMIT {rows}"
                )
            else:
                cur.execute(
                    f"SELECT ip, last, avg, numbers FROM attacks ORDER BY {sort_by} DESC NULLS FIRST LIMIT {rows}"
                )
            for row in cur.fetchall():
                record = Record()
                record.ip, tstamp, record.avg, record.num = row
                if record.avg == None:
                    record.avg = 0.0
                record.last = datetime.fromtimestamp(tstamp)
                record.location = location(record.ip)
                record.blocked = record.ip in blocked
                self.data.records.append(record)
        return self.data


def main():
    source = Source(DATABASE)
    mode = Mode.TIME
    source.get(mode, 10)


if __name__ == "__main__":
    main()
