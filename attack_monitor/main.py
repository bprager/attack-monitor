#!/usr/bin/env python3
import locale
from datetime import datetime
import sqlite3

from .mode import Mode

DATABASE = "../attack.db"

locale.setlocale(locale.LC_ALL, "")


class Record:
    ip: str
    location: str
    blocked: bool
    last: datetime
    avg: float
    num: int


class Data:
    total: int
    since: datetime
    last: datetime
    reords: list[Record]


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

    def get(self, mode: Mode) -> Data:
        self.mode = mode
        with sqlite3.connect(database=self.db_string) as con:
            cur = con.cursor()
            cur.execute("SELECT sum(numbers), max(last), min(first) FROM attacks")
            self.data.total, tstamp_last, tstamp_first = cur.fetchone()
            self.data.last = datetime.fromtimestamp(tstamp_last)
            self.data.first = datetime.fromtimestamp(tstamp_first)
        return self.data


def main():
    source = Source(DATABASE)
    mode = Mode.TIME
    source.get(mode)


if __name__ == "__main__":
    main()
