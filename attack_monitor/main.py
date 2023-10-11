#!/usr/bin/env python3
import locale
import datetime

from .mode import Mode

DATABASE = "../attack.db"

locale.setlocale(locale.LC_ALL, "")


class Record:
    ip: str
    location: str
    blocked: bool
    last: datetime.datetime
    avg: float
    num: int


class Data:
    total: int
    since: datetime.datetime
    last: datetime.datetime
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
        self.data.total = 0
        return self.data


def main():
    source = Source(DATABASE)
    mode = Mode.TIME
    source.get(mode)


if __name__ == "__main__":
    main()
