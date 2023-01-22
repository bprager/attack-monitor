#!/usr/bin/env python3
from blessed import Terminal
import logging
import sqlite3
import locale
from datetime import datetime

from .run import _run
from .mode import Mode

DATABASE = "../attack.db"
REFRESH = 3

locale.setlocale(locale.LC_ALL, "")


class AttackMonitor:
    term: Terminal
    db_string: str
    refresh: int
    mode: Mode

    def __init__(self, db: str, refresh: int) -> None:
        self.refresh = refresh
        self.db_string = db
        self.term = Terminal()
        self.mode = Mode.TIME

    def __del__(self) -> None:
        pass

    def run(self):
        _run(self)


def main():
    am = AttackMonitor(DATABASE, REFRESH)
    am.run()


if __name__ == "__main__":
    main()
