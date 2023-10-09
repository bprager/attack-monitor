#!/usr/bin/env python3
from blessed import Terminal
import logging
import locale
from datetime import datetime

from .run import _run
from .mode import Mode

DATABASE = "../attack.db"
REFRESH = 3
FORMAT = "%(asctime)s - %(name)s, %(levelname)s: %(message)s"

locale.setlocale(locale.LC_ALL, "")

# create logger
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
# create file handler and set level to debug
fh = logging.FileHandler("attack_monitor.log")
fh.setFormatter(logging.Formatter(FORMAT))
log.addHandler(fh)


class AttackMonitor:
    term: Terminal
    db_string: str
    refresh: int
    mode: Mode

    def __init__(self, db: str, refresh: int) -> None:
        log.debug("in __init__")
        self.refresh = refresh
        log.debug(f"refresh is {refresh}")
        self.db_string = db
        self.term = Terminal()
        # sorting method
        self.mode = Mode.TIME

    def __del__(self) -> None:
        pass

    def run(self):
        log.debug("in run")
        _run(self)


def main():
    am = AttackMonitor(DATABASE, REFRESH)
    am.run()


if __name__ == "__main__":
    main()
