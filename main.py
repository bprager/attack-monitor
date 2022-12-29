#!/usr/bin/env python3
from blessed import Terminal
import logging
import sqlite3

FORMAT = "%(asctime)s - %(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, filename="attack_monitor.log", level=logging.DEBUG)

DATABASE = "./attack.db"
REFRESH = 10


class AttackMonitor:
    term: Terminal
    db_string: str
    refresh: int

    def __init__(self, db: str, refresh: int) -> None:
        self.refresh = refresh
        self.db_string = db
        self.term = Terminal()

    def __del__(self) -> None:
        pass

    def run(self) -> None:
        pass


def main():
    am = AttackMonitor(DATABASE, REFRESH)
    am.run()


if __name__ == "__main__":
    logging.debug("hi")
    main()
    logging.debug("bye")
