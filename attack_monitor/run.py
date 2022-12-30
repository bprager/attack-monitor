#!/usr/bin/env python3
from blessed import Terminal
import logging
import sqlite3
from enum import Enum
import locale
from datetime import datetime
from blessed import Terminal

from .mode import Mode


FORMAT = "%(asctime)s - %(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, filename="attack_monitor.log", level=logging.DEBUG)

locale.setlocale(locale.LC_ALL, "")

# Colors
term = Terminal()
FG1 = term.orangered
FG2 = term.bright_cyan
IN1 = term.black_on_bright_cyan


def _run(self) -> None:
    t = self.term
    while True:
        with t.fullscreen(), t.cbreak(), t.hidden_cursor():
            all, last = None, None
            with sqlite3.connect(self.db_string) as con:
                cur = con.cursor()
                # cur.execute("SELECT 1,SQLITE_VERSION()")
                cur.execute("SELECT sum(numbers), max(last) FROM attacks")
                all, tstamp = cur.fetchone()
                last = datetime.fromtimestamp(tstamp)
                logging.debug(f"all: {all},last: {last}")
            # summary
            print(
                t.home + t.move_xy(2, 1) + t.clear_eol,
                end="",
            )
            print(f"{FG2}Absolute numbers: {FG1}{all:,}")
            print(t.move_xy(2, 2) + t.clear_eol, end="")
            print(f"{FG2}Last: {FG1}{last:%a, %b %d %H:%M:%S}")
            # header
            steps = int(t.width / 4)
            print(t.move_xy(0, 3) + IN1 + t.clear_eol + "IP", end="")
            print(t.move_xy(steps, 3) + IN1 + t.clear_eol + "Last", end="")
            print(t.move_xy(2 * steps, 3) + IN1 + t.clear_eol + "Avg", end="")
            print(t.move_xy(3 * steps, 3) + IN1 + t.clear_eol + "Num", end="")
            # list
            num_rows = t.height - 5
            ip, tstamp, avg, num = None, None, None, None
            sort_by = ["last", "avg", "numbers"][self.mode.value]
            logging.debug(f"sort mode: '{sort_by}'")
            print(t.move_xy(0, 3) + t.normal, end="")
            with sqlite3.connect(self.db_string) as con:
                cur = con.cursor()
                cur.execute(
                    f"SELECT ip, last, avg, numbers FROM attacks ORDER BY {sort_by} DESC LIMIT {num_rows}"
                )
                for row in cur.fetchall():
                    ip, tstamp, avg, num = row
                    last = datetime.fromtimestamp(tstamp)
                    print(t.move_down(1) + t.clear_eol, end="")
                    print(t.move_x(0) + f"{ip:>15}", end="")
                    print(t.move_x(steps) + f"{last:%b %d %H:%M:%S}", end="")
                    print(t.move_x(steps * 2) + f"{avg:>10.2f}", end="")
                    print(t.move_x(steps * 3) + f"{num:>10,}", end="")
            # footer
            print(t.move_xy(0, t.height - 1) + IN1 + t.clear_eol, end="")
            print(
                t.black_on_bright_cyan(
                    "q: Quit, t: Sort by time, f: Sort by frequency, n: Sort by Numbers"
                )
            )
            inp = ""
            inp = t.inkey(timeout=self.refresh)
            if inp == "q":
                # Quit
                break
            if inp == "t":
                self.mode = Mode.TIME
            if inp == "f":
                self.mode = Mode.FREQ
            if inp == "n":
                self.mode = Mode.NUM
