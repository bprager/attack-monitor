#!/usr/bin/env python3
import locale
import logging
import re
import sqlite3
import subprocess
from datetime import datetime

import geoip2.database

from .mode import Mode

GEO_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"

FORMAT = "%(asctime)s - %(levelname)s: %(message)s"
locale.setlocale(locale.LC_ALL, "")

# create logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# create file handler and set level to debug
fh = logging.FileHandler("attack_monitor.log")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter(FORMAT))
log.addHandler(fh)

# Colors
term = None
# FG1 = term.orangered
# FG2 = term.bright_cyan
# IN1 = term.black_on_bright_cyan


def location(ip: str) -> str:
    country = ""
    city = ""
    with geoip2.database.Reader(GEO_DB) as reader:
        response = reader.city(ip)
        country = "Unknow" if response.country.name == None else response.country.name
        city = "Unknown" if response.city.name == None else response.city.name
    return f"{city} ({country})"


def _run(self) -> None:
    t = self.term
    while True:
        with t.fullscreen(), t.cbreak(), t.hidden_cursor():
            all, last = None, None
            # Get latest attacks
            with sqlite3.connect(self.db_string) as con:
                cur = con.cursor()
                # cur.execute("SELECT 1,SQLITE_VERSION()")
                cur.execute("SELECT sum(numbers), max(last) FROM attacks")
                all, tstamp = cur.fetchone()
                last = datetime.fromtimestamp(tstamp)
                # logging.debug(f"all: {all},last: {last}")
            # Get blocked IP addresses
            output = subprocess.getoutput("sudo ipset save -o plain")
            blocked = re.findall(r"[\w:.]+", output)
            start = blocked.index("Members:")
            blocked = blocked[start + 1 :]
            log.debug(f"blocked: {blocked}")
            # summary
            print(
                t.home + t.move_xy(2, 1) + t.clear_eol,
                end="",
            )
            print(f"{FG2}Absolute numbers: {FG1}{all:,}")
            print(t.move_xy(2, 2) + t.clear_eol, end="")
            print(f"{FG2}Last: {FG1}{last:%a, %b %d %H:%M:%S}")
            # header
            steps = int(t.width / 6)
            print(t.move_xy(0, 3) + IN1 + t.clear_eol + "IP".rjust(steps - 2), end="")
            print(t.move_xy(steps, 3) + IN1 + t.clear_eol + "Location", end="")
            print(
                t.move_xy(2 * steps, 3)
                + IN1
                + t.clear_eol
                + "Blocked".rjust(steps - 2),
                end="",
            )
            print(t.move_xy(3 * steps, 3) + IN1 + t.clear_eol + "Last", end="")
            print(t.move_xy(4 * steps, 3) + IN1 + t.clear_eol + "Avg (/hour)", end="")
            print(t.move_xy(5 * steps, 3) + IN1 + t.clear_eol + "Num", end="")
            # list
            num_rows = t.height - 5
            ip, tstamp, avg, num = None, None, None, None
            sort_by = ["last", "avg", "numbers"][self.mode.value]
            log.debug(f"sort mode: '{sort_by}'")
            print(t.move_xy(0, 3) + t.normal, end="")
            with sqlite3.connect(self.db_string) as con:
                cur = con.cursor()
                if sort_by == "avg":
                    cur.execute(
                        f"SELECT ip, last, avg, numbers FROM attacks WHERE avg IS NOT NULL AND avg > 0 ORDER BY {sort_by} ASC NULLS LAST LIMIT {num_rows}"
                    )
                else:
                    cur.execute(
                        f"SELECT ip, last, avg, numbers FROM attacks WHERE avg IS NOT NULL AND avg > 0 ORDER BY {sort_by} DESC NULLS FIRST LIMIT {num_rows}"
                    )
                lines = []
                for row in cur.fetchall():
                    line = {}
                    ip, tstamp, avg, num = row
                    line["ip"] = f"{ip:>15}".rjust(steps - 2)
                    line["location"] = location(ip)
                    line["blocked"] = "X" if ip in blocked else " "
                    line["blocked"] = line["blocked"].rjust(steps - 2)
                    last = datetime.fromtimestamp(tstamp)
                    line["last"] = f"{last:%b %d %H:%M:%S}"
                    avg = (1 / avg) * 3600
                    line["avg"] = f"{avg:>10,.0f}"
                    line["num"] = f"{num:>10,}"
                    lines.append(line)
                print(t.move_xy(0, 4) + t.clear_eol, end="")
                for l in lines:
                    print(t.move_x(0) + l["ip"], end="")
                    print(t.move_x(2 * steps) + l["blocked"], end="")
                    print(t.move_x(steps) + l["location"], end="")
                    print(t.move_x(3 * steps) + l["last"], end="")
                    print(t.move_x(4 * steps) + l["avg"], end="")
                    print(t.move_x(5 * steps) + l["num"], end="")
                    print(t.move_down(1) + t.clear_eol, end="")
            # footer
            print(t.move_xy(0, t.height - 2) + IN1 + t.clear_eol, end="")
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
