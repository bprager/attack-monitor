#!/usr/bin/env python3

"""Script to monitor attack data."""

import curses
import logging
import os
import re
import sqlite3
import subprocess
from curses import wrapper
from datetime import datetime
from enum import Enum
from math import ceil

import geoip2.database

DATABASE = "/home/bernd/attack.db"
GEO_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
REFRESH = 5000
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(funcName)s:%(lineno)d: %(message)s",
    handlers=[logging.FileHandler(f"{SCRIPT_DIR}/attack_monitor.log")],
    datefmt="%Y-%m-%d %H:%M:%S",
)


class Mode(Enum):
    """Mode definitions for the curses interface."""

    TIME = 0
    FREQ = 1
    NUM = 2


class Theme(Enum):
    """Color definitions for the curses interface."""

    WHITE_ON_BLACK = 1
    RED_ON_BLACK = 2
    CYAN_ON_BLACK = 3
    BLACK_ON_CYAN = 4


class Record:
    """Database record."""

    ip: str
    location: str
    last: datetime
    blocked: bool
    avg: float
    num: int

    def __init__(
        self,
        ip: str = "",
        loc: str = "",
        last: datetime = datetime.now(),
        blocked: bool = False,
        avg: float = 0.0,
        num: int = 0,
    ):
        self.ip = ip
        self.loc = loc
        self.last = last
        self.blocked = blocked
        self.avg = avg
        self.num = num

    def __repr__(self):
        return f"""
    ip:{self.ip} location:{self.loc} 
    blocked: {self.blocked} last: {self.last} 
    avg: {self.avg} num: {self.num} """


class Data:
    """Database query data."""

    total: int
    since: datetime
    last: datetime
    records: list[Record]

    def __init__(
        self,
        count: int = 0,
        total: int = 0,
        since: datetime = datetime.now(),
        last: datetime = datetime.now(),
        records: list[Record] | None = None,
    ):
        self.count = count
        self.total = total
        self.since = since
        self.last = last
        self.records = records if records else []

    def __repr__(self) -> str:
        return f"total: {self.total} since: {self.since} last: {self.last} records: {self.records}"


class Source:
    """Database source."""

    db_string: str
    refresh: int
    mode: Mode
    data: Data

    def __init__(self, db: str) -> None:
        self.db_string = db
        self.mode = Mode.TIME
        self.data = Data()

    def get(self, mode: Mode, first_line: int, rows: int) -> Data:
        """Get data from the database."""
        logging.debug("source.get")
        logging.debug(
            "first_line: %s, number of rows: %d", format(first_line, ","), rows
        )
        self.mode = mode
        # Get blocked IP addresses
        output = subprocess.getoutput("sudo ipset save -o plain")
        blocked = re.findall(r"[\w:.]+", output)
        if "Members:" in blocked:
            start = blocked.index("Members:")
            blocked = blocked[start + 1 :]
        else:
            blocked = []
        logging.debug("blocked: %s", blocked)
        with sqlite3.connect(database=self.db_string) as con:
            cur = con.cursor()
            # stats
            cur.execute(
                "SELECT count(numbers), sum(numbers), max(last), min(first) FROM attacks"
            )
            self.data.count, self.data.total, tstamp_last, tstamp_first = cur.fetchone()
            self.data.last = datetime.fromtimestamp(tstamp_last)
            self.data.since = datetime.fromtimestamp(tstamp_first)
            # records
            self.data.records = []
            sort_by = ["last", "avg", "numbers"][mode.value]
            if sort_by == "avg":
                cur.execute(
                    f"""SELECT ip, last, avg, numbers FROM attacks WHERE avg IS NOT NULL AND avg > 0 
                    ORDER BY avg ASC NULLS LAST LIMIT {rows} OFFSET {first_line - 1}"""
                )
            else:
                cur.execute(
                    f"""SELECT ip, last, avg, numbers FROM attacks 
                    ORDER BY {sort_by} DESC NULLS FIRST LIMIT {rows} OFFSET {first_line - 1}"""
                )
            for row in cur.fetchall():
                record = Record()
                record.ip, tstamp, record.avg, record.num = row
                if record.avg is None:
                    record.avg = 0.0
                record.last = datetime.fromtimestamp(tstamp)
                record.location = location(record.ip)
                record.blocked = record.ip in blocked
                self.data.records.append(record)
        return self.data


def location(ip: str) -> str:
    """Convert IP address to location string."""
    country: str | None = ""
    city = ""
    with geoip2.database.Reader(GEO_DB) as reader:
        try:
            response = reader.city(ip)
            country = (
                "Unknow" if response.country.name is None else response.country.name
            )
            city = "Unknown" if response.city.name is None else response.city.name
        except geoip2.errors.AddressNotFoundError:
            country = "Unknow"
            city = "Unknown"

    return f"{city} ({country})"


def header(
    screen: curses.window, data: Data, rows: int, cols: int, first_line: int
) -> None:
    """Displays screen header."""
    screen.move(0, 0)
    screen.clrtoeol()
    screen.attron(curses.color_pair(Theme.WHITE_ON_BLACK.value))
    steps: int = int(cols / 4)
    screen.addstr("Total attacks: ")
    screen.addstr(f"{data.total:,}", curses.color_pair(Theme.RED_ON_BLACK.value))
    screen.move(0, 1 * steps)
    screen.addstr("Last: ")
    screen.addstr(
        f"{data.last:%a, %b %d %Y %H:%M:%S}",
        curses.color_pair(Theme.RED_ON_BLACK.value),
    )
    screen.move(0, 2 * steps)
    screen.addstr("Since: ")
    screen.addstr(
        f"{data.since:%a, %b %d %Y %H:%M:%S}",
        curses.color_pair(Theme.RED_ON_BLACK.value),
    )
    screen.move(0, 3 * steps)
    screen.addstr(
        f"Page {ceil(first_line/rows)+1:,}/{ceil(data.count/rows):,}".rjust(steps)
    )
    steps = int(cols / 6)
    screen.move(1, 0)
    screen.clrtoeol()
    screen.chgat(1, 0, -1, curses.color_pair(Theme.BLACK_ON_CYAN.value))
    screen.attron(curses.color_pair(Theme.BLACK_ON_CYAN.value))
    screen.addstr("IP".rjust(steps - 2))
    screen.move(1, 1 * steps)
    screen.addstr("Location")
    screen.move(1, 2 * steps)
    screen.addstr("Blocked".rjust(steps - 1))
    screen.move(1, 3 * steps)
    screen.addstr("Last")
    screen.move(1, 4 * steps)
    screen.addstr("Avg (/hour)".rjust(steps - 2))
    screen.move(1, 5 * steps)
    screen.addstr("Count".rjust(steps - 2))


def footer(screen: curses.window, rows: int, cols: int):
    """Screen footer."""
    screen.move(rows - 1, 0)
    screen.clrtoeol()
    screen.chgat(rows - 1, 0, -1, curses.color_pair(Theme.BLACK_ON_CYAN.value))
    screen.attron(curses.color_pair(4))
    try:
        screen.addstr("Q: Quit, T: Sort by time, N: Sort by Numbers")
        screen.addstr(
            "Home: First, PgUp: Previous, PgDn: Next, End: Last".rjust(cols - 44)
        )
    except curses.error:
        pass


def panel(screen: curses.window, data: Data, rows: int, cols: int):
    """Screen panel."""
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    steps = int(cols / 6)
    screen.move(2, 0)
    screen.attron(curses.color_pair(1))
    screen.chgat(rows - 1, 0, -1, curses.color_pair(1))
    for idx, record in enumerate(data.records):
        y = 2 + idx
        screen.move(y, 0)
        screen.clrtoeol()
        screen.addstr(f"{record.ip:>15}".rjust(steps - 2), curses.color_pair(1))
        screen.move(y, 2 * steps)
        screen.addstr("🚫".rjust(steps - 2) if record.blocked else " ")
        screen.move(y, 1 * steps)
        screen.addstr(record.location)
        screen.move(y, 3 * steps)
        screen.addstr(f"{record.last:%b %d, %Y %H:%M:%S}")
        screen.move(y, 4 * steps)
        screen.addstr(f"{record.avg:>10,.0f}".rjust(steps - 2))
        screen.move(y, 5 * steps)
        screen.addstr(f"{record.num:>10,}\n".rjust(steps - 2))


def draw_screen(
    screen: curses.window, first_line: int, data: Data, rows: int, cols: int
):
    """Draw the actual screen."""
    # colors
    curses.init_pair(Theme.WHITE_ON_BLACK.value, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(Theme.RED_ON_BLACK.value, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(Theme.CYAN_ON_BLACK.value, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(Theme.BLACK_ON_CYAN.value, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.start_color()
    curses.curs_set(0)  # Hide cursor
    header(screen, data, rows, cols, first_line=first_line)
    panel(screen, data, rows, cols)
    footer(screen, rows, cols)
    screen.refresh()


def main(stdscr: curses.window) -> None:
    """Main event loop."""
    mode: Mode = Mode.TIME
    stdscr.nodelay(True)
    stdscr.timeout(REFRESH)
    first_line: int = 0
    source: Source = Source(DATABASE)
    # curses configuration
    # Make get_wch() non-blocking
    while True:
        rows, cols = stdscr.getmaxyx()
        data = source.get(mode, first_line, rows - 3)
        draw_screen(stdscr, first_line, data, rows, cols)
        key: int | str
        try:
            key = stdscr.get_wch()
        except curses.error as e:
            # Handle no input
            if str(e) == "no input":
                continue  # No input, just continue the loop
            raise  # Re-raise other exceptions
        match key:
            case "t" | "T":
                mode = Mode.TIME
            case "n" | "N":
                mode = Mode.NUM
            case curses.KEY_HOME:
                first_line = 0
            case curses.KEY_END:
                first_line = data.count - rows + 3
            case curses.KEY_NPAGE:
                first_line = (
                    first_line + rows - 2
                    if first_line + rows < data.count
                    else data.count - rows
                )
            case curses.KEY_PPAGE:
                first_line = first_line - rows + 2 if first_line - rows > 0 else 0
            case "q" | "Q":
                break


wrapper(main)
