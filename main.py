#!/usr/bin/env python3
import attack_monitor as monitor
import curses
import logging
import os
from curses import wrapper
from enum import Enum


class Theme(Enum):
    WHITE_ON_BLACK = 1
    RED_ON_BLACK = 2
    CYAN_ON_BLACK = 3
    BLACK_ON_CYAN = 4


DATABASE = "./attack.db"
REFRESH = 5000
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(funcName)s:%(lineno)d: %(message)s",
    handlers=[logging.FileHandler(f"{SCRIPT_DIR}/attack_monitor.log")],
    datefmt="%Y-%m-%d %H:%M:%S",
)


def header(screen, data, cols):
    screen.move(0, 0)
    screen.clrtoeol()
    screen.attron(curses.color_pair(Theme.WHITE_ON_BLACK.value))
    steps: int = int(cols / 3)
    screen.addstr("Total attacks: ")
    screen.addstr(f"{data.total:,}", curses.color_pair(Theme.RED_ON_BLACK.value))
    screen.move(0, 1 * steps)
    screen.addstr("Last: ")
    screen.addstr(
        f"{data.last:%a, %b %d %H:%M:%S}", curses.color_pair(Theme.RED_ON_BLACK.value)
    )
    screen.move(0, 2 * steps)
    screen.addstr("Since: ")
    screen.addstr(
        f"{data.last:%a, %b %d %H:%M:%S}", curses.color_pair(Theme.RED_ON_BLACK.value)
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
    screen.addstr("Blocked".rjust(steps - 2))
    screen.move(1, 3 * steps)
    screen.addstr("Last")
    screen.move(1, 4 * steps)
    screen.addstr("Avg (/hour)".rjust(steps - 2))
    screen.move(1, 5 * steps)
    screen.addstr("Count".rjust(steps - 2))


def footer(screen, rows):
    screen.move(rows - 1, 0)
    screen.clrtoeol()
    screen.chgat(rows - 1, 0, -1, curses.color_pair(Theme.BLACK_ON_CYAN.value))
    screen.attron(curses.color_pair(4))
    screen.addstr("Q: Quit, T: Sort by time, F: Sort by frequency, N: Sort by Numbers")


def panel(screen, data, rows, cols):
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
        screen.addstr("🛇".rjust(steps - 5) if record.blocked else " ")
        screen.move(y, 1 * steps)
        screen.addstr(record.location)
        screen.move(y, 3 * steps)
        screen.addstr(f"{record.last:%b %d %H:%M:%S}")
        screen.move(y, 4 * steps)
        screen.addstr(f"{record.avg:>10,.0f}".rjust(steps - 2))
        screen.move(y, 5 * steps)
        screen.addstr(f"{record.num:>10,}\n".rjust(steps - 2))


def draw_screen(screen, data, rows, cols):
    # colors
    curses.init_pair(Theme.WHITE_ON_BLACK.value, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(Theme.RED_ON_BLACK.value, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(Theme.CYAN_ON_BLACK.value, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(Theme.BLACK_ON_CYAN.value, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.start_color()
    curses.curs_set(0)  # Hide cursor
    header(screen, data, cols)
    panel(screen, data, rows, cols)
    footer(screen, rows)
    screen.refresh()


def main(stdscr):
    mode: monitor.Mode = monitor.Mode.TIME
    source: monitor.Source = monitor.Source(db=DATABASE)
    stdscr.timeout(REFRESH)
    key_char: chr = ""
    while True:
        rows, cols = stdscr.getmaxyx()
        data = source.get(mode, rows - 3)
        draw_screen(stdscr, data, rows, cols)
        key: int = stdscr.getch()
        # Convert the integer to its corresponding character
        if 0 <= key <= 0x10FFFF:
            key_char = chr(key)
        match key_char:
            case "t" | "T":
                mode = monitor.Mode.TIME
            case "n" | "N":
                mode = monitor.Mode.NUM
            case "f" | "F":
                mode = monitor.Mode.FREQ
            case "q" | "Q":
                break


wrapper(main)
