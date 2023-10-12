#!/usr/bin/env python3
import attack_monitor as monitor
import curses
import logging
import os
import time
from curses import wrapper

DATABASE = "./attack.db"
REFRESH = 2
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(funcName)s:%(lineno)d: %(message)s",
    handlers=[logging.FileHandler(f"{SCRIPT_DIR}/attack_monitor.log")],
    datefmt="%Y-%m-%d %H:%M:%S",
)


def draw_screen(screen, data, rows, cols):
    # colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.curs_set(0)  # Hide cursor
    screen.attron(curses.color_pair(3))
    # header
    screen.move(0, 0)
    screen.clrtoeol()
    screen.chgat(0, 0, -1, curses.color_pair(3))
    steps: int = int(cols / 3)
    screen.addstr("Total attacks: ")
    screen.addstr(f"{data.total:,}", curses.color_pair(2))
    screen.move(0, 1 * steps)
    screen.addstr("Last: ")
    screen.addstr(f"{data.last:%a, %b %d %H:%M:%S}", curses.color_pair(2))
    screen.move(0, 2 * steps)
    screen.addstr("Since: ")
    screen.addstr(f"{data.first:%a, %b %d %H:%M:%S}", curses.color_pair(2))
    steps = int(cols / 6)
    screen.move(1, 0)
    screen.clrtoeol()
    screen.chgat(1, 0, -1, curses.color_pair(4))
    screen.attron(curses.color_pair(4))
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
    screen.attroff(curses.color_pair(1))
    # footer
    screen.move(rows - 1, 0)
    screen.clrtoeol()
    screen.chgat(rows - 1, 0, -1, curses.color_pair(4))
    screen.attron(curses.color_pair(4))
    screen.addstr("Q: Quit, T: Sort by time, F: Sort by frequency, N: Sort by Numbers")
    screen.refresh()


def main(stdscr):
    mode: monitor.Mode = monitor.Mode.TIME
    source: monitor.Source = monitor.Source(db=DATABASE)
    stdscr.nodelay(True)
    key_char: chr = ""
    while True:
        data = source.get(mode)
        rows, cols = stdscr.getmaxyx()
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
        time.sleep(REFRESH)


wrapper(main)
