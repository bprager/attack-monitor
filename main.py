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


def draw_screen(screen, data):
    y, x = [0, 0]
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_CYAN)
    curses.curs_set(0)
    screen.attron(curses.color_pair(1))
    screen.move(x, y)
    screen.addstr("Total attacks: ", curses.color_pair(2))
    screen.addstr(f"{data.total}")
    screen.chgat(screen.getyx()[0], screen.getyx()[1], -1, curses.color_pair(1))
    screen.attroff(curses.color_pair(1))
    screen.refresh()


def main(stdscr):
    mode: monitor.Mode = monitor.Mode.TIME
    source: monitor.Source = monitor.Source(db=DATABASE)
    stdscr.nodelay(True)
    key_char: chr = ""
    while True:
        data = source.get(mode)
        draw_screen(stdscr, data)
        key: int = stdscr.getch()
        # Convert the integer to its corresponding character
        if 0 <= key <= 0x10FFFF:
            key_char = chr(key)
        match key_char:
            case "t" | "T":
                mode = monitor.Mode.TIME
            case "n" | "N":
                mode = monitor.Mode.NUM
            case "q" | "Q":
                break
        time.sleep(REFRESH)


wrapper(main)
