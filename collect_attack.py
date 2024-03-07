#!/usr/bin/env python3
"""
This script reads a kern.log lease file and persists the recen 1000 iptables deny records
It assumes that the records are not older than 12 months
"""

__version__ = "0.4.0"
__author__ = "Bernd Prager"


import calendar
import datetime
import logging
import os
import signal
import socket
import sqlite3
import sys
import time
from typing import Generator

import pytz
import readchar

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(funcName)s:%(lineno)d: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"{SCRIPT_DIR}/attacks.log"),
    ],
    datefmt="%Y-%m-%d %H:%M:%S",
)

KERN_LOG_FILE = "/var/log/kern.log"
AUTH_LOG_FILE = "/var/log/auth.log"
DB_FILE = "/home/bernd/attack.db"

LOCAL = ["192.168"]
MAX = 1000


def handler(_signum, _frame):
    """Handle Ctrl-c signal. Ask for confirmation before exit."""
    msg = "Ctrl-c was pressed. Do you really want to exit? y/n "
    print(msg, end="", flush=True)
    res = readchar.readchar()
    if res == "y":
        print("")
        sys.exit(0)
    else:
        print("", end="\r", flush=True)
        print(" " * len(msg), end="", flush=True)  # clear the printed line
        print("    ", end="\r", flush=True)


signal.signal(signal.SIGINT, handler)


def follow(name: str) -> Generator[str, None, None]:
    """Follow a file and yield new lines."""
    current = open(name, "r", encoding="utf-8")
    curino = os.fstat(current.fileno()).st_ino
    while True:
        while True:
            line = current.readline()
            if not line:
                break
            yield line

        try:
            if os.stat(name).st_ino != curino:
                new = open(name, "r", encoding="utf-8")
                current.close()
                current = new
                curino = os.fstat(current.fileno()).st_ino
                continue
        except IOError:
            pass
        time.sleep(1)


def get_time_and_ip_from_kern_log(line: str) -> tuple:
    """Extract time and ip from kern.log line."""
    hostname = socket.gethostname()
    timestring = line.split(hostname)[0].strip()
    # logging.debug(f"line: {line}")
    ip = line.split("SRC=")[1].split()[0]
    return timestring, ip


def get_time_and_ip_from_auth_log(line: str) -> tuple:
    """Extract time and ip from auth.log line."""
    hostname = socket.gethostname()
    timestring = line.split(hostname)[0].strip()
    # logging.debug(f"line: {line}")
    ip = line.split("rhost=")[1].split()[0]
    return timestring, ip


def persist(con: sqlite3.Connection, timestring: str, ip: str):
    """Persist the record in the database. If the record already exist, update it."""
    local = pytz.timezone("America/Los_Angeles")
    # convert timestring to timestamp
    now = local.localize(datetime.datetime.utcnow())
    year = now.year
    log_date = local.localize(
        datetime.datetime.strptime(timestring, "%b %d %H:%M:%S").replace(year=year)
    )
    if log_date.date() > now.date():
        log_date = log_date.replace(year=year - 1)
    timestamp = calendar.timegm(log_date.utctimetuple())

    # Check if IP already exist
    rows = con.execute("""SELECT ip FROM attacks""")
    ips = [row[0] for row in rows]
    if ip in ips:
        # Update
        logging.debug("update record for ip %s", ip)
        res = con.execute(
            """SELECT "last", avg, numbers FROM attacks WHERE ip = ?""", (ip,)
        )
        last, avg, numbers = res.fetchone()
        numbers = numbers + 1
        delta = timestamp - last
        if delta < 0:
            # already in database, do nothing
            logging.debug("record exist, do nothing")
            return
        if avg is None:
            avg = delta
        else:
            avg = (avg * (numbers - 1) + delta) / numbers
        con.execute(
            """UPDATE attacks SET last=?, avg=?, numbers=? WHERE ip=?""",
            (timestamp, avg, numbers, ip),
        )
        con.commit()
    else:
        # Create new record
        logging.debug("create new record for ip: %s and timestamp: %s", ip, timestamp)
        # Check if max entries
        res = con.execute("""SELECT max(id) FROM attacks""")
        row = res.fetchone()[0]
        logging.debug("current max: %s", row)
        if row and (row > MAX):
            # Find oldest record and replace
            logging.debug("find oldest record")
            res = con.execute(
                """SELECT id FROM attacks WHERE last = (SELECT min(last) FROM attacks)"""
            )
            row = res.fetchone()[0]
            con.execute(
                """UPDATE attacks SET ip=?, "last"=?, avg=?, numbers=? WHERE id=?)""",
                (ip, timestamp, None, 1, row),
            )
            con.commit()
        else:
            con.execute(
                """INSERT INTO attacks (ip, last, numbers) VALUES (?, ?, ?)""",
                (ip, timestamp, 1),
            )
            con.commit()


def main():
    """Main function"""
    con = sqlite3.connect(f"file:{DB_FILE}?mode=rw")
    with con:
        for l in follow(AUTH_LOG_FILE):
            if "pam_unix(sshd:auth): authentication failure" in l:
                log_time, ip = get_time_and_ip_from_auth_log(l)
                domain = ".".join(ip.split(".")[:2])
                if domain in LOCAL:
                    continue
                logging.debug("from auth.log, time: %s, ip: %s", log_time, ip)
                persist(con, log_time, ip)
        for l in follow(KERN_LOG_FILE):
            if "iptables deny" in l:
                log_time, ip = get_time_and_ip_from_kern_log(l)
                domain = ".".join(ip.split(".")[:2])
                if domain in LOCAL:
                    continue
                logging.debug("from kern.log, time: %s, ip: %s", log_time, ip)
                persist(con, log_time, ip)
    con.close()


if __name__ == "__main__":
    main()
