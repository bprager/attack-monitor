#!/usr/bin/env python3
"""
This script reads a kern.log lease file and persists the recen 1000 iptables deny records
It assumes that the records are not older than 12 months
"""

__version__ = '0.1.0'
__author__ = 'Bernd Prager'


import calendar
import datetime
import logging
import os
import pytz
import readchar
import signal
import socket
import sqlite3
import sys
import time

# setup logging
FORMATTER = logging.Formatter(
    "%(asctime)s — %(name)s — %(levelname)s — %(message)s")
log = logging.getLogger(__name__)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(FORMATTER)
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)
log.addHandler(console_handler)

SOURCE_FILE = "/var/log/kern.log"
DB_FILE = "/home/bernd/attack.db"

LOCAL = ["192.168"]
MAX = 1000

def handler(signum, frame):
    msg = "Ctrl-c was pressed. Do you really want to exit? y/n "
    print(msg, end="", flush=True)
    res = readchar.readchar()
    if res == 'y':
        print("")
        exit(1)
    else:
        print("", end="\r", flush=True)
        print(" " * len(msg), end="", flush=True) # clear the printed line
        print("    ", end="\r", flush=True)

signal.signal(signal.SIGINT, handler)

def follow(name: str) -> str:
    current = open(name, "r")
    curino = os.fstat(current.fileno()).st_ino
    while True:
        while True:
            line = current.readline()
            if not line:
                break
            yield line

        try:
            if os.stat(name).st_ino != curino:
                new = open(name, "r")
                current.close()
                current = new
                curino = os.fstat(current.fileno()).st_ino
                continue
        except IOError:
            pass
        time.sleep(1)

def getTimeAndIP(line: str) -> tuple:
    hostname = socket.gethostname()
    timestring = line.split(hostname)[0].strip()
    ip = line.split("SRC=")[1].split()[0]
    return timestring, ip

def persist(con: sqlite3.Connection, timestring: str, ip: str):
    local = pytz.timezone("America/Los_Angeles")
    # convert timestring to timestamp 
    now = local.localize(datetime.datetime.utcnow())
    year = now.year
    log_date = local.localize(datetime.datetime.strptime(timestring, "%b %d %H:%M:%S").replace(year=year))
    if log_date.date() > now.date():
        log_date = log_date.replace(year = year - 1)
    timestamp = calendar.timegm(log_date.utctimetuple())

    # Check if IP already exist
    rows = con.execute ("""SELECT ip FROM attacks""")
    ips = [row[0] for row in rows]
    if ip in ips:
        # Update 
        log.debug(f"update record for ip {ip}")
        res = con.execute("""SELECT "last", avg, numbers FROM attacks WHERE ip = ?""", (ip,))
        last, avg, numbers = res.fetchone()
        numbers = numbers + 1
        delta = timestamp - last
        if delta < 0:
            # already in database, do nothing
            log.debug("record exist, do nothing")
            return
        if avg == None:
            avg = delta
        else:
            avg = (avg * (numbers - 1) + delta) / numbers
        con.execute("""UPDATE attacks SET last=?, avg=?, numbers=? WHERE ip=?""", (timestamp, avg, numbers, ip))
        con.commit()
    else:
        # Create new record
        log.debug(f"create new record for ip: {ip} and timestamp: {timestamp}")
        # Check if max entries
        res = con.execute ("""SELECT max(id) FROM attacks""")
        row = res.fetchone()[0]
        log.debug(f"current max: {row}")
        if row and (row > MAX):
            # Find oldest record and replace
            log.debug("find oldest record")
            res = con.execute ("""SELECT id FROM attacks WHERE last = (SELECT min(last) FROM attacks)""")
            row = res.fetchone()[0]
            con.execute("""UPDATE attacks SET ip=?, "last"=?, avg=?, numbers=? WHERE id=?)""", (ip, timestamp, None, 1, row))
            con.commit()
        else:
            con.execute("""INSERT INTO attacks (ip, last, numbers) VALUES (?, ?, ?)""", (ip, timestamp, 1))
            con.commit()

    

def main():
    con = sqlite3.connect(f"file:{DB_FILE}?mode=rw")
    with con:
        for l in follow(SOURCE_FILE):
            if "iptables deny" in l:
                time, ip = getTimeAndIP(l)
                domain = '.'.join(ip.split('.')[:2])
                if domain in LOCAL:
                    continue
                persist(con, time, ip)
    con.close()

if __name__ == "__main__":
    main()
