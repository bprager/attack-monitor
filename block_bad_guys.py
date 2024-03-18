#!/usr/bin/env python3
"""
This script checks the attack database for actors who tried more than 1,000 times
and add them to the ip blacklist
"""

__version__ = "0.3.2"
__author__ = "Bernd Prager"

import logging
import os
import sqlite3
import subprocess
import sys

DB_FILE = "/home/bernd/attack.db"
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(funcName)s:%(lineno)d: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"{SCRIPT_DIR}/blocker.log"),
    ],
    datefmt="%Y-%m-%d %H:%M:%S",
)

if "DEBUG" in os.environ:
    logging.getLogger().setLevel(logging.DEBUG)


def main():
    """main function to check the attack database and add bad actors to the blacklist"""
    # check if admin
    if os.getuid() > 0:
        logging.error("insufficient permissions")
        sys.exit(1)
    # get already black listed IPs
    out = subprocess.run(
        ["ipset", "list", "blacklist"], capture_output=True, text=True, check=False
    )
    blacklist = out.stdout.strip().split("\n")[8:]
    logging.debug(blacklist)
    added_ips = 0
    # get database records
    con = sqlite3.connect(f"file:{DB_FILE}?mode=ro")
    with con:
        for row in con.execute("SELECT ip FROM attacks WHERE numbers >= 1000"):
            if row[0] not in blacklist:
                # add to blacklist
                try:
                    subprocess.run(["ipset", "add", "blacklist", row[0]], check=True)
                    logging.debug("added %s to blacklist", row[0])
                    added_ips += 1
                except subprocess.CalledProcessError as e:
                    logging.warning("can't add %s to blacklist, due to %s", row[0], e)

    if added_ips > 0:
        logging.info("added %d IPs to blacklist", added_ips)
        try:
            # save the blacklist
            command = "ipset save blacklist -f/etc/ipset.conf"
            subprocess.run(command, shell=True, check=True)
            # reload the blacklist
            command = "ipset -exist restore < /etc/ipset.conf"
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.warning("can't persist blacklist, due to %s", e)
    else:
        logging.debug("no IPs added to blacklist")


if __name__ == "__main__":
    main()
